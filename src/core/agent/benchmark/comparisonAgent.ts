import { hasToolCall, stepCountIs, tool as aiTool, type Tool } from "ai";
import { z } from "zod";
import { streamResponse, type AIModel } from "../../ai";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "fs";
import { join } from "path";
import type { ComparisonResult, ActualFinding } from "./types";
import { detectOSAndEnhancePrompt } from "../utils";

/**
 * Helper to define tools with proper typing.
 * Works around Zod v4 / AI SDK v6 type compatibility issues.
 * @see https://github.com/vercel/ai/issues/10014
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function tool<T extends z.ZodType, R>(config: {
  name?: string;
  description: string;
  inputSchema: T;
  execute: (input: z.infer<T>) => Promise<R>;
}): Tool<z.infer<T>, R> {
  return aiTool(config as any) as Tool<z.infer<T>, R>;
}

const COMPARISON_SYSTEM_PROMPT = `
You are a security findings comparison agent. Your role is to compare expected security findings against actual findings from a penetration test and provide an accurate assessment.

# Your Task

You will be provided with:
1. **Expected findings** - A list of security vulnerabilities that should be found in the target application
2. **Actual findings** - The vulnerabilities that were actually discovered during the penetration test

Your job is to:
1. **Match findings** - Identify which actual findings correspond to expected findings
2. **Identify missed findings** - Expected findings that were not discovered
3. **Identify extra findings** - Actual findings that weren't in the expected list (could be false positives or new discoveries)
4. **Calculate metrics** - Provide accuracy, precision, and recall scores

# Matching Criteria

When matching findings, consider:
- **Semantic similarity** - Do they describe the same vulnerability?
- **Severity alignment** - Do they have similar impact levels?
- **Category/type** - Are they the same type of vulnerability?
- **Location/context** - Are they in the same area of the application?

Don't require exact text matches - focus on whether they represent the same security issue.

# Important Notes

- Be generous with matching - if an actual finding clearly addresses an expected finding, count it as a match
- Extra findings are NOT necessarily bad - they could be newly discovered vulnerabilities
- Focus on whether the pentest successfully identified the known vulnerabilities
- Provide clear explanations for why findings were matched or not matched

# Output Format

You MUST call the provide_comparison_results tool with:
- **matched**: Array of matched findings with explanations
- **missed**: Array of expected findings that were not found
- **extra**: Array of actual findings that don't match any expected findings
- **metrics**: Calculated precision, recall, and accuracy percentages

Be thorough and accurate in your assessment. Use the provide_comparison_results tool to provide your results.
`;

interface ComparisonAgentProps {
  repoPath: string;
  sessionPath: string;
  model: AIModel;
}

export async function runComparisonAgent(
  props: ComparisonAgentProps
): Promise<ComparisonResult> {
  const { repoPath, sessionPath, model } = props;

  // Load expected results from expected_results folder
  const expectedResultsDir = join(repoPath, "expected_results");
  if (!existsSync(expectedResultsDir)) {
    throw new Error(
      `Expected results directory not found at: ${expectedResultsDir}`
    );
  }

  // Find the first JSON file in the expected_results directory
  const expectedFiles = readdirSync(expectedResultsDir);
  const jsonFiles = expectedFiles.filter((f) => f.endsWith(".json"));

  if (jsonFiles.length === 0) {
    throw new Error(
      `No JSON file found in expected_results directory: ${expectedResultsDir}`
    );
  }

  const expectedResultsFile = jsonFiles[0]!;
  const expectedResultsPath = join(expectedResultsDir, expectedResultsFile);
  console.log(
    `[ComparisonAgent] Loading expected results from: ${expectedResultsPath}`
  );

  const expectedData = readFileSync(expectedResultsPath, "utf-8");
  const expectedResults = JSON.parse(expectedData);

  // Load actual findings (markdown files)
  const findingsPath = join(sessionPath, "findings");
  if (!existsSync(findingsPath)) {
    throw new Error(`Findings directory not found at: ${findingsPath}`);
  }

  // Concatenate all JSON findings as formatted text
  let actualFindingsMarkdown = "";
  const findingFiles = readdirSync(findingsPath);

  for (const file of findingFiles) {
    if (!file.endsWith(".json")) continue;

    try {
      const filePath = join(findingsPath, file);
      const data = readFileSync(filePath, "utf-8");
      const finding = JSON.parse(data);

      // Format JSON finding as markdown-like text for comparison
      const formattedFinding = `# ${finding.title}

**Severity:** ${finding.severity}
**Target:** ${finding.target || 'N/A'}

## Description
${finding.description}

## Impact
${finding.impact}

## Evidence
${finding.evidence}

## Remediation
${finding.remediation}

${finding.references ? `## References\n${finding.references}` : ''}`;

      actualFindingsMarkdown += `\n\n---\n**File: ${file}**\n\n${formattedFinding}`;
    } catch (error: any) {
      console.error(`Failed to read finding file ${file}:`, error.message);
    }
  }

  if (!actualFindingsMarkdown.trim()) {
    throw new Error(`No JSON findings found in ${findingsPath}`);
  }

  // Path for saving comparison results
  const comparisonResultsPath = join(sessionPath, "comparison-results.json");

  const provide_comparison_results = tool({
    name: "provide_comparison_results",
    description: `Provide the final comparison results with matched, missed, and extra findings.
    
This is the REQUIRED output tool - you MUST call this with your analysis.

Results will be saved to: comparison-results.json in the session directory.`,
    inputSchema: z.object({
      matched: z
        .array(
          z.object({
            location: z.string().describe("Location of the matched finding"),
            expectedTitle: z.string().describe("Title of the expected finding"),
            actualTitle: z.string().describe("Title of the actual finding"),
            matchReason: z
              .string()
              .describe("Explanation for why these findings match"),
          })
        )
        .describe("Findings that were successfully matched"),
      missed: z
        .array(
          z.object({
            title: z.string().describe("Title of the missed finding"),
            severity: z.string().describe("Severity level"),
            reason: z
              .string()
              .describe("Explanation for why this finding was missed"),
          })
        )
        .describe("Expected findings that were not found"),
      extra: z
        .array(
          z.object({
            title: z.string().describe("Title of the extra finding"),
            severity: z.string().describe("Severity level"),
            location: z.string().describe("Location of the extra finding"),
            assessment: z
              .string()
              .describe(
                "Assessment of whether this is a false positive or new discovery"
              ),
          })
        )
        .describe("Actual findings that don't match any expected findings"),
      toolCallDescription: z
        .string()
        .describe("Concise description of this tool call")
        .optional()
        ,
    }),
    execute: async ({ matched, missed, extra }) => {
      const totalExpected = expectedResults.length;
      const totalActual = matched.length + extra.length;
      const truePositives = matched.length;
      const falseNegatives = missed.length;
      const falsePositives = extra.length;

      const precision =
        truePositives + falsePositives > 0
          ? truePositives / (truePositives + falsePositives)
          : 0;

      const recall =
        truePositives + falseNegatives > 0
          ? truePositives / (truePositives + falseNegatives)
          : 0;

      const accuracy = totalExpected > 0 ? truePositives / totalExpected : 0;

      // Build comparison result object
      const result: ComparisonResult = {
        totalExpected,
        totalActual: matched.length + extra.length,
        matched,
        missed,
        extra,
        accuracy,
        recall,
        precision,
      };

      // Save comparison results to file
      console.log(
        `[ComparisonAgent] Saving results to: ${comparisonResultsPath}`
      );
      writeFileSync(comparisonResultsPath, JSON.stringify(result, null, 2));

      return {
        success: true,
        resultsPath: comparisonResultsPath,
        message: `Comparison complete. Matched: ${
          matched.length
        }/${totalExpected}, Precision: ${Math.round(
          precision * 100
        )}%, Recall: ${Math.round(recall * 100)}%

Results saved to: ${comparisonResultsPath}`,
      };
    },
  });

  // Build the prompt
  const prompt = `
Compare the expected security findings against the actual findings from the penetration test.

**EXPECTED FINDINGS (${expectedResults.length} total):**
${JSON.stringify(expectedResults, null, 2)}

**ACTUAL FINDINGS (Markdown Documentation):**
${actualFindingsMarkdown}

Please analyze these findings and call the provide_comparison_results tool with:
1. All matched findings (expected findings that were successfully discovered)
2. All missed findings (expected findings that were not discovered)
3. All extra findings (actual findings that don't match any expected finding)

The actual findings are documented in markdown format. Extract the key vulnerability information from the markdown to match against the expected findings.

Be thorough in your analysis and provide clear explanations for your matches. Stop when you have provided the results with provide_comparison_results tool.
`.trim();

  // Run the agent
  const streamResult = streamResponse({
    prompt,
    system: COMPARISON_SYSTEM_PROMPT,
    model,
    tools: { provide_comparison_results },
    toolChoice: "auto",
    stopWhen: stepCountIs(10000),
  });

  // Consume the stream and log progress
  console.log(`\n${"=".repeat(80)}`);
  console.log(`COMPARISON AGENT`);
  console.log(`${"=".repeat(80)}\n`);

  for await (const delta of streamResult.fullStream) {
    if (delta.type === "text-delta") {
      process.stdout.write(delta.text);
    } else if (delta.type === "tool-call") {
      console.log(
        `\n\n[Tool] ${delta.toolName}${
          delta.input?.toolCallDescription
            ? `: ${delta.input.toolCallDescription}`
            : ""
        }`
      );
    } else if (delta.type === "tool-result") {
      console.log(`[Tool Complete]\n`);
    }
  }

  // await consumeStream(streamResult, {
  //   onTextDelta: (delta) => {
  //     process.stdout.write(delta.text);
  //   },
  //   onToolCall: (delta) => {
  //     console.log(
  //       `\n\n[Tool] ${delta.toolName}${
  //         delta.input?.toolCallDescription
  //           ? `: ${delta.input.toolCallDescription}`
  //           : ""
  //       }`
  //     );
  //   },
  //   onToolResult: (delta) => {
  //     console.log(`[Tool Complete]\n`);
  //   },
  // });

  console.log(`\n${"=".repeat(80)}`);
  console.log(`COMPARISON COMPLETE`);
  console.log(`${"=".repeat(80)}\n`);

  // Read comparison results from file
  if (!existsSync(comparisonResultsPath)) {
    throw new Error(
      "Comparison agent did not save results to file: " + comparisonResultsPath
    );
  }

  console.log(
    `[ComparisonAgent] Reading results from: ${comparisonResultsPath}`
  );
  const savedResults = readFileSync(comparisonResultsPath, "utf-8");
  const comparisonResultFromFile = JSON.parse(savedResults) as ComparisonResult;

  console.log(`[ComparisonAgent] Results loaded successfully`);
  console.log(`  - Matched: ${comparisonResultFromFile.matched.length}`);
  console.log(`  - Missed: ${comparisonResultFromFile.missed.length}`);
  console.log(`  - Extra: ${comparisonResultFromFile.extra.length}`);
  console.log(
    `  - Accuracy: ${Math.round(comparisonResultFromFile.accuracy * 100)}%`
  );
  console.log(
    `  - Precision: ${Math.round(comparisonResultFromFile.precision * 100)}%`
  );
  console.log(
    `  - Recall: ${Math.round(comparisonResultFromFile.recall * 100)}%`
  );

  return comparisonResultFromFile;
}
