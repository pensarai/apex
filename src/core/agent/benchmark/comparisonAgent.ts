import { tool } from "ai";
import { z } from "zod";
import { streamResponse, type AIModel } from "../../ai";
import { existsSync, readFileSync, readdirSync } from "fs";
import { join } from "path";
import type { ComparisonResult, ActualFinding } from "./types";
import { detectOSAndEnhancePrompt } from "../utils";

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

Be thorough and accurate in your assessment.
`;

interface ComparisonAgentProps {
  repoPath: string;
  sessionPath: string;
  model: AIModel;
  abortSignal?: AbortSignal;
}

export async function runComparisonAgent(
  props: ComparisonAgentProps
): Promise<ComparisonResult> {
  const { repoPath, sessionPath, model, abortSignal } = props;

  // Load expected results
  const expectedResultsPath = join(repoPath, "expected_results.json");
  if (!existsSync(expectedResultsPath)) {
    throw new Error(
      `Expected results file not found at: ${expectedResultsPath}`
    );
  }

  const expectedData = readFileSync(expectedResultsPath, "utf-8");
  const expectedResults = JSON.parse(expectedData);

  // Load actual findings (markdown files)
  const findingsPath = join(sessionPath, "findings");
  if (!existsSync(findingsPath)) {
    throw new Error(`Findings directory not found at: ${findingsPath}`);
  }

  // Concatenate all markdown files
  let actualFindingsMarkdown = "";
  const files = readdirSync(findingsPath);

  for (const file of files) {
    if (!file.endsWith(".md")) continue;

    try {
      const filePath = join(findingsPath, file);
      const data = readFileSync(filePath, "utf-8");
      actualFindingsMarkdown += `\n\n---\n**File: ${file}**\n\n${data}`;
    } catch (error: any) {
      console.error(`Failed to read finding file ${file}:`, error.message);
    }
  }

  if (!actualFindingsMarkdown.trim()) {
    throw new Error(`No markdown findings found in ${findingsPath}`);
  }

  // Create the comparison tool
  let comparisonResult: ComparisonResult | null = null;

  const provide_comparison_results = tool({
    name: "provide_comparison_results",
    description: `Provide the final comparison results with matched, missed, and extra findings.
    
This is the REQUIRED output tool - you MUST call this with your analysis.`,
    inputSchema: z.object({
      matched: z
        .array(
          z.object({
            expectedId: z.string().describe("ID of the expected finding"),
            expectedTitle: z.string().describe("Title of the expected finding"),
            actualTitle: z.string().describe("Title of the actual finding"),
            matchScore: z
              .number()
              .min(0)
              .max(1)
              .describe("Confidence score for this match (0-1)"),
            matchReason: z
              .string()
              .describe("Explanation for why these findings match"),
          })
        )
        .describe("Findings that were successfully matched"),
      missed: z
        .array(
          z.object({
            id: z.string().describe("ID of the missed finding"),
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
        .describe("Concise description of this tool call"),
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

      comparisonResult = {
        totalExpected,
        totalActual: matched.length + extra.length,
        matched: matched.map((m) => ({
          expected: expectedResults.find((e: any) => e.id === m.expectedId) || {
            id: m.expectedId,
            title: m.expectedTitle,
          },
          actual: {
            title: m.actualTitle,
          },
          matchScore: m.matchScore,
          matchReason: m.matchReason,
        })),
        missed: missed.map((m) => ({
          ...expectedResults.find((e: any) => e.id === m.id),
          reason: m.reason,
        })),
        extra: extra.map((e) => ({
          title: e.title,
          severity: e.severity as
            | "CRITICAL"
            | "HIGH"
            | "MEDIUM"
            | "LOW"
            | "INFORMATIONAL"
            | undefined,
          assessment: e.assessment,
        })),
        accuracy,
        recall,
        precision,
      };

      return {
        success: true,
        message: `Comparison complete. Matched: ${
          matched.length
        }/${totalExpected}, Precision: ${Math.round(
          precision * 100
        )}%, Recall: ${Math.round(recall * 100)}%`,
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

Be thorough in your analysis and provide clear explanations for your matches.
`.trim();

  const systemPrompt = detectOSAndEnhancePrompt(COMPARISON_SYSTEM_PROMPT);

  // Run the agent
  const streamResult = streamResponse({
    prompt,
    system: systemPrompt,
    model,
    tools: { provide_comparison_results },
    toolChoice: "auto",
    abortSignal,
  });

  // Consume the stream
  for await (const _delta of streamResult.fullStream) {
    // Just consume to completion
  }

  if (!comparisonResult) {
    throw new Error("Comparison agent did not provide results");
  }

  return comparisonResult;
}
