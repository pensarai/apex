import { tool, hasToolCall, stepCountIs } from "ai";
import { streamResponse, type AIModel } from "../../ai";
import type { Session } from "../sessions";
import z from "zod";
import { join } from "path";
import {
  existsSync,
  writeFileSync,
  chmodSync,
  unlinkSync,
  appendFileSync,
  mkdirSync,
  readFileSync,
  readdirSync,
} from "fs";
import { promisify } from "util";
import { exec } from "child_process";
import { Logger } from "../logger";
import type { AIAuthConfig } from "../../ai/utils";
import {
  ApexFindingObject,
  CreatePocObject,
  type CreatePocOpts,
  type CreatePocResult,
  type DocumentFindingResult,
} from "./types";

const execAsync = promisify(exec);

const FindingObject = z.object({
  title: z.string().describe("Finding title"),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
  description: z.string().describe("Detailed description of the finding"),
  impact: z.string().describe("Potential impact if exploited"),
  endpoint: z
    .string()
    .describe(
      "The full URL Endpoint of the finding. Do not include any other text. i.e. https://example.com/endpoint"
    ),
  evidence: z.string().describe("Evidence/proof of the vulnerability"),
  remediation: z.string().describe("Steps to fix the issue"),
  references: z.string().optional().describe("CVE, CWE, or related references"),
  toolCallDescription: z
    .string()
    .describe("Concise description of this tool call"),
});

export type Finding = z.infer<typeof FindingObject>;

export async function documentFindingAgent(
  finding: Finding,
  model: AIModel,
  session: Session,
  authConfig?: AIAuthConfig,
  toolOverride?: {
    create_poc?: (opts: CreatePocOpts) => Promise<CreatePocResult>;
  }
) {
  const logger = new Logger(session, "documentFindingAgent.log");
  // Create pocs directory for pentest agent
  const pocsPath = join(session.rootPath, "pocs");
  if (!existsSync(pocsPath)) {
    mkdirSync(pocsPath, { recursive: true });
  }
  // Pentest-specific tool: create_poc
  const create_poc = tool({
    name: "create_poc",
    description: `Create a Proof-of-Concept (POC) file to demonstrate a vulnerability.

**PRIMARY TYPE: bash scripts** - Most POCs should be executable bash scripts
**SECONDARY TYPE: html files** - For web-based exploits (XSS, CSRF, clickjacking)

Supported POC types:
- **bash** (RECOMMENDED): Executable bash scripts for most vulnerabilities
  * SQL injection, NoSQL injection
  * Command injection, SSRF
  * XXE, deserialization
  * API exploitation, authentication bypass
  * Template injection
  * Any vulnerability testable via curl/http requests
  
- **html**: HTML files for browser-based exploits
  * XSS demonstrations
  * CSRF attack forms
  * Clickjacking POCs
  * Open redirect exploits

This tool will:
1. Create the POC file in the pocs/ directory (.sh or .html)
2. For bash scripts: Make executable (chmod +x) and execute to verify it works
3. For html files: Create file only (test manually in browser)
4. Return execution output/errors for validation

**PREFERENCE:** Use bash scripts whenever possible - they can be automatically tested.

Use this tool BEFORE document_finding to:
- Create working POC scripts for vulnerabilities
- Automatically test that bash POCs work
- Verify the POC demonstrates the vulnerability

The POC should be self-contained and demonstrate the vulnerability clearly.`,
    inputSchema: CreatePocObject,
    execute: async (poc) => {
      try {
        if (toolOverride?.create_poc) {
          return toolOverride.create_poc(poc);
        }
        // Determine file extension based on pocType
        const extension = poc.pocType === "bash" ? ".sh" : ".html";

        // Sanitize filename
        const sanitizedName = poc.pocName
          .toLowerCase()
          .replace(/[^a-z0-9_-]/g, "_")
          .replace(/^poc_/, ""); // Remove poc_ prefix if already there

        const filename = `poc_${sanitizedName}${extension}`;
        const pocPath = join(pocsPath, filename);
        const relativePocPath = `pocs/${filename}`;

        // Check if POC already exists
        if (existsSync(pocPath)) {
          return {
            success: false,
            error: "POC_EXISTS",
            pocPath: relativePocPath,
            message: `POC already exists at: ${relativePocPath}\n\nIf you want to update it, you'll need to use a different name or modify the existing file directly.`,
          };
        }

        let pocContent = poc.pocContent.trim();

        // Add headers based on POC type
        if (poc.pocType === "bash") {
          // Ensure POC starts with shebang
          if (!pocContent.startsWith("#!")) {
            pocContent = "#!/bin/bash\n" + pocContent;
          }

          // Add header comments if not present
          if (!pocContent.includes("# POC:")) {
            const header = `#!/bin/bash
# POC: ${poc.description}
# Target: ${session.target}
# Created: ${new Date().toISOString()}
# Session: ${session.id}

`;
            pocContent = header + pocContent.replace(/^#!\/bin\/bash\s*\n/, "");
          }
        } else if (poc.pocType === "html") {
          // Add HTML comment header if not present
          if (!pocContent.includes("<!-- POC:")) {
            const header = `<!-- 
POC: ${poc.description}
Target: ${session.target}
Created: ${new Date().toISOString()}
Session: ${session.id}

To test this POC:
1. Open this file in a web browser: file://${pocPath}
2. Or serve it and navigate to the target application
3. Observe the vulnerability demonstration (e.g., XSS alert, CSRF execution)
-->

`;
            pocContent = header + pocContent;
          }
        }

        // Write POC to file
        writeFileSync(pocPath, pocContent);

        // Execute POC only for bash scripts
        let executionResult;

        if (poc.pocType === "bash") {
          // Make executable
          chmodSync(pocPath, 0o755);

          try {
            const { stdout, stderr } = await execAsync(
              `cd ${session.rootPath} && ./${relativePocPath}`,
              {
                timeout: 30000, // 30 second timeout
                maxBuffer: 1024 * 1024, // 1MB buffer
              }
            );

            executionResult = {
              success: true,
              exitCode: 0,
              stdout: stdout || "(no output)",
              stderr: stderr || "(no errors)",
            };
          } catch (execError: any) {
            // Execution failed or timed out - DELETE the failed POC
            logger.log(`POC execution failed, deleting file: ${filename}`);

            // Delete the failed POC file
            try {
              unlinkSync(pocPath);
            } catch (deleteError: any) {
              logger.error(`Failed to delete POC file: ${deleteError.message}`);
            }

            executionResult = {
              success: false,
              exitCode: execError.code || 1,
              stdout: execError.stdout || "(no output)",
              stderr: execError.stderr || execError.message,
              error: execError.message,
              fileDeleted: true,
            };
          }
        } else {
          // HTML POC - no automatic execution
          executionResult = {
            success: true,
            executionSkipped: true,
            reason: "HTML POCs require manual testing in a web browser",
            instructions: `To test this HTML POC:
1. Open in browser: file://${pocPath}
2. Or serve via HTTP: python3 -m http.server 8000 (in pocs/ directory)
3. Navigate to http://localhost:8000/${filename}
4. Observe the exploit demonstration`,
          };
        }

        // Build appropriate message based on POC type
        let message;

        if (poc.pocType === "bash") {
          if (executionResult.success) {
            // POC executed successfully
            message = `POC created at: ${relativePocPath}

**Execution Result:**
- Exit Code: ${executionResult.exitCode}
- Success: ✅ Yes

**STDOUT:**
\`\`\`
${executionResult.stdout}
\`\`\`

**STDERR:**
\`\`\`
${executionResult.stderr}
\`\`\`

✅ POC executed successfully! You can now use this POC path with document_finding.

**Next Steps:**
1. Review the output to confirm the vulnerability is demonstrated
2. If output looks good, call document_finding with pocPath: "${relativePocPath}"
3. Include the execution output as evidence in your finding`;
          } else {
            // POC execution failed - file was deleted
            message = `❌ POC execution FAILED and file has been DELETED

**Attempted POC:** ${relativePocPath} (deleted)
**Exit Code:** ${executionResult.exitCode}

**STDOUT:**
\`\`\`
${executionResult.stdout}
\`\`\`

**STDERR:**
\`\`\`
${executionResult.stderr}
\`\`\`

⚠️  The POC failed to execute and has been automatically deleted from the pocs/ directory.

**What Went Wrong:**
${executionResult.error || "POC script encountered an error during execution"}

**Next Steps:**
1. Review the error output above to understand what failed
2. Fix the POC script (check syntax, commands, target URL, etc.)
3. Create a new POC with create_poc using corrected script content
4. Test again until it works
5. Only after POC executes successfully, call document_finding

**Common Issues:**
- Syntax errors in bash script
- Invalid curl commands or URLs
- Missing dependencies or tools
- Network connectivity issues
- Timeout (>30 seconds)

Create a corrected version of the POC and try again.`;
          }
        } else {
          // HTML POC
          message = `HTML POC created at: ${relativePocPath}

**POC Type:** HTML (browser-based exploit)
**File Location:** ${pocPath}

**Manual Testing Required:**
HTML POCs cannot be automatically executed. To test this POC:

1. **Option A - File Protocol:**
   - Open in browser: file://${pocPath}

2. **Option B - HTTP Server:**
   \`\`\`bash
   cd ${session.rootPath}/pocs
   python3 -m http.server 8000
   \`\`\`
   - Navigate to: http://localhost:8000/${filename}

3. **Option C - Target Application:**
   - If POC includes a form or requires target interaction
   - Follow the instructions in the HTML file

**Testing Instructions:**
${executionResult.instructions}

**Next Steps:**
1. Test the HTML POC manually using one of the methods above
2. Verify the vulnerability is demonstrated (XSS alert, CSRF execution, etc.)
3. If the POC works, call document_finding with pocPath: "${relativePocPath}"
4. In your finding evidence, describe how you tested the HTML POC

✅ HTML POC created successfully. Test manually, then document the finding.`;
        }

        // For bash POCs that failed, success = false (file was deleted)
        const overallSuccess =
          poc.pocType === "bash" ? executionResult.success : true;

        return {
          success: overallSuccess,
          pocPath: overallSuccess ? relativePocPath : null, // No path if deleted
          fullPath: overallSuccess ? pocPath : null,
          pocType: poc.pocType,
          description: poc.description,
          execution: executionResult,
          fileDeleted: poc.pocType === "bash" && !executionResult.success,
          message,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          message: `Failed to create POC: ${error.message}`,
        };
      }
    },
  });

  // Pentest-specific tool: document_finding with POC validation
  const document_finding = tool({
    name: "document_finding",
    description: `Document a security finding with severity, impact, and remediation guidance.

**CRITICAL REQUIREMENT:** You MUST provide a valid POC path. The POC script must exist before documenting.

WORKFLOW:
1. Discover potential vulnerability
2. Use create_poc tool to create and test the POC script
3. Review create_poc execution output to confirm vulnerability
4. Call document_finding with the POC path from create_poc
5. If POC doesn't exist, you'll get an error - use create_poc first, then retry

**RECOMMENDED:** Use create_poc tool to create POCs - it automatically tests them and reports output.

SEVERITY LEVELS:
- CRITICAL: Immediate risk of system compromise (RCE, auth bypass, SQL injection with data access)
- HIGH: Significant security risk (XSS, CSRF, sensitive data exposure, privilege escalation)
- MEDIUM: Security weakness that could be exploited (information disclosure, weak configs)
- LOW: Minor security concern (missing headers, verbose errors)

FINDING STRUCTURE:
- Title: Clear, concise description
- Severity: Use CVSS if applicable
- Description: Detailed technical explanation
- Impact: Business and technical consequences
- Evidence: Commands run, responses received, proof of vulnerability
- Endpoint: The full URL Endpoint of the finding. Do not include any other text. i.e. https://example.com/endpoint. If this is an application wide vulnerability, consider it apart of the root path i.e. https://example.com/
- POC Path: Path to the proof-of-concept script (REQUIRED)
- Remediation: Specific, actionable steps to fix
- References: CVE, CWE, OWASP, or security advisories`,
    inputSchema: ApexFindingObject,
    execute: async (finding) => {
      try {
        // Validate POC path exists
        const fullPocPath = join(session.rootPath, finding.pocPath);

        if (!existsSync(fullPocPath)) {
          return {
            success: false,
            error: "POC_NOT_FOUND",
            message: `POC script not found at: ${finding.pocPath}

**ACTION REQUIRED:** 
1. Create the POC script first at: ${finding.pocPath}
2. Test the POC to verify it works
3. Then call document_finding again with the same parameters

The POC script should:
- Be executable (chmod +x)
- Demonstrate the vulnerability
- Include clear comments
- Show success indicators

Example POC structure:
\`\`\`bash
#!/bin/bash
# POC: ${finding.title}
# Severity: ${finding.severity}

TARGET="${session.target}"
echo "[*] Testing ${finding.title}"
# ... exploitation commands ...
echo "[+] Vulnerability confirmed"
\`\`\`

Create this POC, test it, then retry document_finding.`,
            pocPath: finding.pocPath,
            expectedLocation: fullPocPath,
          };
        }

        const timestamp = new Date().toISOString();
        const findingWithMeta = {
          ...finding,
          timestamp,
          sessionId: session.id,
          target: session.target,
          pocPath: finding.pocPath,
        };

        // Create a safe filename from the title
        const safeTitle = finding.title
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/^-|-$/g, "")
          .substring(0, 50);

        const findingId = `${timestamp.split("T")[0]}-${safeTitle}`;
        const filename = `${findingId}.json`;
        const filepath = join(session.findingsPath, filename);

        // Create markdown document with POC reference
        //         const markdown = `# ${finding.title}

        // **Severity:** ${finding.severity}
        // **Target:** ${session.target}
        // **Date:** ${timestamp}
        // **Session:** ${session.id}
        // **POC:** \`${finding.pocPath}\`

        // ## Description

        // ${finding.description}

        // ## Impact

        // ${finding.impact}

        // ## Evidence

        // \`\`\`
        // ${finding.evidence}
        // \`\`\`

        // ## Proof of Concept

        // A working POC script is available at: \`${finding.pocPath}\`

        // To reproduce this vulnerability, run:
        // \`\`\`bash
        // cd ${session.rootPath}
        // ./${finding.pocPath}
        // \`\`\`

        // ## Remediation

        // ${finding.remediation}

        // ${finding.references ? `## References\n\n${finding.references}` : ""}

        // ---

        // *This finding was automatically documented by the Pensar penetration testing agent.*
        // *POC verified and available at: ${finding.pocPath}*
        // `;

        writeFileSync(filepath, JSON.stringify(findingWithMeta, null, 2));

        // Also append to a summary file
        const summaryPath = join(session.rootPath, "findings-summary.md");
        const summaryEntry = `- [${finding.severity}] ${finding.title} - \`findings/${filename}\` - POC: \`${finding.pocPath}\`\n`;

        try {
          appendFileSync(summaryPath, summaryEntry);
        } catch (e) {
          // File doesn't exist, create it with header
          const header = `# Findings Summary\n\n**Target:** ${session.target}  \n**Session:** ${session.id}\n\n## All Findings\n\n`;
          writeFileSync(summaryPath, header + summaryEntry);
        }

        return {
          success: true,
          finding: findingWithMeta,
          filepath,
          pocPath: finding.pocPath,
          pocVerified: true,
          message: `Finding documented with POC: [${finding.severity}] ${finding.title}`,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          message: `Failed to document finding: ${error.message}`,
        };
      }
    },
  });

  // Read all existing findings to check for duplicates
  const findingsPath = join(session.rootPath, "findings");
  let existingFindingsText = "";

  if (existsSync(findingsPath)) {
    const findingFiles = readdirSync(findingsPath).filter((f) =>
      f.endsWith(".json")
    );

    for (const file of findingFiles) {
      try {
        const filePath = join(findingsPath, file);
        const content = readFileSync(filePath, "utf-8");
        const finding = JSON.parse(content);
        existingFindingsText += `\n\n---\nFile: ${file}\nTitle: ${finding.title}\nSeverity: ${finding.severity}\nDescription: ${finding.description}`;
      } catch (error) {
        console.error(`Failed to read finding file ${file}:`, error);
      }
    }
  }

  // Create final documentation tool
  let documentationResult: any = null;

  const finalize_documentation = tool({
    name: "finalize_documentation",
    description: `Finalize the finding documentation after POC verification.
    
Call this tool to indicate the finding has been successfully documented or should be discarded.`,
    inputSchema: z.object({
      action: z.enum(["documented", "discarded"]).describe("Action taken"),
      reason: z.string().describe("Reason for the action"),
      pocPath: z.string().optional().describe("POC path if documented"),
      findingPath: z
        .string()
        .optional()
        .describe("Finding file path if documented"),
      toolCallDescription: z.string().describe("Description of this action"),
    }),
    execute: async (result) => {
      documentationResult = result;
      return {
        success: true,
        action: result.action,
        message: result.reason,
      };
    },
  });

  // System prompt for the agent
  const SYSTEM_PROMPT = `You are a finding documentation specialist agent. Your role is to validate, create POCs for, and document security findings while eliminating duplicates.

# Your Workflow

You will be provided with:
- **Proposed Finding**: A security vulnerability to validate and document
- **Existing Findings**: All currently documented findings in this session

Your job is to:

## Step 1: Duplicate Detection

Review the existing findings and determine if the proposed finding is:
- **Duplicate**: Exact same vulnerability already documented → DISCARD
- **Variation**: Similar vulnerability in same location → DISCARD  
- **Unique**: New, distinct vulnerability → PROCEED

**Duplicate Examples:**
- Both are "SQL Injection in /login" → Duplicate, discard
- Both are "XSS in search parameter" → Duplicate, discard
- "Missing X-Frame-Options" + "Missing Clickjacking Protection" → Variation, discard

**Unique Examples:**
- "SQL Injection in /login" vs "SQL Injection in /register" → Different locations, both valid
- "XSS in search" vs "XSS in comments" → Different locations, both valid
- "NoSQL injection in API" vs "SQL injection in web" → Different types, both valid

## Step 2: POC Creation & Iteration

If finding is unique, create a working POC:

1. **Draft initial POC** based on the evidence provided
2. **Use create_poc tool** with pocType: "bash" (preferred) or "html"
3. **Review execution results**:
   - If bash POC succeeds → Proceed to Step 3
   - If bash POC fails → Analyze error, fix, and retry with new poc name
   - If HTML POC → Note that manual testing is required
4. **Iterate until working** - Try up to 3 times if needed
5. **If unable to create working POC** → DISCARD (not confirmed)

## Step 3: Document Finding

Once you have a working POC:

1. **Call document_finding** with:
   - All provided finding details
   - POC path from successful create_poc
   - Enhanced evidence including POC execution output
2. **Verify documentation succeeded**
3. **Call finalize_documentation** with action: "documented"

## Step 4: Finalization

Call finalize_documentation with:
- **action: "documented"** if successfully created POC and documented
- **action: "discarded"** if duplicate or unable to create working POC
- **reason**: Clear explanation of why

# Important Rules

- **Be strict on duplicates** - Don't document the same thing twice
- **Be lenient on variations** - Same vulnerability, different location = unique
- **Require working POCs** - If you can't create a working POC after 3 tries, discard
- **Prefer bash POCs** - They're auto-tested
- **Iterate on failures** - Fix POC script based on error output
- **Explain your decisions** - Why is it duplicate? Why did POC fail?

# Example Outputs

**Duplicate Detection:**
"This finding is a DUPLICATE of existing finding 'SQL Injection in Login Form'. Both describe SQL injection in the /login endpoint with the same impact. DISCARDING this finding."

**POC Iteration:**
"First POC attempt failed with syntax error. Reviewing error output... The issue is missing quotes around the target URL. Creating corrected POC version 2..."

**Successful Documentation:**
"POC executed successfully showing SQL injection bypass. Documenting finding with pocPath: pocs/poc_sqli_login_v2.sh"

**Failed After Retries:**
"After 3 attempts, unable to create working POC for this finding. The vulnerability may not be exploitable or the evidence is insufficient. DISCARDING this finding."

Remember: Your goal is quality over quantity. Only document confirmed, unique, reproducible vulnerabilities.
`;

  // Build prompt with proposed finding and existing findings
  const prompt = `
**PROPOSED FINDING TO VALIDATE:**

Title: ${finding.title}
Severity: ${finding.severity}
Description: ${finding.description}
Impact: ${finding.impact}
Evidence: ${finding.evidence}
Remediation: ${finding.remediation}
${finding.references ? `References: ${finding.references}` : ""}

**EXISTING FINDINGS IN SESSION:**
${existingFindingsText || "(No existing findings - this would be the first)"}

---

**YOUR TASK:**

1. **Check for duplicates**: Is this finding already documented? Is it a variation of an existing finding?

2. **If unique**: Create a working POC using the create_poc tool
   - Start with a bash POC based on the evidence
   - If it fails, analyze the error and create an improved version
   - Try up to 3 times to get a working POC
   - If you can't create a working POC, discard the finding

3. **If POC works**: Document the finding using document_finding tool with the POC path

4. **Finalize**: Call finalize_documentation to indicate success or failure

Begin your analysis now.
`.trim();

  // Run the agent
  const streamResult = streamResponse({
    prompt,
    system: SYSTEM_PROMPT,
    model,
    tools: {
      create_poc,
      document_finding,
      finalize_documentation,
    },
    authConfig,
    stopWhen: hasToolCall("finalize_documentation") || stepCountIs(1000),
  });

  for await (const delta of streamResult.fullStream) {
  }

  if (!documentationResult) {
    throw new Error("Document finding agent did not finalize");
  }

  return {
    action: documentationResult.action,
    reason: documentationResult.reason,
    pocPath: documentationResult.pocPath,
    findingPath: documentationResult.findingPath,
    success: documentationResult.action === "documented",
  };
}
