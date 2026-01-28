import { tool, hasToolCall } from "ai";
import { z } from "zod";
import { join } from "path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { streamResponse, type AIModel } from "../../ai";
import type { OrchestratorInput, OrchestratorResult, SpawnSubagentInput } from "./newTypes";
import { SpawnSubagentSchema } from "./newTypes";
import type { SubAgentManifest, SubAgentConfig, VulnerabilityClass } from "../subagent/types";
import { VulnerabilityClassSchema } from "../subagent/types";
import type { AttackSurfaceAnalysisResults } from "../attackSurfaceAgent/types";
import { nanoid } from "nanoid";

const ORCHESTRATOR_SYSTEM_PROMPT = `You are a security testing orchestrator. Your job is to analyze the attack surface and intelligently spawn sub-agents to test for vulnerabilities.

## Your Role

1. Read and analyze the attack surface JSON (if available)
2. Understand each endpoint's purpose, parameters, and potential vulnerabilities
3. Decide which sub-agents to spawn for each endpoint
4. Consider which vulnerability classes are most relevant based on:
   - Endpoint functionality (auth endpoints → authentication bypass, sqli)
   - Parameter types (file paths → lfi, URLs → ssrf)
   - Technology stack (identified frameworks, databases)
   - Objective hints from attack surface analysis

## Vulnerability Classes

Available vulnerability classes to test:
- sql_injection: SQL/NoSQL injection
- xss: Cross-site scripting
- command_injection: OS command injection
- ssti: Server-side template injection
- path_traversal: LFI/path traversal
- ssrf: Server-side request forgery
- idor: Insecure direct object references
- authentication_bypass: Auth/session vulnerabilities
- jwt_vulnerabilities: JWT attacks
- deserialization: Insecure deserialization
- xxe: XML external entity
- crypto: Cryptographic weaknesses
- business_logic: Logic flaws
- generic: Other vulnerabilities

## Sub-agent Strategy

For each endpoint, consider spawning multiple sub-agents with different vulnerability focuses. For example:
- Login endpoint → authentication_bypass, sql_injection
- File download → path_traversal, idor
- User profile → idor, xss

Prioritize based on:
- critical: RCE potential (command_injection, ssti, deserialization)
- high: Data access (sql_injection, idor, path_traversal)
- medium: XSS, SSRF, crypto
- low: Info disclosure, generic

## Process

1. Call read_attack_surface to load the attack surface data (if available)
2. Optionally use search_source_code (if whitebox mode) to understand handlers
3. Build your sub-agent manifest by calling spawn_subagent for each test
4. Call finalize_manifest when done

Be thorough but intelligent - spawn sub-agents for likely vulnerabilities based on context.`;

const WHITEBOX_SYSTEM_PROMPT = `You are a security testing orchestrator with SOURCE CODE ACCESS. Your job is to analyze the source code for a target endpoint and spawn sub-agents to test for vulnerabilities.

## Your Role (Whitebox Mode)

You have access to the application's source code. Use this to make INFORMED decisions about which vulnerabilities to test. Don't just guess - ANALYZE the code.

## Analysis Process

1. **Find the route handler**: Use search_source_code or list_files to locate the endpoint's route definition
   - Search for the endpoint path in route files
   - Common patterns: \`.get('/path'\`, \`@app.route('/path')\`, \`@GetMapping\`

2. **Analyze the handler code**: Read the handler file to understand:
   - What parameters does it accept?
   - How are parameters used?
   - What database queries are made?
   - What external calls are made?
   - What file operations occur?

3. **Identify vulnerability patterns**: Look for specific code patterns:
   - SQL: String concatenation in queries, raw SQL, ORM misuse
   - Command injection: exec(), spawn(), system(), shell commands
   - Path traversal: File operations with user input, path.join without validation
   - SSTI: Template rendering with user input
   - SSRF: HTTP requests with user-controlled URLs
   - Deserialization: pickle.loads, JSON.parse of untrusted data, unserialize
   - XSS: User input reflected without encoding
   - Auth bypass: Weak session handling, JWT without verification

4. **Spawn targeted sub-agents**: Only spawn sub-agents for vulnerabilities you have evidence for:
   - Found a raw SQL query? → sql_injection
   - Found exec() with user input? → command_injection
   - Found file read with path parameter? → path_traversal

## Available Tools

- list_files: Find files matching a glob pattern (e.g., "**/*routes*.ts", "**/*controller*.py")
- search_source_code: Search for code patterns using regex
- read_file: Read a specific file's contents
- spawn_subagent: Add a sub-agent for a specific vulnerability test
- finalize_manifest: Complete the orchestration

## Vulnerability Classes

- sql_injection: SQL/NoSQL injection - look for query(), execute(), raw SQL strings
- xss: Cross-site scripting - look for innerHTML, dangerouslySetInnerHTML, unescaped output
- command_injection: OS command injection - look for exec, spawn, system, shell commands
- ssti: Server-side template injection - look for render_template with user input
- path_traversal: LFI/path traversal - look for file operations with user-controlled paths
- ssrf: Server-side request forgery - look for HTTP clients with user-controlled URLs
- idor: Insecure direct object references - look for ID parameters without auth checks
- authentication_bypass: Auth vulnerabilities - look for weak auth logic, session handling
- jwt_vulnerabilities: JWT attacks - look for jwt.decode without verify, weak algorithms
- deserialization: Insecure deserialization - look for pickle, yaml.load, unserialize
- xxe: XML external entity - look for XML parsers without entity restrictions
- crypto: Cryptographic weaknesses - look for MD5, SHA1, weak random, hardcoded keys
- business_logic: Logic flaws - look for race conditions, pricing bugs, privilege issues
- nosql_injection: NoSQL injection - look for MongoDB queries with user input
- generic: Other vulnerabilities

## Important Guidelines

- BE SELECTIVE: Only spawn sub-agents for vulnerabilities you found evidence of in the code
- PROVIDE CONTEXT: Include the file path and relevant code snippets in the context field
- PRIORITIZE: Focus on the most critical vulnerabilities first
- DON'T GUESS: If you don't find evidence of a vulnerability pattern, don't spawn a sub-agent for it

## Process

1. Use list_files to find route/controller files
2. Use search_source_code to find the target endpoint's handler
3. Use read_file to examine the handler code in detail
4. Identify specific vulnerability patterns in the code
5. Spawn sub-agents ONLY for vulnerabilities you found evidence of
6. Call finalize_manifest when done`;

function createOrchestratorTools(
  input: OrchestratorInput,
  subagents: SubAgentConfig[]
) {
  const { attackSurfacePath, session, whiteboxMode, sourceCodePath } = input;

  const read_attack_surface = tool({
    description: "Read the attack surface JSON file",
    inputSchema: z.object({}),
    execute: async () => {
      if (!attackSurfacePath) {
        return { success: false, error: "No attack surface file available" };
      }
      try {
        const content = readFileSync(attackSurfacePath, "utf-8");
        const data = JSON.parse(content) as AttackSurfaceAnalysisResults;
        return { success: true, data };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const read_file = tool({
    description: "Read a file from the filesystem. Use this to examine source code files in detail.",
    inputSchema: z.object({
      path: z.string().describe("Absolute path to the file"),
    }),
    execute: async ({ path }) => {
      try {
        const content = readFileSync(path, "utf-8");
        return { success: true, content: content.slice(0, 15000) };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const list_files = tool({
    description: "List files matching a glob pattern. Use this to find route files, controllers, handlers, etc.",
    inputSchema: z.object({
      pattern: z.string().describe("Glob pattern to match files (e.g., '**/*routes*.ts', '**/controllers/**/*.py')"),
    }),
    execute: async ({ pattern }) => {
      if (!whiteboxMode) {
        return { success: false, error: "File listing only available in whitebox mode" };
      }
      const searchPath = sourceCodePath || ".";
      try {
        // Use find with glob pattern via bash
        const proc = Bun.spawn(
          ["bash", "-c", `find "${searchPath}" -type f -name "${pattern.replace(/\*\*\//g, "").replace(/\*\*/g, "*")}" 2>/dev/null | head -50`],
          { stdout: "pipe", stderr: "pipe" }
        );
        const stdout = await new Response(proc.stdout).text();
        const files = stdout.split("\n").filter((f) => f.trim());

        // If the simple find doesn't work well, try fd if available
        if (files.length === 0) {
          const fdProc = Bun.spawn(
            ["fd", "--type", "f", "--glob", pattern, searchPath],
            { stdout: "pipe", stderr: "pipe" }
          );
          const fdStdout = await new Response(fdProc.stdout).text();
          const fdFiles = fdStdout.split("\n").filter((f) => f.trim()).slice(0, 50);
          return { success: true, files: fdFiles };
        }

        return { success: true, files };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const search_source_code = tool({
    description: "Search source code for patterns using regex. Use this to find route definitions, SQL queries, dangerous functions, etc.",
    inputSchema: z.object({
      pattern: z.string().describe("Regex pattern to search (e.g., '\\.get\\s*\\(' for Express routes, 'query\\s*\\(' for SQL)"),
      filePattern: z.string().optional().describe("File glob pattern to filter (e.g., '*.ts', '*.py')"),
    }),
    execute: async ({ pattern, filePattern }) => {
      if (!whiteboxMode) {
        return { success: false, error: "Source code search only available in whitebox mode" };
      }
      const searchPath = sourceCodePath || ".";
      const glob = filePattern || "**/*";
      try {
        const args = ["--json", "-i", pattern];
        if (filePattern) {
          args.push("-g", filePattern);
        }
        args.push(searchPath);

        const proc = Bun.spawn(["rg", ...args], { stdout: "pipe", stderr: "pipe" });
        const stdout = await new Response(proc.stdout).text();
        const matches = stdout
          .split("\n")
          .filter((l) => l.trim())
          .map((l) => {
            try {
              return JSON.parse(l);
            } catch {
              return null;
            }
          })
          .filter((m) => m?.type === "match")
          .slice(0, 50);

        // Format matches for easier reading
        const formattedMatches = matches.map((m: any) => ({
          file: m.data?.path?.text,
          line: m.data?.line_number,
          content: m.data?.lines?.text?.trim(),
        }));

        return { success: true, matches: formattedMatches, count: formattedMatches.length };
      } catch (error: any) {
        return { success: false, error: error.message };
      }
    },
  });

  const spawn_subagent = tool({
    description: "Add a sub-agent to the manifest for spawning",
    inputSchema: SpawnSubagentSchema,
    execute: async ({ endpoint, vulnerabilityClass, context, priority, rationale }) => {
      const validClass = VulnerabilityClassSchema.safeParse(vulnerabilityClass);
      if (!validClass.success) {
        return {
          success: false,
          error: `Invalid vulnerability class: ${vulnerabilityClass}. Use one of: sql_injection, nosql_injection, xss, command_injection, ssti, path_traversal, ssrf, idor, authentication_bypass, jwt_vulnerabilities, deserialization, xxe, crypto, business_logic, generic`
        };
      }

      const subagentId = `subagent-${nanoid(6)}`;
      const config: SubAgentConfig = {
        id: subagentId,
        endpoint,
        vulnerabilityClass: validClass.data,
        context: { ...context, rationale },
        priority,
        whiteboxMode: whiteboxMode || false,
        sourceCodePath,
      };

      subagents.push(config);

      return {
        success: true,
        subagentId,
        message: `Sub-agent ${subagentId} added: ${vulnerabilityClass} testing for ${endpoint}`,
      };
    },
  });

  const finalize_manifest = tool({
    description: "Finalize the sub-agent manifest. Call when done adding all sub-agents.",
    inputSchema: z.object({
      summary: z.string().describe("Summary of the orchestration decisions"),
    }),
    execute: async ({ summary }) => {
      return {
        success: true,
        complete: true,
        totalSubagents: subagents.length,
        summary
      };
    },
  });

  return {
    read_attack_surface,
    read_file,
    list_files,
    search_source_code,
    spawn_subagent,
    finalize_manifest,
  };
}

export async function runOrchestrator(
  input: OrchestratorInput,
  model: AIModel
): Promise<OrchestratorResult> {
  const { session, attackSurfacePath, whiteboxMode, sourceCodePath, focusEndpoint, abortSignal } = input;

  const orchestratorDir = join(session.rootPath, "orchestrator");
  if (!existsSync(orchestratorDir)) {
    mkdirSync(orchestratorDir, { recursive: true });
  }

  const subagents: SubAgentConfig[] = [];
  const tools = createOrchestratorTools(input, subagents);

  // Use whitebox-specific prompt when in whitebox mode
  const systemPrompt = whiteboxMode ? WHITEBOX_SYSTEM_PROMPT : ORCHESTRATOR_SYSTEM_PROMPT;

  let userPrompt: string;

  if (whiteboxMode && sourceCodePath) {
    // Whitebox mode with source code - focus on code analysis
    userPrompt = `Analyze the source code and create a sub-agent manifest for security testing.

Source code path: ${sourceCodePath}`;

    if (attackSurfacePath && existsSync(attackSurfacePath)) {
      userPrompt += `\nAttack surface file: ${attackSurfacePath} (optional - use if helpful)`;
    }

    if (focusEndpoint) {
      userPrompt += `

## Target Endpoint
${focusEndpoint}

## Your Task

1. **Find the route handler** for ${focusEndpoint}:
   - Use list_files to find route files (e.g., "*routes*", "*controller*", "*handler*")
   - Use search_source_code to search for the endpoint path pattern

2. **Analyze the handler code**:
   - Use read_file to examine the handler implementation
   - Look for how parameters are processed
   - Identify database queries, file operations, external calls

3. **Identify vulnerability patterns**:
   - Look for string concatenation in queries (SQL injection)
   - Look for exec/spawn/system calls (command injection)
   - Look for file operations with user input (path traversal)
   - Look for template rendering with user input (SSTI)
   - Look for HTTP requests with user URLs (SSRF)
   - Look for weak auth checks (auth bypass)

4. **Spawn targeted sub-agents**:
   - ONLY spawn sub-agents for vulnerabilities you found evidence of
   - Include file paths and code snippets in the context field
   - Set appropriate priority based on severity

5. Call finalize_manifest when done`;
    } else {
      userPrompt += `

## Your Task

Analyze the entire codebase to understand the application structure and identify vulnerability patterns.

1. Use list_files to find key files (routes, controllers, models, services)
2. Use search_source_code to find vulnerability patterns
3. Use read_file to examine suspicious code in detail
4. Spawn sub-agents for each endpoint/vulnerability combination you identify
5. Call finalize_manifest when complete`;
    }
  } else {
    // Blackbox mode or no source code - use attack surface
    userPrompt = `Analyze the attack surface and create a sub-agent manifest for security testing.

Attack surface file: ${attackSurfacePath}`;

    if (whiteboxMode) {
      userPrompt += `\n\nThis is a WHITEBOX test. You have access to source code via search_source_code.
Use it to understand handlers, find SQL queries, identify dangerous functions, etc.`;
    }

    if (focusEndpoint) {
      userPrompt += `\n\nFocus specifically on this endpoint: ${focusEndpoint}
Spawn multiple sub-agents with different vulnerability classes for thorough testing.`;
    } else {
      userPrompt += `\n\nAnalyze ALL endpoints in the attack surface.
Spawn appropriate sub-agents for each endpoint based on its functionality.`;
    }

    userPrompt += `\n\nProcess:
1. Read the attack surface
2. Analyze each endpoint (${focusEndpoint ? "focusing on " + focusEndpoint : "all endpoints"})
3. Spawn sub-agents using spawn_subagent for each relevant vulnerability test
4. Call finalize_manifest when complete`;
  }

  try {
    const streamResult = streamResponse({
      prompt: userPrompt,
      system: systemPrompt,
      model,
      tools,
      stopWhen: hasToolCall("finalize_manifest"),
      abortSignal,
      silent: true,
    });

    for await (const chunk of streamResult.fullStream) {
      if (chunk.type === "error") {
        throw (chunk as any).error;
      }
    }

    const manifest: SubAgentManifest = {
      sessionId: session.id,
      createdAt: new Date().toISOString(),
      attackSurfacePath,
      whiteboxMode: whiteboxMode || false,
      subagents,
    };

    const manifestPath = join(orchestratorDir, "subagent-manifest.json");
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    return {
      success: true,
      manifest,
      manifestPath,
    };
  } catch (error: any) {
    const manifest: SubAgentManifest = {
      sessionId: session.id,
      createdAt: new Date().toISOString(),
      attackSurfacePath,
      whiteboxMode: whiteboxMode || false,
      subagents,
    };

    return {
      success: false,
      manifest,
      manifestPath: "",
      error: error.message,
    };
  }
}
