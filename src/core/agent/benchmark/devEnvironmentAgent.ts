import { stepCountIs, tool } from "ai";
import { z } from "zod";
import { streamResponse, type AIModel } from "../../ai";
import { existsSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { exec as nodeExec } from "child_process";
import { promisify } from "util";
import { detectOSAndEnhancePrompt } from "../utils";
import { createPentestTools } from "../pentestAgent";
import type { Session } from "../sessions";

const exec = promisify(nodeExec);

const DEV_ENVIRONMENT_SYSTEM_PROMPT = `
You are a development environment setup agent. Your role is to start a development environment using docker compose and fix any issues that prevent it from starting successfully.

# Your Task

You will be provided with:
- **Working Directory**: Path to the application
- **Docker Compose File**: The docker-compose.yml or similar file

Your job is to:
1. **Attempt to start the environment** using docker compose up
2. **Diagnose any errors** if the startup fails
3. **Fix issues** by editing configuration files (docker-compose.yml, .env, config files, etc.)
4. **Retry until successful** or determine the issue is unfixable
5. **Report success** with the target URL

# Common Issues You Can Fix

- Port conflicts (change exposed ports in docker-compose.yml)
- Missing environment variables (create/edit .env file or add to docker-compose)
- Volume mount issues (adjust paths in docker-compose.yml)
- Network configuration problems
- Service dependency ordering (depends_on in docker-compose.yml)
- Resource limit issues
- Missing configuration files (create .env, config files)
- Syntax errors in docker-compose.yml or config files
- Database initialization issues (check .sql files, env vars)

# Tools at Your Disposal

- **read_file**: Read any file in the working directory (docker-compose.yml, .env, config files, etc.)
- **edit_file**: Edit any file to fix issues or add configuration
- **start_docker_compose**: Attempt to start the environment
- **check_docker_logs**: Read logs from failed containers
- **check_service_health**: Verify if services are running
- **report_environment_ready**: Report success with target URL

# Important Guidelines

- **Be proactive**: Read configuration files to understand dependencies
- **Fix comprehensively**: Edit docker-compose.yml, .env, or any config file needed
- **Document changes**: Explain what you changed and why
- **Try multiple times**: If first attempt fails, diagnose and fix
- **Give up gracefully**: If issue is complex/unfixable, report failure with details
- **Default ports**: If port conflicts, try 3000, 3001, 3002, 8080, 8081, etc.
- **Create files**: If .env or config files are missing, create them with defaults

# Workflow

1. Install any necessary dependencies (e.g. npm install, yarn install, etc.)
2. Read docker-compose file to understand services and configuration
3. Check for .env file or other required config files (read them if they exist)
4. Attempt to start docker compose
5. If it fails:
   - Check logs to diagnose the issue
   - Identify what's wrong (missing file? wrong config? port conflict?)
   - Edit appropriate file (docker-compose.yml, .env, config files, etc.)
   - Try starting again
6. Once started:
   - Check service health
   - Determine the target URL (usually http://localhost:PORT)
   - Report success

# Example Fixes

Port Conflict:
- Edit docker-compose.yml: Change "3000:3000" to "3001:3000"

Missing .env File:
- Create .env file with required variables:
  \`\`\`
  NODE_ENV=development
  DATABASE_URL=postgresql://user:pass@db:5432/dbname
  API_KEY=default_key_for_testing
  \`\`\`

Missing Environment Variable in Service:
- Edit docker-compose.yml: Add environment section to service

Volume Mount Issues:
- Edit docker-compose.yml: Adjust volume paths

Database Connection Error:
- Edit .env: Fix DATABASE_URL or database credentials
- Or edit docker-compose.yml: Fix database service configuration

Be helpful and fix issues efficiently! You can read and edit ANY file in the working directory.
`;

interface DevEnvironmentAgentResult {
  success: boolean;
  targetUrl?: string;
  composeFile?: string;
  changes?: string[];
  error?: string;
}

export async function runDevEnvironmentAgent(
  workingDir: string,
  session: Session,
  branch: string,
  model: AIModel,
  abortSignal?: AbortSignal
): Promise<DevEnvironmentAgentResult> {
  console.log(`[DevEnvAgent] Starting in: ${workingDir}`);
  console.log(
    `[DevEnvAgent] Absolute path: ${require("path").resolve(workingDir)}`
  );

  let result: DevEnvironmentAgentResult = { success: false };

  // Find docker-compose file
  const composeFiles = [
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
  ];

  let composeFile: string | null = null;
  for (const file of composeFiles) {
    if (existsSync(join(workingDir, file))) {
      composeFile = file;
      break;
    }
  }

  if (!composeFile) {
    console.log(`[DevEnvAgent] No docker-compose file found in ${workingDir}`);
    return {
      success: false,
      error: "No docker-compose file found",
    };
  }

  // Create tools for the agent
  const read_file = tool({
    name: "read_file",
    description: "Read any file in the working directory or its subdirectories",
    inputSchema: z.object({
      filePath: z
        .string()
        .describe(
          "Path to file relative to working directory (e.g., 'docker-compose.yml', '.env', 'config/app.yml')"
        ),
      toolCallDescription: z
        .string()
        .describe("Brief description of why reading this file"),
    }),
    execute: async ({ filePath }) => {
      try {
        const fullPath = join(workingDir, filePath);

        // Security check - ensure path is within workingDir
        const resolvedPath = require("path").resolve(fullPath);
        const resolvedWorkingDir = require("path").resolve(workingDir);
        if (!resolvedPath.startsWith(resolvedWorkingDir)) {
          return {
            success: false,
            error: "Access denied: File path outside working directory",
          };
        }

        if (!existsSync(fullPath)) {
          return {
            success: false,
            error: `File not found: ${filePath}`,
          };
        }

        const content = readFileSync(fullPath, "utf-8");
        return {
          success: true,
          content,
          path: fullPath,
          relativePath: filePath,
        };
      } catch (error: any) {
        console.log(
          `[DevEnvAgent] Error reading ${filePath}: ${error.message}`
        );
        return {
          success: false,
          error: error.message,
        };
      }
    },
  });

  const edit_file = tool({
    name: "edit_file",
    description:
      "Edit any file in the working directory to fix issues or add configuration",
    inputSchema: z.object({
      filePath: z
        .string()
        .describe(
          "Path to file relative to working directory (e.g., 'docker-compose.yml', '.env', 'config/app.yml')"
        ),
      newContent: z.string().describe("The complete new content for the file"),
      changeDescription: z
        .string()
        .describe("Explanation of what changed and why"),
      toolCallDescription: z.string().describe("Brief description of the edit"),
    }),
    execute: async ({ filePath, newContent, changeDescription }) => {
      try {
        const fullPath = join(workingDir, filePath);

        // Security check - ensure path is within workingDir
        const resolvedPath = require("path").resolve(fullPath);
        const resolvedWorkingDir = require("path").resolve(workingDir);
        if (!resolvedPath.startsWith(resolvedWorkingDir)) {
          return {
            success: false,
            error: "Access denied: File path outside working directory",
          };
        }

        writeFileSync(fullPath, newContent);
        console.log(`[DevEnvAgent] Modified ${filePath}: ${changeDescription}`);

        if (!result.changes) result.changes = [];
        result.changes.push(`${filePath}: ${changeDescription}`);

        return {
          success: true,
          message: `Successfully updated ${filePath}`,
          change: changeDescription,
          path: fullPath,
        };
      } catch (error: any) {
        console.log(
          `[DevEnvAgent] Error editing ${filePath}: ${error.message}`
        );
        return {
          success: false,
          error: error.message,
        };
      }
    },
  });

  const start_docker_compose = tool({
    name: "start_docker_compose",
    description: "Attempt to start the docker compose environment",
    inputSchema: z.object({
      toolCallDescription: z.string().describe("Brief description"),
    }),
    execute: async () => {
      try {
        console.log(`[DevEnvAgent] Attempting docker compose up...`);
        const { stdout, stderr } = await exec(
          `docker compose -f ${composeFile} up -d`,
          { cwd: workingDir }
        );

        // Wait a bit for services to start
        await new Promise((resolve) => setTimeout(resolve, 5000));

        return {
          success: true,
          stdout,
          stderr,
          message: "Docker compose started successfully",
        };
      } catch (error: any) {
        console.log(`[DevEnvAgent] Error: ${error.message}`);
        return {
          success: false,
          error: error.message,
          stdout: error.stdout || "",
          stderr: error.stderr || "",
        };
      }
    },
  });

  const check_docker_logs = tool({
    name: "check_docker_logs",
    description: "Check logs from docker containers to diagnose issues",
    inputSchema: z.object({
      serviceName: z
        .string()
        .optional()
        .describe("Specific service name, or omit for all"),
      toolCallDescription: z.string().describe("Brief description"),
    }),
    execute: async ({ serviceName }) => {
      try {
        const cmd = serviceName
          ? `docker compose -f ${composeFile} logs ${serviceName}`
          : `docker compose -f ${composeFile} logs`;

        const { stdout, stderr } = await exec(cmd, { cwd: workingDir });

        return {
          success: true,
          logs: stdout || stderr,
        };
      } catch (error: any) {
        console.log(`[DevEnvAgent] Error: ${error.message}`);
        return {
          success: false,
          error: error.message,
          logs: error.stdout || error.stderr || "",
        };
      }
    },
  });

  const check_service_health = tool({
    name: "check_service_health",
    description: "Check if docker compose services are running",
    inputSchema: z.object({
      toolCallDescription: z.string().describe("Brief description"),
    }),
    execute: async () => {
      try {
        const { stdout } = await exec(`docker compose -f ${composeFile} ps`, {
          cwd: workingDir,
        });

        return {
          success: true,
          status: stdout,
          running: stdout.includes("Up") || stdout.includes("running"),
        };
      } catch (error: any) {
        console.log(`[DevEnvAgent] Error: ${error.message}`);
        return {
          success: false,
          error: error.message,
        };
      }
    },
  });

  const report_environment_ready = tool({
    name: "report_environment_ready",
    description: "Report that the environment is ready with the target URL",
    inputSchema: z.object({
      targetUrl: z
        .string()
        .describe(
          "The URL where the application is accessible (e.g., http://localhost:3000)"
        ),
      summary: z.string().describe("Brief summary of the setup"),
      toolCallDescription: z.string().describe("Brief description"),
    }),
    execute: async ({ targetUrl, summary }) => {
      console.log(`[DevEnvAgent] Environment ready: ${targetUrl}`);
      result = {
        success: true,
        targetUrl,
        composeFile: composeFile!,
        changes: result.changes,
      };

      return {
        success: true,
        message: `Environment ready. ${summary}`,
      };
    },
  });

  const { execute_command } = createPentestTools(session, model);

  // Build the prompt
  const prompt = `
Start the development environment in: ${workingDir}
Docker compose file: ${composeFile}

Your mission:
1. Read the docker-compose file (use read_file with path: "${composeFile}") to understand the setup
2. Check if .env or other config files are referenced - read them if they exist
3. Attempt to start the environment with start_docker_compose
4. If it fails, diagnose the issue and fix it:
   - Use read_file to read any configuration files you need
   - Use edit_file to modify docker-compose.yml, .env, or any other files
5. Retry until successful
6. Once running, determine the target URL and report success with report_environment_ready

You have access to read_file and edit_file - use them to read and modify ANY file in the working directory.

Begin by reading the docker-compose file.

Ensure the repo is on the correct branch: ${branch}. Use execute_command to check the current branch and switch to the correct branch if needed.
`.trim();

  // Run the agent
  const streamResult = streamResponse({
    prompt,
    system: DEV_ENVIRONMENT_SYSTEM_PROMPT,
    model,
    tools: {
      read_file,
      edit_file,
      start_docker_compose,
      check_docker_logs,
      check_service_health,
      report_environment_ready,
      execute_command,
    },
    stopWhen: stepCountIs(10000),
    toolChoice: "auto",
    abortSignal,
  });

  // Consume the stream and log progress
  console.log(`\n${"=".repeat(80)}`);
  console.log(`DEV ENVIRONMENT AGENT`);
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

  console.log(`\n${"=".repeat(80)}`);
  console.log(
    `DEV ENVIRONMENT ${result.success ? "READY" : `FAILED ${result.error}`}`
  );
  console.log(`${"=".repeat(80)}\n`);

  return result;
}
