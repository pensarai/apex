import { stepCountIs, tool } from "ai";
import { z } from "zod";
import { streamResponse, type AIModel } from "../../ai";
import { existsSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { exec as nodeExec } from "child_process";
import { promisify } from "util";
import { detectOSAndEnhancePrompt } from "../utils";

const exec = promisify(nodeExec);

const DEV_ENVIRONMENT_SYSTEM_PROMPT = `
You are a development environment setup agent. Your role is to start a development environment using docker compose and fix any simple issues that prevent it from starting successfully.

# Your Task

You will be provided with:
- **Working Directory**: Path to the application
- **Docker Compose File**: The docker-compose.yml or similar file

Your job is to:
1. **Attempt to start the environment** using docker compose up
2. **Diagnose any errors** if the startup fails
3. **Fix simple issues** by editing the docker-compose file or related configuration
4. **Retry until successful** or determine the issue is unfixable
5. **Report success** with the target URL

# Common Issues You Can Fix

- Port conflicts (change exposed ports)
- Missing environment variables (add defaults or .env file)
- Volume mount issues (adjust paths)
- Network configuration problems
- Service dependency ordering
- Resource limit issues
- Simple syntax errors in docker-compose.yml

# Tools at Your Disposal

- **read_docker_compose**: Read the current docker-compose file
- **edit_docker_compose**: Make changes to the docker-compose file
- **start_docker_compose**: Attempt to start the environment
- **check_docker_logs**: Read logs from failed containers
- **check_service_health**: Verify if services are running
- **report_environment_ready**: Report success with target URL

# Important Guidelines

- **Be conservative**: Only fix issues you're confident about
- **Document changes**: Explain what you changed and why
- **Try multiple times**: If first attempt fails, diagnose and fix
- **Give up gracefully**: If issue is complex, report failure with details
- **Default ports**: If port conflicts, try 3000, 3001, 3002, 8080, 8081, etc.

# Workflow

1. Read the docker-compose file to understand the setup
2. Attempt to start docker compose
3. If it fails:
   - Check logs to diagnose the issue
   - Identify the fix needed
   - Edit the docker-compose file
   - Try starting again
4. Once started:
   - Check service health
   - Determine the target URL
   - Report success

# Example Fixes

Port Conflict:
- Change "3000:3000" to "3001:3000" (use different external port)

Missing Environment Variable:
- Add environment section with NODE_ENV=production

Volume Mount Issues:
- Adjust volume paths to match the actual filesystem

Be helpful and fix issues efficiently!
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
  const read_docker_compose = tool({
    name: "read_docker_compose",
    description: "Read the docker-compose file to understand the configuration",
    inputSchema: z.object({
      toolCallDescription: z
        .string()
        .describe("Brief description of why reading"),
    }),
    execute: async () => {
      try {
        const composePath = join(workingDir, composeFile!);
        const content = readFileSync(composePath, "utf-8");
        return {
          success: true,
          content,
          path: composePath,
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

  const edit_docker_compose = tool({
    name: "edit_docker_compose",
    description: "Edit the docker-compose file to fix issues",
    inputSchema: z.object({
      newContent: z.string().describe("The complete new content for the file"),
      changeDescription: z
        .string()
        .describe("Explanation of what changed and why"),
      toolCallDescription: z.string().describe("Brief description of the edit"),
    }),
    execute: async ({ newContent, changeDescription }) => {
      try {
        const composePath = join(workingDir, composeFile!);
        writeFileSync(composePath, newContent);
        console.log(
          `[DevEnvAgent] Modified docker-compose: ${changeDescription}`
        );

        if (!result.changes) result.changes = [];
        result.changes.push(changeDescription);

        return {
          success: true,
          message: `Successfully updated ${composeFile}`,
          change: changeDescription,
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

  // Build the prompt
  const prompt = `
Start the development environment in: ${workingDir}
Docker compose file: ${composeFile}

Your mission:
1. Read the docker-compose file to understand the setup
2. Attempt to start the environment with docker compose up
3. If it fails, diagnose the issue and fix it
4. Retry until successful
5. Once running, determine the target URL and report success

Begin by reading the docker-compose file.
`.trim();

  // Run the agent
  const streamResult = streamResponse({
    prompt,
    system: DEV_ENVIRONMENT_SYSTEM_PROMPT,
    model,
    tools: {
      read_docker_compose,
      edit_docker_compose,
      start_docker_compose,
      check_docker_logs,
      check_service_health,
      report_environment_ready,
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
