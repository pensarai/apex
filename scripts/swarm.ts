import { promisify } from "node:util";
import type { ExecuteCommandOpts, ExecuteCommandResult } from "../src/core/agent/tools";
import type { AIModel } from "../src/core/ai";
import { Session } from "../src/core/session";
import { exec as _exec } from "node:child_process";
import { runStreamlinedPentest } from "../src/core/agent/thoroughPentestAgent";

const exec = promisify(_exec);

interface SwarmAgentOptions {
    target: string;
    benchmarkPath: string;
    model?: AIModel;
};

async function runSwarmTest(options: SwarmAgentOptions) {
    const url = new URL(options.target);
    const session = await Session.create({
        targets: [options.target],
        name: "swarm-test",
        prefix: "swarm-test",
        config: {
            scopeConstraints: {
                allowedHosts: [url.host],
                strictScope: true
            }
        }
    });

    const BLOCKED_DOCKER_COMMANDS = [
      "docker",
      "docker-compose",
      "dockerd",
      "containerd",
      "ctr",
      "nerdctl",
    ];

    // Blocked filesystem paths - prevent reading benchmark source code or container data
    const BLOCKED_FS_PATHS = [
      options.benchmarkPath, // Prevent access to benchmark source code
      "/var/lib/docker", // Prevent direct access to container filesystems/databases
    ];

    const executeCommandOverride = async (
          opts: ExecuteCommandOpts
        ): Promise<ExecuteCommandResult> => {
          try {
            // Check for blocked docker commands
            const commandLower = opts.command.toLowerCase().trim();
            const firstWord = commandLower.split(/\s+/)[0] || "";
    
            // Block docker commands to prevent cheating
            if (
              BLOCKED_DOCKER_COMMANDS.some(
                (blocked) =>
                  firstWord === blocked ||
                  firstWord.startsWith(`${blocked} `) ||
                  commandLower.includes("docker ") ||
                  commandLower.includes("docker-compose ")
              )
            ) {
              return {
                command: opts.command,
                success: false,
                stdout: "",
                stderr:
                  "Docker commands are blocked in benchmark mode to prevent cheating. Use HTTP requests to interact with the target application.",
                error: "Docker commands are blocked in benchmark mode",
              };
            }
    
            // Block filesystem access to benchmark source code directory
            // This prevents cheating by reading source code directly
            for (const blockedPath of BLOCKED_FS_PATHS) {
              if (opts.command.includes(blockedPath)) {
                return {
                  command: opts.command,
                  success: false,
                  stdout: "",
                  stderr: `Access to ${blockedPath} is blocked in benchmark mode to prevent cheating. Use HTTP requests to interact with the target application.`,
                  error: `Filesystem access to ${blockedPath} is blocked in benchmark mode`,
                };
              }
            }
    
            // Execute command locally with timeout
            const effectiveTimeout = opts.timeout || 120000;
            const { stdout, stderr } =  await exec(opts.command, {
              timeout: effectiveTimeout,
              maxBuffer: 10 * 1024 * 1024, // 10MB buffer
            });
    
            return {
              command: opts.command,
              success: true,
              stdout,
              stderr,
              error: "",
            };
          } catch (error: any) {
            return {
              command: opts.command,
              success: false,
              stdout: error.stdout || "",
              stderr: error.stderr || error.message || String(error),
              error: error.message || String(error),
            };
          }
        };


        const pentestResult = await runStreamlinedPentest({
            target: options.target,
            model: options.model ?? "claude-haiku-4-5",
            session,
            toolOverride: {
                execute_command: executeCommandOverride
            },
            onProgress: (status) => {
                const progressParts: string[] = [`[swarm-test] [${status.phase}]`];

                if (status.tasksCompleted !== undefined && status.totalTasks !== undefined) {
                    progressParts.push(`[${status.tasksCompleted}/${status.totalTasks} tasks]`);
                }
                if (status.activeAgents !== undefined && status.activeAgents > 0) {
                    progressParts.push(`[${status.activeAgents} active]`);
                }
                progressParts.push(status.message);

                console.log(progressParts.join(' '));

                if (status.findingsCount !== undefined && status.findingsCount > 0) {
                    console.log(`[swarm-test]   Findings so far: ${status.findingsCount}`);
                }
            },
        });


        console.log(`[swarm-test] swarm test results can be found at: ${session.rootPath}`);
}


async function main() {
    const args = process.argv.slice(2);

    if(args.length === 0 || args.includes("--help") || args.includes("-h")) {
        console.error("Usage: bun run scripts/swarm.ts --target <url> [options]");
        console.error();
        console.error("Required:");
        console.error("  --target <url>           Target URL to authenticate against");
        console.error("  --benchmarkPath <path>   Path to benchmark directory");
        console.error();
        console.error("Options:");
        console.error("  --model <model>          AI model (default: claude-haiku-4-5)");
        console.error("                           Options: claude-sonnet-4-5, claude-opus-4-5, claude-haiku-4-5");
        process.exit(args.length === 0 ? 1: 0);
    }

    const targetIndex = args.indexOf("--target");
    const benchmarkPathIndex = args.indexOf("--benchmarkPath");
    const modelIndex = args.indexOf("--model");

    if(targetIndex === -1) {
        console.error("Error: --target is required");
        process.exit(1);
    }

    const target = args[targetIndex + 1];
    if(!target) {
        console.error("Error: --target must be followed by a URL");
        process.exit(1);
    }

    if(benchmarkPathIndex === -1) {
        console.error("Error: --benchmarkPath is required");
        process.exit(1);
    }

    const benchmarkPath = args[benchmarkPathIndex + 1];
    if(!benchmarkPath) {
        console.error("Error: --benchmarkPath must be followed by a directory path");
        process.exit(1);
    }

    let model: string | undefined;
    if(modelIndex !== -1) {
        model = args[modelIndex + 1];
        if(!model) {
            console.error("Error: --model must be followed by a model id");
            process.exit(1);
        }
    }

    try {
        await runSwarmTest({
            target,
            benchmarkPath,
            model
        });
    } catch(error: any) {
        console.error("Fatal error:", error.message);;
        process.exit(1);
    }
}

main().catch((error) => {
    console.error("Unhandled error:", error);
    process.exit(1);
});

export { runSwarmTest };