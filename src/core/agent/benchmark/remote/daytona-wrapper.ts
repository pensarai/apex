import { Daytona } from "@daytonaio/sdk";
import type { AIModel } from "../../../ai";
import path from "path";
import { mkdirSync, readFileSync } from "fs";

export interface DaytonaBenchmarkOptions {
  repoUrl: string; // Git URL (e.g., https://github.com/user/repo)
  branches?: string[];
  model: AIModel;
  apiKey?: string;
  orgId?: string;
  anthropicKey?: string; // Pass through to sandbox
  openrouterKey?: string; // Pass through to sandbox
}

interface BenchmarkResults {
  repoPath: string;
  branch: string;
  targetUrl: string;
  sessionId: string;
  sessionPath: string;
  expectedResults: any[];
  actualResults: any[];
  comparison: any;
  timestamp: string;
}

/**
 * Run benchmark in Daytona cloud sandbox
 */
export async function runBenchmarkInDaytona(
  options: DaytonaBenchmarkOptions
): Promise<BenchmarkResults[]> {
  const apiKey = options.apiKey || process.env.DAYTONA_API_KEY;
  const orgId = options.orgId || process.env.DAYTONA_ORG_ID;
  const anthropicKey = options.anthropicKey || process.env.ANTHROPIC_API_KEY;
  const openrouterKey = options.openrouterKey || process.env.OPENROUTER_API_KEY;

  if (!apiKey) {
    throw new Error(
      "DAYTONA_API_KEY is required. Set it via environment variable or pass it in options."
    );
  }

  if (!orgId) {
    throw new Error(
      "DAYTONA_ORG_ID is required. Set it via environment variable or pass it in options."
    );
  }

  if (!anthropicKey && !openrouterKey) {
    throw new Error(
      "At least one AI API key is required (ANTHROPIC_API_KEY or OPENROUTER_API_KEY)"
    );
  }

  // Initialize SDK
  const daytona = new Daytona({
    apiKey,
    organizationId: orgId,
    apiUrl: "https://app.daytona.io/api",
  });

  let sandbox: any;
  const results: BenchmarkResults[] = [];
  const branches = options.branches || ["main"];

  try {
    console.log("🚀 Creating Daytona sandbox (this may take up to 3 minutes)...");
    sandbox = await daytona.create(
      {
        language: "typescript",
        envVars: {
          ...(anthropicKey && { ANTHROPIC_API_KEY: anthropicKey }),
          ...(openrouterKey && { OPENROUTER_API_KEY: openrouterKey }),
        },
        public: true,
        networkBlockAll: false, // Ensure network access
      },
      {
        timeout: 180000, // 3 minutes in milliseconds
      }
    );

    console.log(`✅ Sandbox created: ${sandbox.id}`);

    // Disable auto-stop for long-running benchmarks (prevents 502 errors)
    await sandbox.setAutostopInterval(0);
    console.log("✅ Auto-stop disabled for benchmark");

    // Install bun first
    await installBun(sandbox);

    // Install Apex globally
    await installApex(sandbox);

    // Run benchmarks for each branch
    for (const branch of branches) {
      console.log(`\n${"=".repeat(80)}`);
      console.log(
        `[${branches.indexOf(branch) + 1}/${branches.length}] Branch: ${branch}`
      );
      console.log("=".repeat(80));

      try {
        const result = await runBenchmarkForBranch(
          sandbox,
          options.repoUrl,
          branch,
          options.model
        );
        results.push(result);
      } catch (error: any) {
        console.error(`❌ Failed to benchmark branch ${branch}: ${error.message}`);
        results.push({
          repoPath: options.repoUrl,
          branch,
          targetUrl: "",
          sessionId: "",
          sessionPath: "",
          expectedResults: [],
          actualResults: [],
          comparison: { error: error.message },
          timestamp: new Date().toISOString(),
        });
      }
    }

    return results;
  } catch (error: any) {
    console.error(`❌ Fatal error during benchmark execution: ${error.message}`);
    throw error;
  } finally {
    // Always cleanup sandbox if it was created
    if (sandbox) {
      try {
        console.log("\n🧹 Cleaning up sandbox...");

        let attempts = 0;
        while (attempts < 10) {
          await sandbox.refreshData();
          if (sandbox.state !== "stopping" && sandbox.state !== "starting") {
            break;
          }
          console.log(`⏳ Waiting for sandbox state transition... (${sandbox.state})`);
          await new Promise(resolve => setTimeout(resolve, 3000));
          attempts++;
        }

        await sandbox.delete();
        console.log("✅ Cleanup complete");
      } catch (cleanupError: any) {
        console.error(`⚠️  Warning: Failed to cleanup sandbox: ${cleanupError.message}`);
        console.error(`   Sandbox ID: ${sandbox.id} - Manual cleanup may be required`);
      }
    }
  }
}

/**
 * Install Bun runtime
 */
async function installBun(sandbox: any): Promise<void> {
  console.log("📦 Installing Bun...");

  const installResult = await sandbox.process.executeCommand(
    "curl -fsSL https://bun.sh/install | bash"
  );

  if (installResult.result) {
    console.log(installResult.result);
  }

  // Add bun to PATH in bashrc
  await sandbox.process.executeCommand(
    'echo \'export BUN_INSTALL="$HOME/.bun"\' >> ~/.bashrc && echo \'export PATH="$BUN_INSTALL/bin:$PATH"\' >> ~/.bashrc'
  );

  // Verify bun is accessible by running with explicit PATH
  const verifyResult = await sandbox.process.executeCommand(
    'export BUN_INSTALL="$HOME/.bun" && export PATH="$BUN_INSTALL/bin:$PATH" && bun --version'
  );

  if (!verifyResult.result || verifyResult.exitCode !== 0) {
    throw new Error("Bun installation verification failed");
  }

  console.log(`✅ Bun installed: v${verifyResult.result.trim()}`);
}

/**
 * Install Apex using bun
 */
async function installApex(sandbox: any): Promise<void> {
  console.log("📦 Installing Apex globally via bun...");

  try {
    // Install using bun (ensures bun PATH is working)
    const installResult = await sandbox.process.executeCommand(
      'export BUN_INSTALL="$HOME/.bun" && export PATH="$BUN_INSTALL/bin:$PATH" && bun install -g @pensar/apex'
    );

    if (installResult.result) {
      console.log(installResult.result);
    }

    if (installResult.exitCode !== 0) {
      throw new Error(`Bun install failed with exit code ${installResult.exitCode}`);
    }

    // Verify installation
    const verifyResult = await sandbox.process.executeCommand(
      'export BUN_INSTALL="$HOME/.bun" && export PATH="$BUN_INSTALL/bin:$PATH" && which pensar'
    );
    const installedPath = verifyResult.result?.trim();

    if (!installedPath) {
      throw new Error("Apex installation verification failed - pensar command not found");
    }

    console.log(`✅ Apex installed at: ${installedPath}`);
  } catch (error: any) {
    throw new Error(`Failed to install Apex: ${error.message}`);
  }
}

/**
 * Clone repository using Daytona's git API
 */
async function cloneRepo(
  sandbox: any,
  repoUrl: string,
  branch: string
): Promise<void> {
  console.log(`📦 Cloning repository: ${repoUrl} (${branch})...`);

  // Use Daytona's git.clone() - automatically clones and checks out branch
  await sandbox.git.clone(repoUrl, "repo", branch);

  console.log(`✅ Repository cloned to ~/repo`);
}

/**
 * Run benchmark for a specific branch with session-based execution
 */
async function runBenchmarkForBranch(
  sandbox: any,
  repoUrl: string,
  branch: string,
  model: AIModel
): Promise<BenchmarkResults> {
  // Clone repository (will switch branches for each run)
  await cloneRepo(sandbox, repoUrl, branch);

  // Create a session for the benchmark
  console.log("🔬 Creating benchmark session...");
  await sandbox.process.createSession("benchmark");

  console.log("📊 Running benchmark...");
  const { cmdId } =
    await sandbox.process.executeSessionCommand("benchmark", {
      command: [
        `export BUN_INSTALL="$HOME/.bun"`,
        `export PATH="$BUN_INSTALL/bin:$PATH"`,
        `export ANTHROPIC_API_KEY="${process.env.ANTHROPIC_API_KEY}"`,
        `export OPENROUTER_API_KEY="${process.env.OPENROUTER_API_KEY}"`,
        `pensar benchmark ./repo --model ${model}`,
      ].join(" && "),
      runAsync: true,  
    });

  if (!cmdId) {
    throw new Error("Failed to execute benchmark command");
  }

  console.log("⏳ Streaming benchmark logs...\n");

  // Stream logs in real-time using callbacks
  await sandbox.process.getSessionCommandLogs(
    "benchmark",
    cmdId,
    (chunk: string) => {
      // Stream stdout chunks as they arrive
      process.stdout.write(chunk);
    },
    (chunk: string) => {
      // Stream stderr chunks as they arrive
      process.stderr.write(chunk);
    }
  );

  // After streaming completes, get final command status
  const command = await sandbox.process.getSessionCommand("benchmark", cmdId);
  const exitCode = command?.exitCode;

  console.log(`\n✅ Benchmark completed with exit code: ${exitCode}`);

  if (exitCode !== 0) {
    throw new Error(`Benchmark failed with exit code ${exitCode}`);
  }

  // Download results
  const benchmarkResults = await downloadResults(sandbox, branch);

  return benchmarkResults;
}

/**
 * Download benchmark results from sandbox
 */
async function downloadResults(
  sandbox: any,
  branch: string
): Promise<BenchmarkResults> {
  console.log("⬇️  Downloading benchmark results...");

  // Get user home directory
  const userHome = await sandbox.getUserHomeDir();
  if (!userHome) {
    throw new Error("Failed to get user home directory");
  }

  // Path to executions directory
  const executionsPath = path.join(userHome, ".pensar", "executions");

  // List all session directories
  const files = await sandbox.fs.listFiles(executionsPath);
  console.log(`Found ${files.length} execution directories`);

  // Find the session for this branch (most recent)
  const branchSessions = files.filter((f: any) =>
    f.name.includes(`benchmark-${branch}`)
  );

  if (branchSessions.length === 0) {
    throw new Error(`No session found for branch ${branch}`);
  }

  // Get the most recent session (last in array)
  const sessionDir = branchSessions[branchSessions.length - 1].name;

  console.log(`Downloading session: ${sessionDir}`);

  // Download all files in the session directory recursively
  const sessionPath = path.join(executionsPath, sessionDir);
  const localSessionPath = path.join(
    process.cwd(),
    ".pensar",
    "executions",
    sessionDir
  );

  // Download the entire session directory recursively
  await downloadDirectoryRecursive(sandbox, sessionPath, localSessionPath);

  // Read benchmark_results.json
  const resultsPath = path.join(localSessionPath, "benchmark_results.json");
  const results = JSON.parse(readFileSync(resultsPath, "utf-8"));

  console.log(`✅ Results downloaded to ${localSessionPath}`);
  return results;
}

/**
 * Recursively download a directory and all its contents
 */
async function downloadDirectoryRecursive(
  sandbox: any,
  remotePath: string,
  localPath: string
): Promise<void> {
  // Create local directory
  mkdirSync(localPath, { recursive: true });

  // List files in remote directory
  const files = await sandbox.fs.listFiles(remotePath);

  for (const file of files) {
    const remoteFilePath = path.join(remotePath, file.name);
    const localFilePath = path.join(localPath, file.name);

    try {
      if (file.isDirectory) {
        // Recursively download subdirectory
        console.log(`  📁 Downloading directory: ${file.name}`);
        await downloadDirectoryRecursive(sandbox, remoteFilePath, localFilePath);
      } else {
        console.log(`  📄 Downloading file: ${file.name}`);
        await sandbox.fs.downloadFile(remoteFilePath, localFilePath);
      }
    } catch (error: any) {
      if (error.message?.includes("file not found") || error.message?.includes("invalid")) {
        console.log(`  📁 Retrying ${file.name} as directory...`);
        try {
          await downloadDirectoryRecursive(sandbox, remoteFilePath, localFilePath);
        } catch (retryError: any) {
          console.error(`  ⚠️  Skipping ${file.name}: ${retryError.message}`);
        }
      } else {
        console.error(`  ⚠️  Skipping ${file.name}: ${error.message}`);
      }
    }
  }
}