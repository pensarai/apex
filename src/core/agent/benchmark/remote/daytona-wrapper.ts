import { Daytona } from "@daytonaio/sdk";
import type { AIModel } from "../../../ai";
import path from "path";
import { mkdirSync, readFileSync, writeFileSync } from "fs";

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
 * Run benchmark for a single branch in its own dedicated sandbox
 */
async function runSingleBranchBenchmark(
  daytona: any,
  options: {
    repoUrl: string;
    branch: string;
    model: AIModel;
    anthropicKey?: string;
    openrouterKey?: string;
  }
): Promise<BenchmarkResults> {
  const { branch, repoUrl, model, anthropicKey, openrouterKey } = options;
  let sandbox: any;
  const startTime = Date.now();

  try {
    console.log(`[${branch}] 🚀 Creating Daytona sandbox...`);
    sandbox = await daytona.create(
      {
        language: "typescript",
        envVars: {
          ...(anthropicKey && { ANTHROPIC_API_KEY: anthropicKey }),
          ...(openrouterKey && { OPENROUTER_API_KEY: openrouterKey }),
        },
        public: true,
        networkBlockAll: false,
      },
      {
        timeout: 180000,
      }
    );

    console.log(`[${branch}] ✅ Sandbox created: ${sandbox.id}`);

    // Disable auto-stop for long-running benchmarks
    await sandbox.setAutostopInterval(0);
    console.log(`[${branch}] ✅ Auto-stop disabled`);

    // Install dependencies
    await installBun(sandbox, branch);
    await installApex(sandbox, branch);

    // Clone and run benchmark
    await cloneRepo(sandbox, repoUrl, branch);

    console.log(`[${branch}] 🔬 Creating benchmark session...`);
    await sandbox.process.createSession("benchmark");

    console.log(`[${branch}] 📊 Running benchmark...\n`);
    const { cmdId } = await sandbox.process.executeSessionCommand("benchmark", {
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

    // Stream logs with branch prefix
    await sandbox.process.getSessionCommandLogs(
      "benchmark",
      cmdId,
      (chunk: string) => {
        const lines = chunk.split('\n');
        lines.forEach(line => {
          if (line) process.stdout.write(`[${branch}] ${line}\n`);
        });
      },
      (chunk: string) => {
        const lines = chunk.split('\n');
        lines.forEach(line => {
          if (line) process.stderr.write(`[${branch}] ${line}\n`);
        });
      }
    );

    const command = await sandbox.process.getSessionCommand("benchmark", cmdId);
    const exitCode = command?.exitCode;

    console.log(`[${branch}] ✅ Benchmark completed with exit code: ${exitCode}`);

    if (exitCode !== 0) {
      throw new Error(`Benchmark failed with exit code ${exitCode}`);
    }

    // Download results
    const results = await downloadResults(sandbox, branch);

    const duration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
    console.log(`[${branch}] ✅ Completed in ${duration}m`);

    return results;
  } catch (error: any) {
    const duration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
    console.error(`[${branch}] ❌ Failed after ${duration}m: ${error.message}`);
    return {
      repoPath: repoUrl,
      branch,
      targetUrl: "",
      sessionId: "",
      sessionPath: "",
      expectedResults: [],
      actualResults: [],
      comparison: { error: error.message },
      timestamp: new Date().toISOString(),
    };
  } finally {
    if (sandbox) {
      try {
        console.log(`[${branch}] 🧹 Cleaning up sandbox...`);

        let attempts = 0;
        while (attempts < 10) {
          await sandbox.refreshData();
          if (sandbox.state !== "stopping" && sandbox.state !== "starting") {
            break;
          }
          await new Promise(resolve => setTimeout(resolve, 3000));
          attempts++;
        }

        await sandbox.delete();
        console.log(`[${branch}] ✅ Cleanup complete`);
      } catch (cleanupError: any) {
        console.error(`[${branch}] ⚠️  Cleanup failed: ${cleanupError.message}`);
      }
    }
  }
}

/**
 * Run benchmark in Daytona cloud sandbox (parallel execution)
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

  const branches = options.branches || ["main"];
  const startTime = Date.now();

  console.log("🚀 Starting parallel benchmark execution");
  console.log(`   Repository: ${options.repoUrl}`);
  console.log(`   Branches: ${branches.join(", ")}`);
  console.log(`   Model: ${options.model}`);
  console.log();

  // Initialize SDK
  const daytona = new Daytona({
    apiKey,
    organizationId: orgId,
    apiUrl: "https://app.daytona.io/api",
  });

  // Run all branches in parallel
  const results = await Promise.all(
    branches.map(branch =>
      runSingleBranchBenchmark(daytona, {
        repoUrl: options.repoUrl,
        branch,
        model: options.model,
        anthropicKey,
        openrouterKey,
      })
    )
  );

  const totalDuration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
  const successful = results.filter(r => !r.comparison.error).length;
  const failed = results.filter(r => r.comparison.error).length;

  console.log("\n" + "=".repeat(80));
  console.log("📊 PARALLEL BENCHMARK SUMMARY");
  console.log("=".repeat(80));
  console.log(`Total Duration: ${totalDuration}m`);
  console.log(`Successful: ${successful}/${branches.length}`);
  console.log(`Failed: ${failed}/${branches.length}`);
  console.log();

  // Generate summary report
  await generateSummaryReport(results, options.repoUrl, options.model, totalDuration);

  return results;
}

/**
 * Install Bun runtime
 */
async function installBun(sandbox: any, branch?: string): Promise<void> {
  const prefix = branch ? `[${branch}] ` : "";
  console.log(`${prefix}📦 Installing Bun...`);

  const installResult = await sandbox.process.executeCommand(
    "curl -fsSL https://bun.sh/install | bash"
  );

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

  console.log(`${prefix}✅ Bun installed: v${verifyResult.result.trim()}`);
}

/**
 * Install Apex using bun
 */
async function installApex(sandbox: any, branch?: string): Promise<void> {
  const prefix = branch ? `[${branch}] ` : "";
  console.log(`${prefix}📦 Installing Apex globally via bun...`);

  try {
    // Install using bun (ensures bun PATH is working)
    const installResult = await sandbox.process.executeCommand(
      'export BUN_INSTALL="$HOME/.bun" && export PATH="$BUN_INSTALL/bin:$PATH" && bun install -g @pensar/apex'
    );

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

    console.log(`${prefix}✅ Apex installed at: ${installedPath}`);
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
  const prefix = `[${branch}] `;
  console.log(`${prefix}📦 Cloning repository: ${repoUrl} (${branch})...`);

  // Use Daytona's git.clone() - automatically clones and checks out branch
  await sandbox.git.clone(repoUrl, "repo", branch);

  console.log(`${prefix}✅ Repository cloned to ~/repo`);
}

/**
 * Download benchmark results from sandbox
 */
async function downloadResults(
  sandbox: any,
  branch: string
): Promise<BenchmarkResults> {
  const prefix = `[${branch}] `;
  console.log(`${prefix}⬇️  Downloading benchmark results...`);

  // Get user home directory
  const userHome = await sandbox.getUserHomeDir();
  if (!userHome) {
    throw new Error("Failed to get user home directory");
  }

  // Path to executions directory
  const executionsPath = path.join(userHome, ".pensar", "executions");

  // List all session directories
  const files = await sandbox.fs.listFiles(executionsPath);
  console.log(`${prefix}Found ${files.length} execution directories`);

  // Find the session for this branch (most recent)
  const branchSessions = files.filter((f: any) =>
    f.name.includes(`benchmark-${branch}`)
  );

  if (branchSessions.length === 0) {
    throw new Error(`No session found for branch ${branch}`);
  }

  // Get the most recent session (last in array)
  const sessionDir = branchSessions[branchSessions.length - 1].name;

  console.log(`${prefix}Downloading session: ${sessionDir}`);

  // Download all files in the session directory recursively
  const sessionPath = path.join(executionsPath, sessionDir);
  const localSessionPath = path.join(
    process.cwd(),
    ".pensar",
    "executions",
    sessionDir
  );

  // Download the entire session directory recursively
  await downloadDirectoryRecursive(sandbox, sessionPath, localSessionPath, branch);

  // Read benchmark_results.json
  const resultsPath = path.join(localSessionPath, "benchmark_results.json");
  const results = JSON.parse(readFileSync(resultsPath, "utf-8"));

  console.log(`${prefix}✅ Results downloaded to ${localSessionPath}`);
  return results;
}

/**
 * Recursively download a directory and all its contents
 */
async function downloadDirectoryRecursive(
  sandbox: any,
  remotePath: string,
  localPath: string,
  branch?: string
): Promise<void> {
  const prefix = branch ? `[${branch}] ` : "";
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
        console.log(`${prefix}  📁 Downloading directory: ${file.name}`);
        await downloadDirectoryRecursive(sandbox, remoteFilePath, localFilePath, branch);
      } else {
        console.log(`${prefix}  📄 Downloading file: ${file.name}`);
        await sandbox.fs.downloadFile(remoteFilePath, localFilePath);
      }
    } catch (error: any) {
      if (error.message?.includes("file not found") || error.message?.includes("invalid")) {
        console.log(`${prefix}  📁 Retrying ${file.name} as directory...`);
        try {
          await downloadDirectoryRecursive(sandbox, remoteFilePath, localFilePath, branch);
        } catch (retryError: any) {
          console.error(`${prefix}  ⚠️  Skipping ${file.name}: ${retryError.message}`);
        }
      } else {
        console.error(`${prefix}  ⚠️  Skipping ${file.name}: ${error.message}`);
      }
    }
  }
}

/**
 * Generate summary report for parallel benchmark execution
 */
async function generateSummaryReport(
  results: BenchmarkResults[],
  repoUrl: string,
  model: AIModel,
  duration: string
): Promise<void> {
  const timestamp = new Date().toISOString();
  const summaryDir = path.join(
    process.cwd(),
    ".pensar",
    "executions",
    `parallel-run-${new Date().toISOString().replace(/[:.]/g, "-")}`
  );

  mkdirSync(summaryDir, { recursive: true });

  // Generate JSON summary
  const jsonSummary = {
    timestamp,
    repoUrl,
    model,
    totalBranches: results.length,
    successful: results.filter(r => !r.comparison.error).length,
    failed: results.filter(r => r.comparison.error).length,
    duration,
    branches: results.map(r => ({
      branch: r.branch,
      status: r.comparison.error ? "failed" : "success",
      error: r.comparison.error,
      sessionId: r.sessionId,
      sessionPath: r.sessionPath,
    })),
  };

  const jsonPath = path.join(summaryDir, "summary.json");
  writeFileSync(jsonPath, JSON.stringify(jsonSummary, null, 2));

  // Generate Markdown summary
  const markdown = [
    "# Parallel Benchmark Results",
    `**Repository**: ${repoUrl}`,
    `**Model**: ${model}`,
    `**Timestamp**: ${new Date(timestamp).toLocaleString()}`,
    `**Duration**: ${duration}m`,
    "",
    "## Summary",
    `- Successful: ${jsonSummary.successful}/${jsonSummary.totalBranches}`,
    `- Failed: ${jsonSummary.failed}/${jsonSummary.totalBranches}`,
    "",
    "## Branch Results",
    "",
  ];

  for (const branch of jsonSummary.branches) {
    const icon = branch.status === "success" ? "✅" : "❌";
    markdown.push(`### ${icon} ${branch.branch}`);
    markdown.push(`- **Status**: ${branch.status}`);
    if (branch.status === "success") {
      markdown.push(`- **Session**: ${branch.sessionId}`);
      markdown.push(`- **Results**: [${branch.sessionPath}](${branch.sessionPath})`);
    } else {
      markdown.push(`- **Error**: ${branch.error}`);
    }
    markdown.push("");
  }

  const mdPath = path.join(summaryDir, "summary.md");
  writeFileSync(mdPath, markdown.join("\n"));

  console.log(`📄 Summary reports saved to: ${summaryDir}`);
}