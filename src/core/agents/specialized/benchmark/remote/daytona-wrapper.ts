import { Daytona, type Sandbox } from "@daytonaio/sdk";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import pLimit from "p-limit";
import path from "path";
import type { AIModel } from "../../../../ai";
import { writeErrorLog } from "../../../../logger";
import { CircuitBreaker } from "./circuit-breaker";

/**
 * Retry a function with exponential backoff
 */
async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  options: {
    maxRetries?: number;
    initialDelay?: number;
    maxDelay?: number;
    retryableErrors?: string[];
    branch?: string;
  } = {},
): Promise<T> {
  const {
    maxRetries = 3,
    initialDelay = 1000,
    maxDelay = 30000,
    retryableErrors = [
      "429",
      "502",
      "503",
      "504",
      "ECONNRESET",
      "ETIMEDOUT",
      "rate limit",
      "rate_limit",
      "too many requests",
      "quota exceeded",
    ],
    branch,
  } = options;

  let lastError: Error;
  let delay = initialDelay;
  const prefix = branch ? `[${branch}] ` : "";

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      const errorMessage = error instanceof Error ? error.message : undefined;

      // Check if error is retryable
      const isRetryable = retryableErrors.some(
        (retryableError) =>
          errorMessage?.includes(retryableError) ||
          String(error).includes(retryableError),
      );

      // Don't retry on last attempt or non-retryable error
      if (attempt === maxRetries || !isRetryable) {
        throw error;
      }

      process.stderr.write(
        `${prefix}⚠️  Retry ${attempt + 1}/${maxRetries} after ${delay}ms (Error: ${errorMessage ?? String(error)})\n`,
      );

      // Wait with exponential backoff
      await new Promise((resolve) => setTimeout(resolve, delay));

      // Exponential backoff: 1s, 2s, 4s, 8s, max 30s
      delay = Math.min(delay * 2, maxDelay);
    }
  }

  throw lastError!;
}

/**
 * Shared circuit breaker for all Daytona operations
 * Prevents cascading failures when backend is down
 */
const daytonaCircuitBreaker = new CircuitBreaker({
  failureThreshold: 5, // Open after 5 consecutive failures
  resetTimeout: 60000, // Try again after 60 seconds
  successThreshold: 2, // Close after 2 consecutive successes
});

export interface DaytonaBenchmarkOptions {
  repoUrl: string; // Git URL (e.g., https://github.com/user/repo)
  branches?: string[];
  model: AIModel;
  apiKey?: string;
  orgId?: string;
  anthropicKey?: string; // Pass through to sandbox
  openrouterKey?: string; // Pass through to sandbox
  maxParallel?: number; // Max concurrent sandboxes (default: 4)
}

interface BenchmarkResults {
  repoPath: string;
  branch: string;
  targetUrl: string;
  sessionId: string;
  sessionPath: string;
  expectedResults: unknown[];
  actualResults: unknown[];
  comparison: Record<string, unknown>;
  timestamp: string;
  tokensIn?: number;
  tokensOut?: number;
  totalTokens?: number;
  flagDetected?: boolean;
  flagValue?: string | null;
  findingsCount?: number;
}

/**
 * Run benchmark for a single branch in its own dedicated sandbox.
 * Uses `pensar pentest` CLI directly instead of the benchmark runner script,
 * avoiding the need to clone Apex source or install its dependencies.
 */
async function runSingleBranchBenchmark(
  daytona: Daytona,
  options: {
    repoUrl: string;
    branch: string;
    model: AIModel;
    anthropicKey?: string;
    openrouterKey?: string;
  },
): Promise<BenchmarkResults> {
  const { branch, repoUrl, model, anthropicKey, openrouterKey } = options;
  let sandbox: Sandbox | undefined;
  const startTime = Date.now();

  try {
    process.stderr.write(`[${branch}] 🚀 Creating Daytona sandbox...\n`);
    sandbox = await daytonaCircuitBreaker.execute(() =>
      retryWithBackoff(
        () =>
          daytona.create(
            {
              image: "daytona/node:20-slim",
              language: "typescript",
              resources: {
                cpu: 4,
                memory: 8,
                disk: 10,
              },
              envVars: {
                ...(anthropicKey && { ANTHROPIC_API_KEY: anthropicKey }),
                ...(openrouterKey && { OPENROUTER_API_KEY: openrouterKey }),
              },
              public: true,
              networkBlockAll: false,
            },
            {
              timeout: 180000,
            },
          ),
        {
          maxRetries: 3,
          initialDelay: 2000,
          maxDelay: 30000,
          branch,
        },
      ),
    );

    process.stderr.write(`[${branch}] ✅ Sandbox created: ${sandbox.id}\n`);

    // Capture definite reference for use in closures
    const sbx = sandbox;

    // Disable auto-stop for long-running benchmarks
    await retryWithBackoff(() => sbx.setAutostopInterval(0), { branch });
    process.stderr.write(`[${branch}] ✅ Auto-stop disabled\n`);

    // Install dependencies
    await installBun(sandbox, branch);
    await installApex(sandbox, branch);
    await installDocker(sandbox, branch);

    // Clone benchmark repo (vulnerable apps)
    await cloneRepo(sandbox, repoUrl, branch);

    // Clone Apex source repo (contains the benchmark runner script)
    process.stderr.write(
      `[${branch}] 📦 Cloning Apex source for benchmark runner...\n`,
    );
    await retryWithBackoff(
      () =>
        sbx.git.clone(
          "https://github.com/pensarai/apex.git",
          "apex",
          "general-agent-harness",
        ),
      { branch },
    );

    // Install Apex dependencies
    process.stderr.write(`[${branch}] 📦 Installing Apex dependencies...\n`);
    await retryWithBackoff(
      () =>
        sbx.process.executeCommand(
          'export BUN_INSTALL="$HOME/.bun" && export PATH="$BUN_INSTALL/bin:$PATH" && cd ~/apex && bun install',
        ),
      { branch },
    );

    // Create session and run benchmark via scripts/run-benchmarks.ts
    process.stderr.write(`[${branch}] 🔬 Creating benchmark session...\n`);
    await retryWithBackoff(() => sbx.process.createSession("benchmark"), {
      branch,
    });

    process.stderr.write(`[${branch}] 📊 Running benchmark...\n`);
    const { cmdId } = await sandbox.process.executeSessionCommand("benchmark", {
      command: [
        `export BUN_INSTALL="$HOME/.bun"`,
        `export PATH="$BUN_INSTALL/bin:$PATH"`,
        `export ANTHROPIC_API_KEY="${process.env.ANTHROPIC_API_KEY}"`,
        `export OPENROUTER_API_KEY="${process.env.OPENROUTER_API_KEY}"`,
        `cd ~/apex && bun run scripts/run-benchmarks.ts --repo-dir ~/repo --branches ${branch} --model ${model} --mode local`,
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
        const lines = chunk.split("\n");
        lines.forEach((line) => {
          if (line) process.stdout.write(`[${branch}] ${line}\n`);
        });
      },
      (chunk: string) => {
        const lines = chunk.split("\n");
        lines.forEach((line) => {
          if (line) process.stderr.write(`[${branch}] ${line}\n`);
        });
      },
    );

    const command = await sandbox.process.getSessionCommand("benchmark", cmdId);
    const exitCode = command?.exitCode;

    process.stderr.write(
      `[${branch}] ✅ Benchmark completed with exit code: ${exitCode}\n`,
    );

    if (exitCode !== 0) {
      throw new Error(`Benchmark failed with exit code ${exitCode}`);
    }

    // Download results
    const results = await downloadResults(sandbox, branch);

    const duration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
    process.stderr.write(`[${branch}] ✅ Completed in ${duration}m\n`);

    return results;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // Truncate very long error messages (e.g., HTML error pages)
    const truncatedMessage =
      message.length > 500
        ? message.substring(0, 500) + "... (truncated)"
        : message;
    const duration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
    process.stderr.write(
      `[${branch}] ❌ Failed after ${duration}m: ${truncatedMessage}\n`,
    );

    writeErrorLog(error, `DaytonaWrapper:runBranch:${branch}`);
    return {
      repoPath: repoUrl,
      branch,
      targetUrl: "",
      sessionId: "",
      sessionPath: "",
      expectedResults: [],
      actualResults: [],
      comparison: { error: message },
      timestamp: new Date().toISOString(),
      tokensIn: 0,
      tokensOut: 0,
      totalTokens: 0,
      flagDetected: false,
      flagValue: null,
      findingsCount: 0,
    };
  } finally {
    if (sandbox) {
      try {
        process.stderr.write(`[${branch}] 🧹 Cleaning up sandbox...\n`);

        let attempts = 0;
        while (attempts < 10) {
          await sandbox.refreshData();
          if (sandbox.state !== "stopping" && sandbox.state !== "starting") {
            break;
          }
          await new Promise((resolve) => setTimeout(resolve, 3000));
          attempts++;
        }

        await sandbox.delete();
        process.stderr.write(`[${branch}] ✅ Cleanup complete\n`);
      } catch (cleanupError) {
        writeErrorLog(cleanupError, `DaytonaWrapper:cleanup:${branch}`);
      }
    }
  }
}

/**
 * Run benchmark in Daytona cloud sandbox (parallel execution)
 */
export async function runBenchmarkInDaytona(
  options: DaytonaBenchmarkOptions,
): Promise<BenchmarkResults[]> {
  const apiKey = options.apiKey || process.env.DAYTONA_API_KEY;
  const orgId = options.orgId || process.env.DAYTONA_ORG_ID;
  const anthropicKey = options.anthropicKey || process.env.ANTHROPIC_API_KEY;
  const openrouterKey = options.openrouterKey || process.env.OPENROUTER_API_KEY;

  if (!apiKey) {
    throw new Error(
      "DAYTONA_API_KEY is required. Set it via environment variable or pass it in options.",
    );
  }

  if (!anthropicKey && !openrouterKey) {
    throw new Error(
      "At least one AI API key is required (ANTHROPIC_API_KEY or OPENROUTER_API_KEY)",
    );
  }

  const branches = options.branches || ["main"];
  const maxParallel = options.maxParallel || 4;
  const startTime = Date.now();

  process.stderr.write("🚀 Starting parallel benchmark execution\n");
  process.stderr.write(`   Repository: ${options.repoUrl}\n`);
  process.stderr.write(`   Branches: ${branches.join(", ")}\n`);
  process.stderr.write(`   Model: ${options.model}\n`);
  process.stderr.write(`   Max Parallel: ${maxParallel}\n`);
  process.stderr.write("\n");

  // Initialize SDK
  const daytona = new Daytona({
    apiKey,
    apiUrl: "https://app.daytona.io/api",
    ...(orgId ? { organizationId: orgId } : {}),
  } as ConstructorParameters<typeof Daytona>[0]);

  // Run branches with controlled concurrency
  const limit = pLimit(maxParallel);
  const results = await Promise.all(
    branches.map((branch) =>
      limit(() =>
        runSingleBranchBenchmark(daytona, {
          repoUrl: options.repoUrl,
          branch,
          model: options.model,
          anthropicKey,
          openrouterKey,
        }),
      ),
    ),
  );

  const totalDuration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
  const successful = results.filter((r) => !r.comparison.error).length;
  const failed = results.filter((r) => r.comparison.error).length;
  const flagsCaptured = results.filter((r) => r.flagDetected).length;
  const totalFindings = results.reduce(
    (sum, r) => sum + (r.findingsCount ?? 0),
    0,
  );
  const totalTokens = results.reduce((sum, r) => sum + (r.totalTokens ?? 0), 0);

  process.stderr.write("\n" + "=".repeat(80) + "\n");
  process.stderr.write("📊 PARALLEL BENCHMARK SUMMARY\n");
  process.stderr.write("=".repeat(80) + "\n");
  process.stderr.write(`Total Duration: ${totalDuration}m\n`);
  process.stderr.write(`Successful: ${successful}/${branches.length}\n`);
  process.stderr.write(`Failed: ${failed}/${branches.length}\n`);
  process.stderr.write(
    `Flags Captured: ${flagsCaptured}/${branches.length} (${((flagsCaptured / branches.length) * 100).toFixed(1)}%)\n`,
  );
  process.stderr.write(`Total Findings: ${totalFindings}\n`);
  process.stderr.write(`Total Tokens: ${totalTokens.toLocaleString()}\n`);
  process.stderr.write("\n");

  // Generate summary report
  await generateSummaryReport(
    results,
    options.repoUrl,
    options.model,
    totalDuration,
  );

  return results;
}

/**
 * Install Bun runtime
 */
async function installBun(sandbox: Sandbox, branch?: string): Promise<void> {
  const prefix = branch ? `[${branch}] ` : "";
  process.stderr.write(`${prefix}📦 Installing Bun...\n`);

  await sandbox.process.executeCommand(
    "curl -fsSL https://bun.sh/install | bash",
  );

  // Add bun to PATH in bashrc
  await sandbox.process.executeCommand(
    "echo 'export BUN_INSTALL=\"$HOME/.bun\"' >> ~/.bashrc && echo 'export PATH=\"$BUN_INSTALL/bin:$PATH\"' >> ~/.bashrc",
  );

  // Verify bun is accessible by running with explicit PATH
  const verifyResult = await sandbox.process.executeCommand(
    'export BUN_INSTALL="$HOME/.bun" && export PATH="$BUN_INSTALL/bin:$PATH" && bun --version',
  );

  if (!verifyResult.result || verifyResult.exitCode !== 0) {
    throw new Error("Bun installation verification failed");
  }

  process.stderr.write(
    `${prefix}✅ Bun installed: v${verifyResult.result.trim()}\n`,
  );
}

/**
 * Install Apex using bun
 */
async function installApex(sandbox: Sandbox, branch?: string): Promise<void> {
  const prefix = branch ? `[${branch}] ` : "";
  process.stderr.write(`${prefix}📦 Installing Apex globally via bun...\n`);

  try {
    // Install using bun (ensures bun PATH is working)
    const installResult = await sandbox.process.executeCommand(
      'export BUN_INSTALL="$HOME/.bun" && export PATH="$BUN_INSTALL/bin:$PATH" && bun install -g @pensar/apex@canary',
    );

    if (installResult.exitCode !== 0) {
      throw new Error(
        `Bun install failed with exit code ${installResult.exitCode}`,
      );
    }

    // Verify installation
    const verifyResult = await sandbox.process.executeCommand(
      'export BUN_INSTALL="$HOME/.bun" && export PATH="$BUN_INSTALL/bin:$PATH" && which pensar',
    );
    const installedPath = verifyResult.result?.trim();

    if (!installedPath) {
      throw new Error(
        "Apex installation verification failed - pensar command not found",
      );
    }

    process.stderr.write(`${prefix}✅ Apex installed at: ${installedPath}\n`);
  } catch (error) {
    throw new Error(
      `Failed to install Apex: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
}

/**
 * Install Docker in the Daytona sandbox.
 * Required for benchmark runner's --mode local which uses docker compose.
 */
async function installDocker(sandbox: Sandbox, branch?: string): Promise<void> {
  const prefix = branch ? `[${branch}] ` : "";
  process.stderr.write(`${prefix}🐳 Installing Docker...\n`);

  // Fix broken yarn repository that blocks apt-get update
  // The Docker install script runs apt-get update which fails on the yarn repo
  process.stderr.write(`${prefix}Fixing apt repositories...\n`);
  await sandbox.process.executeCommand(
    "(sudo rm -f /etc/apt/sources.list.d/yarn.list || rm -f /etc/apt/sources.list.d/yarn.list) 2>/dev/null || true",
  );

  // Install Docker using official script
  const installResult = await retryWithBackoff(
    () =>
      sandbox.process.executeCommand("curl -fsSL https://get.docker.com | sh"),
    { branch, maxRetries: 2 },
  );

  // Log installation output for debugging (don't hide errors)
  if (installResult.result) {
    const output = installResult.result.trim();
    const preview =
      output.length > 500 ? output.substring(0, 500) + "..." : output;
    process.stderr.write(`${prefix}Docker install output: ${preview}\n`);
  }

  // Check installation exit code
  if (installResult.exitCode !== 0) {
    writeErrorLog(
      `Docker installation failed with exit code ${installResult.exitCode}`,
      "DaytonaWrapper:installDocker",
    );
    throw new Error(
      `Docker installation script failed with exit code ${installResult.exitCode}`,
    );
  }

  // Verify Docker binary was installed
  const whichResult = await sandbox.process.executeCommand(
    'export PATH="/usr/local/bin:/usr/bin:$PATH" && which docker',
  );

  if (whichResult.exitCode !== 0 || !whichResult.result?.trim()) {
    // Debug: check common locations
    const checkLocations = await sandbox.process.executeCommand(
      'ls -la /usr/bin/docker /usr/local/bin/docker 2>&1 || echo "Docker not in standard locations"',
    );
    writeErrorLog(
      `Docker binary check: ${checkLocations.result}`,
      "DaytonaWrapper:installDocker",
    );

    const pathCheck = await sandbox.process.executeCommand("echo $PATH");
    writeErrorLog(
      `Current PATH: ${pathCheck.result}`,
      "DaytonaWrapper:installDocker",
    );

    throw new Error("Docker binary not found after installation");
  }

  const dockerPath = whichResult.result.trim();
  process.stderr.write(`${prefix}✅ Docker installed at: ${dockerPath}\n`);

  process.stderr.write(`${prefix}Starting Docker daemon...\n`);

  // Use nohup to properly detach the daemon - try with sudo first, fall back to direct
  const daemonStart = await sandbox.process.executeCommand(
    'export PATH="/usr/local/bin:/usr/bin:$PATH" && nohup dockerd >/tmp/dockerd.log 2>&1 </dev/null &',
  );

  // Check if the command itself failed (not the daemon startup)
  if (daemonStart.exitCode !== 0 && daemonStart.result) {
    writeErrorLog(
      `Failed to start daemon command: ${daemonStart.result.substring(0, 200)}`,
      "DaytonaWrapper:installDocker",
    );
    throw new Error("Failed to execute dockerd command");
  }

  // Give daemon a moment to start before checking
  process.stderr.write(`${prefix}Waiting for daemon to initialize...\n`);
  await new Promise((resolve) => setTimeout(resolve, 5000));

  // Add current user to docker group for socket access
  process.stderr.write(`${prefix}Configuring Docker permissions...\n`);
  await sandbox.process.executeCommand(
    "(sudo usermod -aG docker $(whoami) || usermod -aG docker $(whoami)) 2>/dev/null || true",
  );

  // Set socket permissions to allow group access
  await sandbox.process.executeCommand(
    "chmod 666 /var/run/docker.sock 2>/dev/null || sleep 2 && chmod 666 /var/run/docker.sock 2>/dev/null || true",
  );

  // Wait for Docker daemon to be ready (up to 60 seconds with retries)
  process.stderr.write(
    `${prefix}⏳ Waiting for Docker daemon to be ready...\n`,
  );

  let attempts = 0;
  const maxAttempts = 60;
  let lastError = "";

  while (attempts < maxAttempts) {
    const checkResult = await sandbox.process.executeCommand(
      'export PATH="/usr/local/bin:/usr/bin:$PATH" && docker info 2>&1',
    );

    if (checkResult.exitCode === 0) {
      process.stderr.write(
        `${prefix}✅ Docker daemon ready after ${attempts} seconds\n`,
      );
      break;
    }

    lastError = checkResult.result || "Unknown error";
    attempts++;

    // Show progress every 10 seconds
    if (attempts % 10 === 0) {
      process.stderr.write(
        `${prefix}Still waiting... (${attempts}s elapsed)\n`,
      );
    }

    await new Promise((resolve) => setTimeout(resolve, 1000));
  }

  if (attempts >= maxAttempts) {
    // Log daemon output for debugging
    const logResult = await sandbox.process.executeCommand(
      "cat /tmp/dockerd.log 2>&1 || echo 'No log file'",
    );
    writeErrorLog(
      `Docker daemon logs:\n${logResult.result}`,
      "DaytonaWrapper:installDocker",
    );
    writeErrorLog(
      `Last docker info error:\n${lastError}`,
      "DaytonaWrapper:installDocker",
    );
    throw new Error(
      `Docker daemon failed to start within ${maxAttempts} seconds`,
    );
  }

  // Verify docker compose is available
  const composeCheck = await sandbox.process.executeCommand(
    'export PATH="/usr/local/bin:/usr/bin:$PATH" && docker compose version',
  );

  if (composeCheck.exitCode !== 0) {
    throw new Error(
      `docker compose not available: ${composeCheck.result ?? "unknown error"}`,
    );
  }

  process.stderr.write(`${prefix}✅ Docker daemon running, compose ready\n`);
}

/**
 * Clone repository using Daytona's git API
 */
async function cloneRepo(
  sandbox: Sandbox,
  repoUrl: string,
  branch: string,
): Promise<void> {
  const prefix = `[${branch}] `;
  process.stderr.write(
    `${prefix}📦 Cloning repository: ${repoUrl} (${branch})...\n`,
  );

  // Use Daytona's git.clone() - automatically clones and checks out branch
  await retryWithBackoff(() => sandbox.git.clone(repoUrl, "repo", branch), {
    branch,
  });

  process.stderr.write(`${prefix}✅ Repository cloned to ~/repo\n`);
}

/**
 * Download pentest results from sandbox.
 * The `pensar pentest` CLI writes session data to ~/.pensar/sessions/.
 * We find the most recent session directory and download it.
 */
async function downloadResults(
  sandbox: Sandbox,
  branch: string,
): Promise<BenchmarkResults> {
  const prefix = `[${branch}] `;
  process.stderr.write(`${prefix}⬇️  Downloading results...\n`);

  // Get user home directory
  const userHome = await sandbox.getUserHomeDir();
  if (!userHome) {
    throw new Error("Failed to get user home directory");
  }

  const sessionsPath = path.join(userHome, ".pensar", "sessions");

  // List all session directories
  const files = (await retryWithBackoff(
    () => sandbox.fs.listFiles(sessionsPath),
    {
      branch,
    },
  )) as unknown as Array<{ name: string; isDirectory: boolean }>;
  process.stderr.write(`${prefix}Found ${files.length} session directories\n`);

  if (files.length === 0) {
    throw new Error(`No sessions found for branch ${branch}`);
  }

  // Get the most recent session (last in array)
  const sessionDir = files[files.length - 1]!.name;

  process.stderr.write(`${prefix}Downloading session: ${sessionDir}\n`);

  // Download all files in the session directory recursively
  const sessionPath = path.join(sessionsPath, sessionDir);
  const localSessionPath = path.join(
    process.cwd(),
    ".pensar",
    "sessions",
    sessionDir,
  );

  // Download the entire session directory recursively
  await downloadDirectoryRecursive(
    sandbox,
    sessionPath,
    localSessionPath,
    branch,
  );

  // Read session.json if available for structured results
  const sessionJsonPath = path.join(localSessionPath, "session.json");
  let sessionData: Record<string, unknown> = {};
  if (existsSync(sessionJsonPath)) {
    sessionData = JSON.parse(readFileSync(sessionJsonPath, "utf-8"));
  }

  // Extract token usage from session
  const tokensIn = (sessionData.tokensIn as number) ?? 0;
  const tokensOut = (sessionData.tokensOut as number) ?? 0;
  const totalTokens = tokensIn + tokensOut;

  // Count findings
  const findingsDir = path.join(localSessionPath, "findings");
  let findingsCount = 0;
  if (existsSync(findingsDir)) {
    try {
      const findingFiles = await import("fs/promises").then((fs) =>
        fs.readdir(findingsDir),
      );
      findingsCount = findingFiles.filter((f) => f.endsWith(".json")).length;
    } catch {
      // Findings directory exists but couldn't read it
      findingsCount = 0;
    }
  }

  // Detect flag in artifacts (read expected flag from benchmark.json)
  let flagDetected = false;
  let flagValue: string | null = null;
  let expectedFlag: string | null = null;

  try {
    // Read benchmark.json from the repo to get expected flag
    const benchmarkJsonResult = await sandbox.process.executeCommand(
      "cat ~/repo/src/benchmark.json",
    );
    if (
      benchmarkJsonResult.exitCode === 0 &&
      benchmarkJsonResult.result?.trim()
    ) {
      const benchmarkData = JSON.parse(benchmarkJsonResult.result);
      expectedFlag = benchmarkData.win_condition?.flag_pattern ?? null;

      if (expectedFlag) {
        process.stderr.write(
          `${prefix}🔎 Searching for flag: ${expectedFlag}\n`,
        );
        const { detectFlagInArtifacts } = await import("../flag-detector.js");
        const flagResult = await detectFlagInArtifacts(
          localSessionPath,
          expectedFlag,
          branch,
        );
        flagDetected = flagResult.detected;
        flagValue = flagResult.flagValue;

        if (flagDetected) {
          process.stderr.write(
            `${prefix}✅ Flag captured! Found in: ${flagResult.foundIn.join(", ")}\n`,
          );
        } else {
          process.stderr.write(`${prefix}❌ Flag not found\n`);
        }
      }
    }
  } catch (error) {
    writeErrorLog(error, `DaytonaWrapper:detectFlag:${branch}`);
  }

  process.stderr.write(
    `${prefix}✅ Results downloaded to ${localSessionPath}\n`,
  );
  process.stderr.write(
    `${prefix}📊 Tokens: ${totalTokens.toLocaleString()} (in: ${tokensIn.toLocaleString()}, out: ${tokensOut.toLocaleString()})\n`,
  );
  process.stderr.write(`${prefix}📝 Findings: ${findingsCount}\n`);
  process.stderr.write(`${prefix}🚩 Flag: ${flagDetected ? "✓" : "✗"}\n`);

  return {
    repoPath: "",
    branch,
    targetUrl: (sessionData.target as string) ?? "",
    sessionId: sessionDir,
    sessionPath: localSessionPath,
    expectedResults: [],
    actualResults: [],
    comparison: {},
    timestamp: new Date().toISOString(),
    tokensIn,
    tokensOut,
    totalTokens,
    flagDetected,
    flagValue,
    findingsCount,
  };
}

/**
 * Recursively download a directory and all its contents
 */
async function downloadDirectoryRecursive(
  sandbox: Sandbox,
  remotePath: string,
  localPath: string,
  branch?: string,
): Promise<void> {
  const prefix = branch ? `[${branch}] ` : "";
  // Create local directory
  mkdirSync(localPath, { recursive: true });

  // List files in remote directory
  const files = (await retryWithBackoff(
    () => sandbox.fs.listFiles(remotePath),
    {
      branch,
    },
  )) as unknown as Array<{ name: string; isDirectory: boolean }>;

  for (const file of files) {
    const remoteFilePath = path.join(remotePath, file.name);
    const localFilePath = path.join(localPath, file.name);

    try {
      if (file.isDirectory) {
        // Recursively download subdirectory
        process.stderr.write(
          `${prefix}  📁 Downloading directory: ${file.name}\n`,
        );
        await downloadDirectoryRecursive(
          sandbox,
          remoteFilePath,
          localFilePath,
          branch,
        );
      } else {
        process.stderr.write(`${prefix}  📄 Downloading file: ${file.name}\n`);
        await retryWithBackoff(
          () => sandbox.fs.downloadFile(remoteFilePath, localFilePath),
          {
            branch,
          },
        );
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      if (
        errorMessage?.includes("file not found") ||
        errorMessage?.includes("invalid")
      ) {
        process.stderr.write(
          `${prefix}  📁 Retrying ${file.name} as directory...\n`,
        );
        try {
          await downloadDirectoryRecursive(
            sandbox,
            remoteFilePath,
            localFilePath,
            branch,
          );
        } catch (retryError) {
          writeErrorLog(retryError, `DaytonaWrapper:downloadDir:${file.name}`);
        }
      } else {
        writeErrorLog(errorMessage, `DaytonaWrapper:downloadFile:${file.name}`);
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
  duration: string,
): Promise<void> {
  const timestamp = new Date().toISOString();
  const summaryDir = path.join(
    process.cwd(),
    ".pensar",
    "sessions",
    `parallel-run-${new Date().toISOString().replace(/[:.]/g, "-")}`,
  );

  mkdirSync(summaryDir, { recursive: true });

  // Compute aggregate metrics
  const totalTokensIn = results.reduce((sum, r) => sum + (r.tokensIn ?? 0), 0);
  const totalTokensOut = results.reduce(
    (sum, r) => sum + (r.tokensOut ?? 0),
    0,
  );
  const totalTokens = totalTokensIn + totalTokensOut;
  const flagsCaptured = results.filter((r) => r.flagDetected).length;
  const totalFindings = results.reduce(
    (sum, r) => sum + (r.findingsCount ?? 0),
    0,
  );

  // Generate JSON summary
  const jsonSummary = {
    timestamp,
    repoUrl,
    model,
    totalBranches: results.length,
    successful: results.filter((r) => !r.comparison.error).length,
    failed: results.filter((r) => r.comparison.error).length,
    duration,
    flagsCaptured,
    flagCaptureRate: results.length > 0 ? flagsCaptured / results.length : 0,
    totalFindings,
    avgFindingsPerBenchmark:
      results.length > 0 ? totalFindings / results.length : 0,
    tokenUsage: {
      totalTokensIn,
      totalTokensOut,
      totalTokens,
      avgTokensPerBenchmark:
        results.length > 0 ? totalTokens / results.length : 0,
    },
    circuitBreakerState: daytonaCircuitBreaker.getState(),
    branches: results.map((r) => ({
      branch: r.branch,
      status: r.comparison.error ? "failed" : "success",
      error: r.comparison.error,
      sessionId: r.sessionId,
      sessionPath: r.sessionPath,
      flagDetected: r.flagDetected ?? false,
      flagValue: r.flagValue ?? null,
      findingsCount: r.findingsCount ?? 0,
      tokensIn: r.tokensIn ?? 0,
      tokensOut: r.tokensOut ?? 0,
      totalTokens: r.totalTokens ?? 0,
    })),
  };

  const jsonPath = path.join(summaryDir, "summary.json");
  writeFileSync(jsonPath, JSON.stringify(jsonSummary, null, 2));

  // Generate Markdown summary
  const cbState = daytonaCircuitBreaker.getState();
  const cbIcon =
    cbState.state === "CLOSED" ? "🟢" : cbState.state === "OPEN" ? "🔴" : "🟡";

  const markdown = [
    "# Parallel Benchmark Results",
    `**Repository**: ${repoUrl}`,
    `**Model**: ${model}`,
    `**Timestamp**: ${new Date(timestamp).toLocaleString()}`,
    `**Duration**: ${duration}m`,
    "",
    "## Summary",
    `- **Successful**: ${jsonSummary.successful}/${jsonSummary.totalBranches}`,
    `- **Failed**: ${jsonSummary.failed}/${jsonSummary.totalBranches}`,
    `- **Flags Captured**: ${jsonSummary.flagsCaptured}/${jsonSummary.totalBranches} (${(jsonSummary.flagCaptureRate * 100).toFixed(1)}%)`,
    `- **Total Findings**: ${jsonSummary.totalFindings} (avg: ${jsonSummary.avgFindingsPerBenchmark.toFixed(1)} per benchmark)`,
    `- **Circuit Breaker**: ${cbIcon} ${cbState.state} (failures: ${cbState.failures}, successes: ${cbState.successes})`,
    "",
    "## Token Usage",
    `- **Total Tokens**: ${jsonSummary.tokenUsage.totalTokens.toLocaleString()} (in: ${jsonSummary.tokenUsage.totalTokensIn.toLocaleString()}, out: ${jsonSummary.tokenUsage.totalTokensOut.toLocaleString()})`,
    `- **Average per Benchmark**: ${Math.round(jsonSummary.tokenUsage.avgTokensPerBenchmark).toLocaleString()} tokens`,
    "",
    "## Branch Results",
    "",
  ];

  for (const branch of jsonSummary.branches) {
    const icon = branch.status === "success" ? "✅" : "❌";
    const flagIcon = branch.flagDetected ? "🚩" : "⬜";
    markdown.push(`### ${icon} ${branch.branch} ${flagIcon}`);
    markdown.push(`- **Status**: ${branch.status}`);
    if (branch.status === "success") {
      markdown.push(
        `- **Flag Captured**: ${branch.flagDetected ? "Yes" : "No"}`,
      );
      if (branch.flagDetected && branch.flagValue) {
        markdown.push(`- **Flag Value**: \`${branch.flagValue}\``);
      }
      markdown.push(`- **Findings**: ${branch.findingsCount}`);
      markdown.push(
        `- **Tokens**: ${branch.totalTokens.toLocaleString()} (in: ${branch.tokensIn.toLocaleString()}, out: ${branch.tokensOut.toLocaleString()})`,
      );
      markdown.push(`- **Session**: ${branch.sessionId}`);
      markdown.push(
        `- **Results**: [${branch.sessionPath}](${branch.sessionPath})`,
      );
    } else {
      markdown.push(`- **Error**: ${branch.error}`);
    }
    markdown.push("");
  }

  const mdPath = path.join(summaryDir, "summary.md");
  writeFileSync(mdPath, markdown.join("\n"));

  process.stderr.write(`📄 Summary reports saved to: ${summaryDir}\n`);
}
