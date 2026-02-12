import { Daytona, Image, Sandbox } from "@daytonaio/sdk";
import type { AIModel } from "../../../../ai";
import { Session } from "../../../../session";
import {
  extractFlagFromRepo,
  detectFlagInArtifacts,
  extractPACEFlags,
  detectMultipleFlagsInArtifacts,
} from "../flag-detector";
import { runStreamlinedPentest } from "../../thoroughPentestAgent/streamlined";
import type { BenchmarkResults } from "../types";
import type {
  ExecuteCommandOpts,
  ExecuteCommandResult,
  HttpRequestOpts,
  HttpRequestResult,
} from "../../tools";
import {
  writeFileSync,
  readFileSync,
  existsSync,
  readdirSync,
  statSync,
  mkdirSync,
} from "fs";
import path from "path";
import pLimit from "p-limit";
import ignore, { type Ignore } from "ignore";
import { parseDockerComposePort } from "../docker-utils";

export interface DaytonaBenchmarkOptions {
  benchmarkPath: string; // Local path to benchmark directory (e.g., /path/to/repo/benchmarks/XBOW-001-24)
  benchmarkName: string; // Benchmark name (e.g., XBOW-001-24)
  model: AIModel;
  apiKey?: string;
  orgId?: string;
  anthropicKey?: string;
  openrouterKey?: string;
  prefix?: string; // Prefix for session names and output directories
  dockerUsername?: string; // Docker Hub username for authenticated pulls
  dockerPassword?: string; // Docker Hub password/token for authenticated pulls
  benchmarkType?: "xben" | "pace" | "target"; // Benchmark type: xben (default), pace (PACEbench), or target (custom)
  vulnsMode?: boolean; // If true, use vulnerability detection mode instead of flag detection
  // Sandbox resource configuration (per Daytona docs: min 2 vCPU, 4GiB for DinD)
  sandboxCpu?: number; // vCPUs for sandbox (default: 4)
  sandboxMemory?: number; // Memory in GiB for sandbox (default: 8)
  sandboxDisk?: number; // Disk in GiB for sandbox (default: 4)
}

export interface MultipleBenchmarkOptions extends Omit<
  DaytonaBenchmarkOptions,
  "benchmarkPath" | "benchmarkName"
> {
  repoPath: string; // Local path to repo root
  benchmarks?: string[]; // Benchmark names (e.g., ["XBOW-001-24", "XBOW-002-24"])
  maxParallel?: number;
}

interface PocRunResult {
  pocFile: string;
  pocName: string;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  duration: number;
  success: boolean;
  error?: string;
}

/**
 * Load .gitignore from a directory and return an Ignore instance
 */
function loadGitignore(baseDir: string): Ignore {
  const ig = ignore();

  // Always ignore .git directory
  ig.add(".git");

  // Load .gitignore if it exists
  const gitignorePath = path.join(baseDir, ".gitignore");
  if (existsSync(gitignorePath)) {
    const gitignoreContent = readFileSync(gitignorePath, "utf-8");
    ig.add(gitignoreContent);
  }

  return ig;
}

/**
 * Recursively collect all files from a directory, respecting .gitignore
 */
function collectFilesRecursive(
  dirPath: string,
  baseDir: string,
  files: Array<{ source: Buffer; destination: string }> = [],
  ig?: Ignore,
): Array<{ source: Buffer; destination: string }> {
  const entries = readdirSync(dirPath);

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry);
    // Calculate relative path from base directory (use forward slashes for ignore matching)
    const relativePath = path.relative(baseDir, fullPath).replace(/\\/g, "/");

    // Check if this path should be ignored
    if (ig && ig.ignores(relativePath)) {
      continue;
    }

    const stat = statSync(fullPath);

    if (stat.isDirectory()) {
      // Recursively collect files from subdirectory
      collectFilesRecursive(fullPath, baseDir, files, ig);
    } else if (stat.isFile()) {
      const contents = readFileSync(fullPath);
      files.push({
        source: contents,
        destination: relativePath,
      });
    }
  }

  return files;
}

/**
 * Wait for a service to be ready by polling the target URL
 * Returns true if the service became ready, false if timeout was reached
 */
async function waitForServiceReady(
  sandbox: Sandbox,
  targetUrl: string,
  benchmarkName: string,
  maxWaitMs: number = 120000, // 2 minutes default
  pollIntervalMs: number = 3000, // 3 seconds between polls
): Promise<boolean> {
  const startTime = Date.now();
  let attempt = 0;

  console.log(
    `[${benchmarkName}] ⏳ Waiting for service to be ready at ${targetUrl}...`,
  );

  while (Date.now() - startTime < maxWaitMs) {
    attempt++;
    try {
      // Use curl with a short timeout to check if the service responds
      const result = await sandbox.process.executeCommand(
        `curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 ${targetUrl} 2>/dev/null || echo "000"`,
        undefined,
        undefined,
        15000,
      );

      const httpCode = parseInt(result.result?.trim() || "0", 10);

      // Consider any HTTP response (even 4xx/5xx) as "service is up"
      // A 000 means connection refused/timeout
      if (httpCode > 0) {
        const elapsed = Math.round((Date.now() - startTime) / 1000);
        console.log(
          `[${benchmarkName}] ✅ Service ready (HTTP ${httpCode}) after ${elapsed}s`,
        );
        return true;
      }

      console.log(
        `[${benchmarkName}] ⏳ Attempt ${attempt}: Service not ready yet (HTTP ${httpCode}), retrying...`,
      );
    } catch (_error) {
      console.log(
        `[${benchmarkName}] ⏳ Attempt ${attempt}: Connection failed, retrying...`,
      );
    }

    // Wait before next poll
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }

  const elapsed = Math.round((Date.now() - startTime) / 1000);
  console.log(
    `[${benchmarkName}] ⚠️ Service not ready after ${elapsed}s (${attempt} attempts)`,
  );
  return false;
}

/**
 * Re-run all POC scripts in a session via Daytona sandbox and save their outputs
 */
async function rerunAllPocsInSandbox(
  sandbox: Sandbox,
  sessionPath: string,
  remoteBenchmarkPath: string,
  benchmarkName: string,
  targetUrl: string,
): Promise<{
  total: number;
  passed: number;
  failed: number;
  results: PocRunResult[];
}> {
  const pocsDir = path.join(sessionPath, "pocs");
  const logsDir = path.join(pocsDir, "logs");

  // Check if pocs directory exists locally
  if (!existsSync(pocsDir)) {
    console.log(
      `[${benchmarkName}] 📁 No POCs directory found, skipping POC re-run`,
    );
    return { total: 0, passed: 0, failed: 0, results: [] };
  }

  // Create logs directory
  mkdirSync(logsDir, { recursive: true });

  // Find all POC files
  const files = readdirSync(pocsDir);
  const pocFiles = files.filter(
    (f) => f.endsWith(".sh") || f.endsWith(".html"),
  );

  if (pocFiles.length === 0) {
    console.log(`[${benchmarkName}] 📁 No POC files found in ${pocsDir}`);
    return { total: 0, passed: 0, failed: 0, results: [] };
  }

  console.log(
    `[${benchmarkName}] 🔄 Re-running ${pocFiles.length} POC(s) in sandbox...`,
  );

  const results: PocRunResult[] = [];
  let passed = 0;
  let failed = 0;

  for (const pocFile of pocFiles) {
    const pocPath = path.join(pocsDir, pocFile);
    const pocName = pocFile.replace(/\.(sh|html)$/, "");
    const logFileName = `${pocFile}.log`;
    const logPath = path.join(logsDir, logFileName);

    if (pocFile.endsWith(".html")) {
      // HTML POCs can't be executed automatically
      const result: PocRunResult = {
        pocFile,
        pocName,
        exitCode: null,
        stdout: "",
        stderr: "",
        duration: 0,
        success: false,
        error: "HTML POCs cannot be executed automatically (requires browser)",
      };
      results.push(result);

      const logContent = `POC: ${pocFile}
Type: HTML
Status: SKIPPED (HTML POCs require manual browser execution)
Timestamp: ${new Date().toISOString()}
`;
      writeFileSync(logPath, logContent);
      console.log(`[${benchmarkName}]   ⏭️  ${pocFile} (HTML - skipped)`);
      continue;
    }

    // Read the POC file content and upload to sandbox
    const pocContent = readFileSync(pocPath, "utf-8");
    const remotePocPath = `/tmp/poc-${pocName}.sh`;

    // Upload POC script to sandbox
    await sandbox.fs.uploadFiles([
      {
        source: Buffer.from(pocContent),
        destination: remotePocPath,
      },
    ]);

    // Execute bash POC in sandbox
    const startTime = Date.now();
    let result: PocRunResult;

    try {
      // Make script executable and run it
      const execResult = await sandbox.process.executeCommand(
        `chmod +x "${remotePocPath}" && TARGET="${targetUrl}" bash "${remotePocPath}"`,
        undefined,
        undefined,
        120000, // 2 minute timeout
      );

      const duration = Date.now() - startTime;

      if (execResult.exitCode === 0) {
        result = {
          pocFile,
          pocName,
          exitCode: 0,
          stdout: execResult.result || "",
          stderr: "",
          duration,
          success: true,
        };
        passed++;
        console.log(
          `[${benchmarkName}]   ✅ ${pocFile} (${(duration / 1000).toFixed(1)}s)`,
        );
      } else {
        result = {
          pocFile,
          pocName,
          exitCode: execResult.exitCode ?? 1,
          stdout: execResult.result || "",
          stderr: execResult.result || "",
          duration,
          success: false,
          error: `Exit code: ${execResult.exitCode}`,
        };
        failed++;
        console.log(
          `[${benchmarkName}]   ❌ ${pocFile} (exit code: ${result.exitCode})`,
        );
      }
    } catch (error) {
      const duration = Date.now() - startTime;
      const message = error instanceof Error ? error.message : String(error);
      result = {
        pocFile,
        pocName,
        exitCode: 1,
        stdout: "",
        stderr: message,
        duration,
        success: false,
        error: message,
      };
      failed++;
      console.log(`[${benchmarkName}]   ❌ ${pocFile} (error: ${message})`);
    }

    results.push(result);

    // Save log file
    const logContent = `POC: ${pocFile}
Type: Bash Script
Exit Code: ${result.exitCode}
Success: ${result.success}
Duration: ${result.duration}ms
Timestamp: ${new Date().toISOString()}
Target: ${targetUrl}
Execution: Sandbox

${"=".repeat(60)}
STDOUT:
${"=".repeat(60)}
${result.stdout || "(empty)"}

${"=".repeat(60)}
STDERR:
${"=".repeat(60)}
${result.stderr || "(empty)"}

${
  result.error
    ? `\n${"=".repeat(60)}\nERROR:\n${"=".repeat(60)}\n${result.error}\n`
    : ""
}
`;
    writeFileSync(logPath, logContent);
  }

  // Save summary
  const summaryPath = path.join(logsDir, "poc-run-summary.json");
  const summary = {
    timestamp: new Date().toISOString(),
    benchmarkName,
    targetUrl,
    executionMode: "sandbox",
    total: pocFiles.length,
    passed,
    failed,
    skipped: pocFiles.filter((f) => f.endsWith(".html")).length,
    results: results.map((r) => ({
      pocFile: r.pocFile,
      pocName: r.pocName,
      exitCode: r.exitCode,
      success: r.success,
      duration: r.duration,
      error: r.error,
    })),
  };
  writeFileSync(summaryPath, JSON.stringify(summary, null, 2));

  console.log(
    `[${benchmarkName}] 📊 POC Re-run Summary: ${passed} passed, ${failed} failed, ${summary.skipped} skipped`,
  );
  console.log(`[${benchmarkName}] 📁 POC logs saved to: ${logsDir}`);

  return { total: pocFiles.length, passed, failed, results };
}

/**
 * Run a single benchmark with Daytona sandbox using Docker-in-Docker.
 *
 * Architecture:
 * - Target app runs inside Daytona sandbox (Docker-in-Docker)
 * - Agent runs locally on host machine
 * - Agent commands/HTTP requests are proxied to sandbox via tool overrides
 * - Docker commands are BLOCKED to prevent cheating (accessing containers directly)
 * - Target URL is localhost (inside sandbox) for realistic testing
 */
export async function runBenchmarkWithDaytona(
  options: DaytonaBenchmarkOptions,
): Promise<BenchmarkResults> {
  const { benchmarkPath, benchmarkName, model, prefix } = options;
  const apiKey = options.apiKey || process.env.DAYTONA_API_KEY;
  const orgId = options.orgId || process.env.DAYTONA_ORG_ID;
  const startTime = Date.now();

  if (!apiKey) {
    throw new Error("DAYTONA_API_KEY is required");
  }

  console.log(`\n${"=".repeat(80)}`);
  console.log(`[${benchmarkName}] STARTING DAYTONA BENCHMARK`);
  console.log(`${"=".repeat(80)}`);
  console.log(`[${benchmarkName}] Path: ${benchmarkPath}`);
  console.log(`[${benchmarkName}] Model: ${model}`);
  console.log(`${"=".repeat(80)}\n`);

  // Parse docker-compose port before creating sandbox
  console.log(
    `[${benchmarkName}] 🔍 Parsing docker-compose for web service...`,
  );
  const portInfo = parseDockerComposePort(benchmarkPath);
  console.log(
    `[${benchmarkName}] ✅ Found web service: ${portInfo.serviceName} on port ${portInfo.hostPort}${portInfo.needsPortMapping ? " (added port mapping)" : ""}`,
  );

  const daytona = new Daytona({ apiKey });

  let sandbox: Sandbox | undefined;
  let remoteBenchmarkPath = "";
  let sessionRootPath = ""; // Track session path for error logging in catch block

  try {
    // Step 1: Create sandbox with DinD support and sufficient resources
    console.log(
      `[${benchmarkName}] 🚀 Creating Daytona sandbox with Docker-in-Docker...`,
    );

    // Create image with required tools pre-installed
    // Install feroxagent for intelligent endpoint enumeration
    const dindImage = Image.base("docker:28.3.3-dind").runCommands(
      "apk add --no-cache curl make bash coreutils git jq && " +
        "cd /tmp && " +
        "curl -sL https://github.com/pensarai/feroxagent/releases/download/v0.1.1/x86_64-linux-feroxagent.tar.gz -o feroxagent.tar.gz && " +
        "tar -xzf feroxagent.tar.gz && " +
        "mv feroxagent /usr/local/bin/ && " +
        "chmod +x /usr/local/bin/feroxagent && " +
        "rm -f feroxagent.tar.gz",
    );

    // Get Docker Hub credentials from options or environment
    const dockerUsername =
      options.dockerUsername || process.env.DOCKER_USERNAME || "";
    const dockerPassword =
      options.dockerPassword || process.env.DOCKER_PASSWORD || "";

    sandbox = await daytona.create(
      {
        language: "typescript",
        envVars: {
          ANTHROPIC_API_KEY:
            options.anthropicKey || process.env.ANTHROPIC_API_KEY || "",
          OPENROUTER_API_KEY:
            options.openrouterKey || process.env.OPENROUTER_API_KEY || "",
          DOCKER_USERNAME: dockerUsername,
          DOCKER_PASSWORD: dockerPassword,
        },
        public: true,
        networkBlockAll: false,
        // Configurable resources for Docker-in-Docker (per Daytona docs: min 2 vCPU, 4GiB)
        resources: {
          cpu: options.sandboxCpu ?? 4,
          memory: options.sandboxMemory ?? 8,
          disk: options.sandboxDisk ?? 4,
        },
        image: dindImage,
      },
      { timeout: 300000 }, // 5 minute timeout for sandbox creation
    );

    const cpu = options.sandboxCpu ?? 4;
    const memory = options.sandboxMemory ?? 8;
    const disk = options.sandboxDisk ?? 4;
    console.log(
      `[${benchmarkName}] ✅ Sandbox created: ${sandbox.id} (${cpu} vCPU, ${memory}GB RAM, ${disk}GB disk)`,
    );

    // Wait for sandbox to be ready
    console.log(`[${benchmarkName}] ⏳ Waiting for sandbox to be ready...`);
    await new Promise((resolve) => setTimeout(resolve, 5000));

    // Start Docker daemon manually (DinD image entrypoint may not run in Daytona)
    console.log(`[${benchmarkName}] 🐳 Starting Docker daemon...`);

    // First check if dockerd is already running
    const psCheck = await sandbox.process.executeCommand(
      "ps aux | grep -v grep | grep dockerd || echo 'not running'",
      undefined,
      undefined,
      10000,
    );
    console.log(
      `[${benchmarkName}] 📋 Docker process check: ${psCheck.result?.trim()}`,
    );

    // Try using the DinD entrypoint script if available, or start dockerd directly
    // Use storage-driver=vfs which works without device-mapper/overlay issues in nested containers
    const startDaemonResult = await sandbox.process.executeCommand(
      `(dockerd-entrypoint.sh dockerd --storage-driver=vfs > /var/log/dockerd.log 2>&1 &) || (dockerd --storage-driver=vfs --host=unix:///var/run/docker.sock > /var/log/dockerd.log 2>&1 &)`,
      undefined,
      undefined,
      30000,
    );

    console.log(
      `[${benchmarkName}] 📋 Start daemon result: ${startDaemonResult.result?.substring(0, 200)}`,
    );

    // Wait for Docker daemon to be ready
    console.log(`[${benchmarkName}] ⏳ Waiting for Docker daemon to start...`);
    let dockerReady = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      // Wait a bit before checking
      await new Promise((resolve) => setTimeout(resolve, 2000));

      // Check if daemon socket exists and is responsive
      const dockerCheckResult = await sandbox.process.executeCommand(
        "docker version --format '{{.Server.Version}}' 2>&1",
        undefined,
        undefined,
        10000,
      );

      // If we get a version number, daemon is ready
      if (
        dockerCheckResult.exitCode === 0 &&
        dockerCheckResult.result &&
        !dockerCheckResult.result.includes("Cannot connect")
      ) {
        console.log(
          `[${benchmarkName}] ✅ Docker daemon version: ${dockerCheckResult.result.trim()}`,
        );
        dockerReady = true;
        break;
      }

      // Log progress with more details on certain attempts
      if (attempt === 0 || attempt === 5 || attempt === 10 || attempt === 20) {
        // Check daemon logs
        const logSnippet = await sandbox.process.executeCommand(
          "tail -5 /var/log/dockerd.log 2>/dev/null || echo 'no logs yet'",
          undefined,
          undefined,
          5000,
        );
        console.log(
          `[${benchmarkName}] ⏳ Docker check (attempt ${attempt + 1}/30): ${dockerCheckResult.result?.substring(0, 150)}`,
        );
        console.log(
          `[${benchmarkName}]    Daemon log: ${logSnippet.result?.substring(0, 200)}`,
        );
      } else {
        console.log(
          `[${benchmarkName}] ⏳ Docker not ready, waiting... (attempt ${attempt + 1}/30)`,
        );
      }
    }

    if (!dockerReady) {
      // Get full dockerd logs for debugging
      const logsResult = await sandbox.process.executeCommand(
        "cat /var/log/dockerd.log 2>&1 | tail -100",
        undefined,
        undefined,
        10000,
      );
      console.error(
        `[${benchmarkName}] Docker daemon logs:\n${logsResult.result}`,
      );

      // Also check dmesg for kernel issues
      const dmesgResult = await sandbox.process.executeCommand(
        "dmesg 2>&1 | tail -20 || echo 'dmesg not available'",
        undefined,
        undefined,
        10000,
      );
      console.error(`[${benchmarkName}] System logs:\n${dmesgResult.result}`);

      throw new Error(
        "Docker daemon failed to start in sandbox after 30 attempts",
      );
    }

    console.log(`[${benchmarkName}] ✅ Docker daemon is ready`);

    // Login to Docker Hub if credentials are provided
    if (dockerUsername && dockerPassword) {
      console.log(`[${benchmarkName}] 🔐 Logging in to Docker Hub...`);
      const loginResult = await sandbox.process.executeCommand(
        `echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin`,
        undefined,
        undefined,
        30000,
      );
      if (loginResult.exitCode === 0) {
        console.log(`[${benchmarkName}] ✅ Docker Hub login successful`);
      } else {
        console.log(
          `[${benchmarkName}] ⚠️  Docker Hub login failed: ${loginResult.result?.substring(0, 200)}`,
        );
        // Continue anyway - some images might be public
      }
    }

    // Check docker-compose
    console.log(`[${benchmarkName}] 📦 Checking docker-compose...`);
    const composeCheck = await sandbox.process.executeCommand(
      "docker compose version || docker-compose version",
      undefined,
      undefined,
      30000,
    );
    console.log(
      `[${benchmarkName}] ✅ Docker Compose: ${composeCheck.result?.trim()}`,
    );

    // Step 2: Upload benchmark directory to sandbox
    console.log(`[${benchmarkName}] 📦 Uploading benchmark directory...`);
    const userHome = await sandbox.getUserHomeDir();
    if (!userHome) console.info("User home directory path is empty in sandbox");
    // Use posix path for Linux sandbox
    remoteBenchmarkPath = path.posix.join(userHome ?? "", "benchmark");

    // Load .gitignore and collect all files from benchmark directory
    const ig = loadGitignore(benchmarkPath);
    const filesToUpload = collectFilesRecursive(
      benchmarkPath,
      benchmarkPath,
      [],
      ig,
    );
    console.log(
      `[${benchmarkName}] 📁 Found ${filesToUpload.length} files to upload (respecting .gitignore)`,
    );

    // Map to Daytona upload format with remote path prefix (use posix paths for Linux sandbox)
    const uploadFiles = filesToUpload.map((file) => ({
      source: file.source,
      // Convert local path separators to posix for remote paths
      destination: path.posix.join(
        remoteBenchmarkPath,
        file.destination.replace(/\\/g, "/"),
      ),
    }));

    // Upload files in batches to avoid overwhelming the API
    const BATCH_SIZE = 10;
    const batches = [];
    for (let i = 0; i < uploadFiles.length; i += BATCH_SIZE) {
      batches.push(uploadFiles.slice(i, i + BATCH_SIZE));
    }

    try {
      console.log(
        `[${benchmarkName}] 📤 Uploading ${uploadFiles.length} files in ${batches.length} batch(es)...`,
      );

      for (let i = 0; i < batches.length; i++) {
        const batch = batches[i]!;
        console.log(
          `[${benchmarkName}] 📦 Batch ${i + 1}/${batches.length}: ${batch.length} files...`,
        );
        await sandbox.fs.uploadFiles(batch, 300);

        // Small delay between batches to avoid rate limiting
        if (i < batches.length - 1) {
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
      }

      console.log(
        `[${benchmarkName}] ✅ Benchmark uploaded to ${remoteBenchmarkPath}`,
      );
    } catch (uploadError) {
      const uploadMessage =
        uploadError instanceof Error
          ? uploadError.message
          : String(uploadError);
      console.error(`[${benchmarkName}] ❌ Upload failed: ${uploadMessage}`);
      if (
        typeof uploadError === "object" &&
        uploadError !== null &&
        "response" in uploadError
      ) {
        const { response } = uploadError as {
          response?: { status?: unknown; data?: unknown };
        };
        if (response) {
          console.error(
            `[${benchmarkName}] Response status: ${response.status}`,
          );
          console.error(`[${benchmarkName}] Response data:`, response.data);
        }
      }
      throw new Error(`File upload failed: ${uploadMessage}`, {
        cause: uploadError,
      });
    }

    // Step 3: Extract flag(s) from local benchmark directory
    // For PACEbench, extract multiple flags; for XBEN, extract single flag
    console.log(`[${benchmarkName}] 🔍 Extracting flag(s) from benchmark...`);

    let expectedFlag: string | null = null;
    let expectedFlags: Array<{ name: string; value: string }> = [];

    if (options.benchmarkType === "pace") {
      // PACEbench: Extract multiple flags from flags/ directory
      expectedFlags = await extractPACEFlags(benchmarkPath, benchmarkName);
      if (expectedFlags.length > 0) {
        console.log(
          `[${benchmarkName}] ✅ Found ${expectedFlags.length} PACE flags`,
        );
        // Use the first flag for docker build (if needed)
        expectedFlag = expectedFlags[0]?.value || null;
      } else {
        console.log(`[${benchmarkName}] ⚠️  No PACE flags found in benchmark`);
      }
    } else {
      // XBEN: Extract single flag computed from benchmark name
      expectedFlag = await extractFlagFromRepo(benchmarkPath, benchmarkName);
      if (expectedFlag) {
        console.log(
          `[${benchmarkName}] ✅ FLAG found: ${expectedFlag.substring(0, 20)}...`,
        );
      } else {
        console.log(`[${benchmarkName}] ⚠️  FLAG not found in benchmark`);
      }
    }

    // Step 4: Build docker images with flag injection using make build
    console.log(
      `[${benchmarkName}] 🔨 Building docker images with make build...`,
    );

    // Clear BuildKit cache to avoid corruption issues with VFS storage driver
    console.log(`[${benchmarkName}] 🧹 Clearing BuildKit cache...`);
    await sandbox.process.executeCommand(
      "docker builder prune -af 2>/dev/null || true",
      undefined,
      undefined,
      30000,
    );

    const buildResult = await sandbox.process.executeCommand(
      `cd ${remoteBenchmarkPath} && make build`,
      undefined,
      {
        FLAG: expectedFlag || "",
      },
      300000, // 5 minute timeout for builds
    );

    if (buildResult.exitCode !== 0) {
      // Try docker compose build as fallback
      console.log(
        `[${benchmarkName}] ⚠️  make build failed, trying docker compose build...`,
      );
      const composeResult = await sandbox.process.executeCommand(
        `cd ${remoteBenchmarkPath} && docker compose build`,
        undefined,
        {
          FLAG: expectedFlag || "",
        },
        300000,
      );

      if (composeResult.exitCode !== 0) {
        throw new Error(
          `Failed to build docker images: ${composeResult.result} CODE: ${composeResult.exitCode}`,
        );
      }
    }

    console.log(`[${benchmarkName}] ✅ Docker images built`);

    // Step 5: Start docker compose
    console.log(`[${benchmarkName}] 🐳 Starting docker compose...`);
    const startDockerResult = await sandbox.process.executeCommand(
      `cd ${remoteBenchmarkPath} && docker compose up -d --wait`,
      undefined,
      undefined,
      180000, // 3 minute timeout
    );

    if (startDockerResult.exitCode !== 0) {
      throw new Error(
        `Failed to start docker compose: ${startDockerResult.result} CODE: ${startDockerResult.exitCode}`,
      );
    }

    console.log(`[${benchmarkName}] ✅ Docker compose started`);

    // Step 6: Query Docker to get the actual mapped host port
    console.log(
      `[${benchmarkName}] 🔍 Querying Docker for actual port mapping...`,
    );
    const portQueryResult = await sandbox.process.executeCommand(
      `cd ${remoteBenchmarkPath} && docker compose port ${portInfo.serviceName} ${portInfo.containerPort} 2>/dev/null | cut -d: -f2 || echo "${portInfo.hostPort}"`,
      undefined,
      undefined,
      30000,
    );

    const actualHostPort = parseInt(
      portQueryResult.result?.trim() || String(portInfo.hostPort),
      10,
    );

    // Step 7: Build target URL from actual mapped port (localhost inside sandbox)
    const targetUrl = `http://localhost:${actualHostPort}`;
    console.log(`[${benchmarkName}] 🎯 Target URL: ${targetUrl}`);

    // const preview = await sandbox.getPreviewLink(actualHostPort);
    // console.log(`[${benchmarkName}] Preview URL: ${preview.url}`);

    // Step 7.5: Wait for service to be ready before starting the agent
    const serviceReady = await waitForServiceReady(
      sandbox,
      targetUrl,
      benchmarkName,
    );
    if (!serviceReady) {
      console.log(
        `[${benchmarkName}] ⚠️ Service may not be fully ready, proceeding anyway...`,
      );
    }

    // Step 8: Create local session with benchmark guidance and scope constraints
    const sessionPrefix = prefix
      ? `${prefix}-${benchmarkName}`
      : `benchmark-${benchmarkName}`;
    const session = await Session.create({
      targets: [targetUrl],
      name: `Benchmark testing for ${benchmarkName}`,
      // objective: `Benchmark testing for ${benchmarkName}`,
      prefix: sessionPrefix,
      config: {
        outcomeGuidance: Session.BENCHMARK_OUTCOME_GUIDANCE,
        scopeConstraints: {
          allowedHosts: ["localhost"],
          allowedPorts: [actualHostPort],
          strictScope: true,
        },
        enableCvssScoring: true,
      },
    });

    console.log(`[${benchmarkName}] 📝 Local session created: ${session.id}`);
    sessionRootPath = session.rootPath; // Store for catch block error logging

    // Helper to log errors to session's logs directory
    const logError = (phase: string, error: Record<string, unknown>) => {
      try {
        const errorLogFile = path.join(
          session.rootPath,
          "logs",
          "benchmark-errors.jsonl",
        );
        const entry = {
          timestamp: new Date().toISOString(),
          benchmarkName,
          phase,
          error: error.message ?? String(error),
          stack: error.stack,
        };
        const { appendFileSync } = require("fs");
        appendFileSync(errorLogFile, JSON.stringify(entry) + "\n");
      } catch {
        // Silently fail if we can't write to log
      }
    };

    // Step 9: Create tool overrides that proxy to Daytona sandbox
    // These execute commands/requests in the sandbox but BLOCK docker commands
    // to prevent cheating by accessing Docker containers directly
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
      "/root",
      "/var/lib/docker", // Prevent direct access to container filesystems/databases
      remoteBenchmarkPath,
    ];

    const executeCommandOverride = async (
      opts: ExecuteCommandOpts,
    ): Promise<ExecuteCommandResult> => {
      const isLongRunningCommand =
        opts.command.includes("feroxagent") ||
        opts.command.includes("nuclei") ||
        opts.command.includes("ffuf");

      try {
        if (!sandbox) throw new Error("Sandbox not created");

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
              commandLower.includes("docker-compose "),
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

        // Log long-running commands for debugging
        if (isLongRunningCommand) {
          console.log(
            `[${benchmarkName}] 🔧 Executing long-running command: ${opts.command.substring(0, 100)}...`,
          );
          console.log(
            `[${benchmarkName}]    Timeout: ${opts.timeout || 120000}ms`,
          );
        }

        // Execute command with timeout wrapper
        // Use Promise.race to ensure we don't hang indefinitely on Daytona SDK issues
        const effectiveTimeout = opts.timeout || 120000;
        const timeoutPromise = new Promise<never>((_, reject) => {
          setTimeout(() => {
            reject(
              new Error(
                `Command timed out after ${effectiveTimeout}ms: ${opts.command.substring(0, 50)}...`,
              ),
            );
          }, effectiveTimeout + 30000); // Add 30s buffer beyond the Daytona timeout
        });

        const executePromise = (async () => {
          try {
            // Execute command directly - Daytona combines stdout/stderr in result
            const result = await sandbox.process.executeCommand(
              opts.command,
              undefined,
              undefined,
              effectiveTimeout,
            );
            return result;
          } catch (daytonaError) {
            console.error(
              `[${benchmarkName}] ❌ Daytona SDK error during command execution:`,
              daytonaError instanceof Error
                ? daytonaError.message
                : String(daytonaError),
            );
            throw daytonaError;
          }
        })();

        const result = await Promise.race([executePromise, timeoutPromise]);

        if (isLongRunningCommand) {
          console.log(
            `[${benchmarkName}] ✅ Long-running command completed with exit code: ${result.exitCode}`,
          );
        }

        const output = result.result || "";
        const success = result.exitCode === 0;

        // Match the exact format from tools.ts
        return {
          command: opts.command,
          success,
          stdout: output,
          stderr: success ? "" : output,
          error: success ? "" : output,
        };
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        const errorStack = error instanceof Error ? error.stack : undefined;
        console.error(
          `[${benchmarkName}] ❌ executeCommandOverride error:`,
          errorMessage,
        );
        console.error(
          `[${benchmarkName}]    Command: ${opts.command.substring(0, 100)}...`,
        );

        // Log full stack trace for debugging
        if (errorStack) {
          console.error(
            `[${benchmarkName}]    Stack:`,
            errorStack.split("\n").slice(0, 5).join("\n"),
          );
        }

        logError("execute_command", {
          message: errorMessage,
          stack: errorStack,
          command: opts.command.substring(0, 500),
        });

        return {
          command: opts.command,
          success: false,
          stdout: "",
          stderr: errorMessage,
          error: errorMessage,
        };
      }
    };

    const httpRequestOverride = async (
      opts: HttpRequestOpts,
    ): Promise<HttpRequestResult> => {
      try {
        if (!sandbox) throw new Error("Sandbox not created");

        // Build curl command - use -i to include headers in output
        const timeoutSec = Math.ceil((opts.timeout || 10000) / 1000);
        let curlCmd = `curl -s -i --max-time ${timeoutSec} --connect-timeout 10`;

        // Handle redirects - only follow if explicitly requested (default is false)
        if (opts.followRedirects === true) {
          curlCmd += " -L --max-redirs 10";
        }

        // Add method
        curlCmd += ` -X ${opts.method || "GET"}`;

        // Add headers
        if (opts.headers) {
          for (const [key, value] of Object.entries(opts.headers)) {
            const safeValue = String(value).replace(/'/g, "'\\''");
            curlCmd += ` -H '${key}: ${safeValue}'`;
          }
        }

        // Add body using heredoc for complex payloads
        if (opts.body) {
          // Use base64 to safely transfer the body
          const bodyBase64 = Buffer.from(opts.body).toString("base64");
          curlCmd = `echo '${bodyBase64}' | base64 -d | curl -s -i --max-time ${timeoutSec} --connect-timeout 10`;
          // Handle redirects - only follow if explicitly requested (default is false)
          if (opts.followRedirects === true) {
            curlCmd += " -L --max-redirs 10";
          }
          curlCmd += ` -X ${opts.method || "GET"}`;
          if (opts.headers) {
            for (const [key, value] of Object.entries(opts.headers)) {
              const safeValue = String(value).replace(/'/g, "'\\''");
              curlCmd += ` -H '${key}: ${safeValue}'`;
            }
          }
          curlCmd += " --data-binary @-";
        }

        // Add URL
        const safeUrl = opts.url.replace(/'/g, "'\\''");
        curlCmd += ` '${safeUrl}'`;

        const result = await sandbox.process.executeCommand(
          curlCmd,
          undefined,
          undefined,
          (opts.timeout || 10000) + 15000,
        );

        const output = result.result || "";

        // Parse curl -i output: headers\r\n\r\nbody
        // Find the blank line separating headers from body
        const headerEndIndex = output.indexOf("\r\n\r\n");
        let headersText = "";
        let body = "";

        if (headerEndIndex !== -1) {
          headersText = output.substring(0, headerEndIndex);
          body = output.substring(headerEndIndex + 4);
        } else {
          // Try with just \n\n
          const altIndex = output.indexOf("\n\n");
          if (altIndex !== -1) {
            headersText = output.substring(0, altIndex);
            body = output.substring(altIndex + 2);
          } else {
            body = output;
          }
        }

        // Parse status from first line: HTTP/1.1 200 OK
        const statusLine = headersText.split("\n")[0] || "";
        const statusMatch = statusLine.match(/HTTP\/[\d.]+\s+(\d+)\s*(.*)/);
        const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
        const statusText = statusMatch ? statusMatch[2]?.trim() || "" : "";

        // Parse headers
        const headers: Record<string, string> = {};
        const headerLines = headersText.split("\n").slice(1);
        for (const line of headerLines) {
          const colonIndex = line.indexOf(":");
          if (colonIndex > 0) {
            const key = line.substring(0, colonIndex).trim().toLowerCase();
            const value = line.substring(colonIndex + 1).trim();
            if (key) {
              headers[key] = value;
            }
          }
        }

        // Detect redirect
        const redirected =
          headers["location"] !== undefined || (status >= 300 && status < 400);

        // Truncate body like the original tool does (5000 chars)
        const truncatedBody =
          body.length > 5000
            ? `${body.substring(0, 5000)}... \n\n (truncated) use execute_command with grep / tail to paginate the response`
            : body;

        // Match the exact format from tools.ts - success: true if no exception
        return {
          success: true,
          status,
          statusText,
          headers,
          body: truncatedBody,
          url: opts.url,
          redirected,
        };
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        const errorStack = error instanceof Error ? error.stack : undefined;
        console.error(
          `[${benchmarkName}] ❌ httpRequestOverride error:`,
          errorMessage,
        );

        logError("http_request", {
          message: errorMessage,
          stack: errorStack,
          url: opts.url,
          method: opts.method,
        });

        // Match the exact error format from tools.ts
        return {
          success: false,
          url: opts.url,
          status: 0,
          statusText: "",
          headers: {},
          body: "",
          redirected: false,
        };
      }
    };

    // Step 10: Run streamlined pentest with tool overrides (scope constraints are in session config)
    console.log(`[${benchmarkName}] 🔍 Starting streamlined pentest...`);
    console.log(
      `[${benchmarkName}] ℹ️  Agent running locally with tool overrides (commands/HTTP proxied to sandbox, docker commands BLOCKED)`,
    );

    let pentestResult;
    try {
      pentestResult = await runStreamlinedPentest({
        target: targetUrl,
        model,
        session,
        toolOverride: {
          execute_command: executeCommandOverride,
          http_request: httpRequestOverride,
        },
        onProgress: (status) => {
          const progressParts: string[] = [
            `[${benchmarkName}] [${status.phase}]`,
          ];

          if (
            status.tasksCompleted !== undefined &&
            status.totalTasks !== undefined
          ) {
            progressParts.push(
              `[${status.tasksCompleted}/${status.totalTasks} tasks]`,
            );
          }
          if (status.activeAgents !== undefined && status.activeAgents > 0) {
            progressParts.push(`[${status.activeAgents} active]`);
          }
          progressParts.push(status.message);

          console.log(progressParts.join(" "));

          if (status.findingsCount !== undefined && status.findingsCount > 0) {
            console.log(
              `[${benchmarkName}]   Findings so far: ${status.findingsCount}`,
            );
          }
        },
      });
    } catch (pentestError) {
      const pentestMessage =
        pentestError instanceof Error
          ? pentestError.message
          : String(pentestError);
      console.error(
        `[${benchmarkName}] ❌ Pentest threw an exception: ${pentestMessage}`,
      );
      logError("pentest_execution", {
        message: pentestMessage,
        stack: pentestError instanceof Error ? pentestError.stack : undefined,
      });
      // Re-throw to be handled by the outer catch
      throw pentestError;
    }

    if (!pentestResult.success) {
      console.log(
        `[${benchmarkName}] ⚠️  Pentest completed with error: ${pentestResult.error}`,
      );
      logError("pentest_result", {
        message: pentestResult.error || "Pentest returned success=false",
      });
    }

    console.log(
      `[${benchmarkName}] ✅ Pentest completed. Total findings: ${pentestResult.totalFindings}`,
    );

    // Step 12: Detect flag in artifacts
    console.log(`[${benchmarkName}] 🎯 Detecting flag in artifacts...`);
    let flagDetection;
    if (options.benchmarkType === "pace" && expectedFlags.length > 0) {
      // PACEbench: Detect multiple flags
      flagDetection = await detectMultipleFlagsInArtifacts(
        session.rootPath,
        expectedFlags,
        benchmarkName,
      );
    } else if (expectedFlag) {
      // XBEN: Detect single flag
      flagDetection = await detectFlagInArtifacts(
        session.rootPath,
        expectedFlag,
        benchmarkName,
      );
    } else {
      flagDetection = {
        detected: false,
        flagValue: null,
        foundIn: [],
        locations: [],
        searchLocations: [],
      };
    }

    // Step 13: Re-run all POCs in sandbox and save their outputs
    console.log(`[${benchmarkName}] 🔄 Re-running POCs in sandbox...`);
    const pocRunResults = await rerunAllPocsInSandbox(
      sandbox,
      session.rootPath,
      remoteBenchmarkPath,
      benchmarkName,
      targetUrl,
    );

    // Step 14: Generate benchmark results
    const results: BenchmarkResults = {
      repoPath: benchmarkPath,
      branch: benchmarkName,
      targetUrl,
      sessionId: session.id,
      sessionPath: session.rootPath,
      flagDetection,
      expectedFlag,
      pocRunSummary:
        pocRunResults.total > 0
          ? {
              total: pocRunResults.total,
              passed: pocRunResults.passed,
              failed: pocRunResults.failed,
              skipped: pocRunResults.results.filter((r) => r.exitCode === null)
                .length,
              results: pocRunResults.results.map((r) => ({
                pocFile: r.pocFile,
                pocName: r.pocName,
                exitCode: r.exitCode,
                success: r.success,
                duration: r.duration,
                error: r.error,
              })),
            }
          : undefined,
      timestamp: new Date().toISOString(),
    };

    const reportPath = path.join(session.rootPath, "benchmark_results.json");
    writeFileSync(reportPath, JSON.stringify(results, null, 2));

    console.log(
      `\n[${benchmarkName}] 📄 Benchmark report saved to: ${reportPath}`,
    );
    console.log(
      `\n[${benchmarkName}] 🎯 FLAG STATUS: ${flagDetection.detected ? "✅ DETECTED" : "❌ NOT DETECTED"}`,
    );
    if (flagDetection.detected) {
      console.log(
        `[${benchmarkName}]    Found in: ${flagDetection.foundIn.join(", ")}`,
      );
      if (flagDetection.locations && flagDetection.locations.length > 0) {
        console.log(`[${benchmarkName}]    Exact locations:`);
        for (const loc of flagDetection.locations.slice(0, 5)) {
          // Show first 5 locations
          console.log(`[${benchmarkName}]      ${loc.file}:${loc.line}`);
        }
        if (flagDetection.locations.length > 5) {
          console.log(
            `[${benchmarkName}]      ... and ${flagDetection.locations.length - 5} more`,
          );
        }
      }
    }
    if (pocRunResults.total > 0) {
      console.log(
        `\n[${benchmarkName}] 🧪 POC RESULTS: ${pocRunResults.passed}/${pocRunResults.total} passed`,
      );
    }

    const duration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
    console.log(`\n[${benchmarkName}] ✅ Completed in ${duration}m`);

    return results;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;
    const duration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
    console.error(
      `\n[${benchmarkName}] ❌ Failed after ${duration}m: ${errorMessage}`,
    );
    if (errorStack) {
      console.error(`[${benchmarkName}] Stack: ${errorStack}`);
    }

    // Log error to session's logs directory if session was created
    if (sessionRootPath) {
      try {
        const errorLogFile = path.join(
          sessionRootPath,
          "logs",
          "benchmark-errors.jsonl",
        );
        const entry = {
          timestamp: new Date().toISOString(),
          benchmarkName,
          phase: "benchmark_fatal",
          error: errorMessage,
          stack: errorStack,
          duration,
        };
        const { appendFileSync } = require("fs");
        appendFileSync(errorLogFile, JSON.stringify(entry) + "\n");
      } catch {
        // Silently fail if we can't write to log
      }
    }

    // Return a failure result
    return {
      repoPath: benchmarkPath,
      branch: benchmarkName,
      targetUrl: "",
      sessionId: "",
      sessionPath: sessionRootPath,
      flagDetection: {
        detected: false,
        flagValue: null,
        foundIn: [],
        locations: [],
        searchLocations: [],
      },
      expectedFlag: null,
      timestamp: new Date().toISOString(),
    };
  } finally {
    // Cleanup: Stop docker and delete sandbox
    if (sandbox) {
      try {
        console.log(`[${benchmarkName}] 🧹 Cleaning up sandbox...`);

        // Only try to stop docker if we successfully uploaded and started it
        if (remoteBenchmarkPath) {
          try {
            console.log(`[${benchmarkName}] 🐳 Stopping docker compose...`);
            await sandbox.process.executeCommand(
              `cd ${remoteBenchmarkPath} && docker compose down`,
              undefined,
              undefined,
              30000,
            );
          } catch (dockerError) {
            // Don't fail cleanup if docker stop fails (might not have started)
            console.log(
              `[${benchmarkName}] ⚠️  Docker stop failed (may not have started): ${dockerError instanceof Error ? dockerError.message : String(dockerError)}`,
            );
          }
        }

        // Wait for sandbox to settle before deleting
        console.log(`[${benchmarkName}] ⏳ Waiting for sandbox to settle...`);
        let attempts = 0;
        while (attempts < 10) {
          try {
            await sandbox.refreshData();
            if (sandbox.state !== "stopping" && sandbox.state !== "starting") {
              break;
            }
          } catch (refreshError) {
            console.log(
              `[${benchmarkName}] ⚠️  Refresh failed (attempt ${attempts + 1}): ${refreshError instanceof Error ? refreshError.message : String(refreshError)}`,
            );
          }
          await new Promise((resolve) => setTimeout(resolve, 3000));
          attempts++;
        }

        // Delete the sandbox
        try {
          console.log(`[${benchmarkName}] 🗑️  Deleting sandbox...`);
          await sandbox.delete();
          console.log(`[${benchmarkName}] ✅ Cleanup complete`);
        } catch (deleteError) {
          console.error(
            `[${benchmarkName}] ⚠️  Failed to delete sandbox: ${deleteError instanceof Error ? deleteError.message : String(deleteError)}`,
          );
          console.error(
            `[${benchmarkName}] ⚠️  You may need to manually delete sandbox: ${sandbox.id}`,
          );
        }
      } catch (error) {
        console.error(
          `[${benchmarkName}] ⚠️  Cleanup error: ${error instanceof Error ? error.message : String(error)}`,
        );
        console.error(
          `[${benchmarkName}] ⚠️  Sandbox may still be running: ${sandbox.id}`,
        );
      }
    }
  }
}

/**
 * Summary report shape used by generateMarkdownSummary
 */
export interface BenchmarkSummaryReport {
  timestamp: string;
  repoPath: string;
  model: string;
  totalBenchmarks: number;
  successful?: number;
  failed?: number;
  failureBreakdown?: {
    rateLimited: number;
    transient: number;
    permanent: number;
    unknown: number;
  };
  flagsDetected: number;
  flagsMissed?: number;
  pocStats?: {
    total: number;
    passed: number;
  };
  duration: string;
  benchmarks: Array<{
    benchmark: string;
    status: string;
    flagDetected?: boolean;
    expectedFlag?: string | null;
    foundIn?: string[];
    metrics?: {
      accuracy: number;
      precision: number;
      recall: number;
    };
    pocResults?: {
      total: number;
      passed: number;
    };
    sessionPath?: string;
    errorCategory?: string;
    error?: string;
  }>;
  failedBenchmarks?: string[];
}

/**
 * Generate markdown summary report
 */
function generateMarkdownSummary(summary: BenchmarkSummaryReport): string {
  const successful = summary.successful ?? summary.totalBenchmarks;
  const failed = summary.failed ?? 0;

  const lines = [
    "# Daytona Benchmark Results",
    "",
    `**Repository**: ${summary.repoPath}`,
    `**Model**: ${summary.model}`,
    `**Mode**: Daytona Docker-in-Docker`,
    `**Timestamp**: ${new Date(summary.timestamp).toLocaleString()}`,
    `**Duration**: ${summary.duration}m`,
    "",
    "## Summary",
    "",
    `- Total Benchmarks: ${summary.totalBenchmarks}`,
    `- Successful: ${successful}/${summary.totalBenchmarks}`,
    `- Failed: ${failed}/${summary.totalBenchmarks}`,
  ];

  // Add failure breakdown if there are failures
  if (summary.failureBreakdown && failed > 0) {
    lines.push(`  - Rate Limited: ${summary.failureBreakdown.rateLimited}`);
    lines.push(`  - Transient Errors: ${summary.failureBreakdown.transient}`);
    lines.push(`  - Permanent Errors: ${summary.failureBreakdown.permanent}`);
    lines.push(`  - Unknown Errors: ${summary.failureBreakdown.unknown}`);
  }

  lines.push(
    `- Flags Detected: ${summary.flagsDetected}/${successful} (${successful > 0 ? Math.round((summary.flagsDetected / successful) * 100) : 0}%)`,
  );
  lines.push(`- Flags Missed: ${summary.flagsMissed}/${successful}`);

  // Add POC stats if available
  if (summary.pocStats && summary.pocStats.total > 0) {
    lines.push(
      `- POCs Passed: ${summary.pocStats.passed}/${summary.pocStats.total} (${Math.round((summary.pocStats.passed / summary.pocStats.total) * 100)}%)`,
    );
  }

  lines.push("");
  lines.push("## Benchmark Results");
  lines.push("");

  for (const benchmark of summary.benchmarks) {
    const statusIcon = benchmark.status === "success" ? "✅" : "❌";
    const flagIcon = benchmark.flagDetected ? "🎯" : "❌";

    lines.push(`### ${statusIcon} ${benchmark.benchmark}`);
    lines.push("");
    lines.push(`- **Status**: ${benchmark.status}`);

    if (benchmark.status === "success") {
      lines.push(
        `- **Flag Detected**: ${flagIcon} ${benchmark.flagDetected ? "YES" : "NO"}`,
      );
      if (benchmark.flagDetected) {
        lines.push(`  - Expected: \`${benchmark.expectedFlag}\``);
        lines.push(
          `  - Found in: ${benchmark.foundIn?.join(", ") ?? "unknown"}`,
        );
      }
      if (benchmark.metrics) {
        lines.push(`- **Metrics**:`);
        lines.push(`  - Accuracy: ${benchmark.metrics.accuracy}%`);
        lines.push(`  - Precision: ${benchmark.metrics.precision}%`);
        lines.push(`  - Recall: ${benchmark.metrics.recall}%`);
      }
      if (benchmark.pocResults) {
        lines.push(
          `- **POC Results**: ${benchmark.pocResults.passed}/${benchmark.pocResults.total} passed`,
        );
      }
      if (benchmark.sessionPath) {
        lines.push(
          `- **Session**: [${benchmark.sessionPath}](${benchmark.sessionPath})`,
        );
      }
    } else {
      lines.push(
        `- **Error Category**: ${benchmark.errorCategory || "unknown"}`,
      );
      lines.push(`- **Error**: ${benchmark.error || "Unknown error"}`);
    }

    lines.push("");
  }

  // Add retry command for failed benchmarks
  if (summary.failedBenchmarks && summary.failedBenchmarks.length > 0) {
    lines.push("## Retry Failed Benchmarks");
    lines.push("");
    lines.push("```bash");
    lines.push(
      `bun run scripts/daytona-benchmark.ts ${summary.repoPath} ${summary.failedBenchmarks.join(" ")}`,
    );
    lines.push("```");
    lines.push("");
  }

  return lines.join("\n");
}

/**
 * Error categories for benchmark failures
 */
type ErrorCategory = "rate_limit" | "transient" | "permanent" | "unknown";

/**
 * Categorize an error to determine if it's retriable
 */
function categorizeError(error: unknown): ErrorCategory {
  const message = (
    error instanceof Error ? error.message : String(error ?? "")
  ).toLowerCase();

  // Rate limit errors
  if (
    message.includes("429") ||
    message.includes("rate limit") ||
    message.includes("rate_limit") ||
    message.includes("too many requests") ||
    message.includes("quota exceeded") ||
    message.includes("overloaded")
  ) {
    return "rate_limit";
  }

  // Transient errors (network, temporary failures)
  if (
    message.includes("502") ||
    message.includes("503") ||
    message.includes("504") ||
    message.includes("econnreset") ||
    message.includes("etimedout") ||
    message.includes("econnrefused") ||
    message.includes("socket hang up") ||
    message.includes("network") ||
    message.includes("timeout")
  ) {
    return "transient";
  }

  // Permanent errors (validation, missing resources, etc.)
  if (
    message.includes("not found") ||
    message.includes("invalid") ||
    message.includes("permission denied") ||
    message.includes("unauthorized")
  ) {
    return "permanent";
  }

  return "unknown";
}

/**
 * Result of a benchmark execution attempt
 */
interface BenchmarkExecutionResult {
  benchmarkName: string;
  status: "success" | "failed";
  result?: BenchmarkResults;
  error?: string;
  errorCategory?: ErrorCategory;
}

/**
 * Run benchmarks across multiple benchmarks in parallel with Daytona Docker-in-Docker
 * Uses Promise.allSettled to ensure all benchmarks complete even if some fail
 */
export async function runMultipleBenchmarks(
  options: MultipleBenchmarkOptions,
): Promise<BenchmarkResults[]> {
  const benchmarks = options.benchmarks || [];

  if (benchmarks.length === 0) {
    throw new Error("No benchmarks provided");
  }

  const maxParallel = options.maxParallel || 10;
  const startTime = Date.now();

  console.log("\n" + "=".repeat(80));
  console.log("🚀 STARTING PARALLEL DAYTONA BENCHMARK EXECUTION");
  console.log("=".repeat(80));
  console.log(`Repository: ${options.repoPath}`);
  console.log(`Benchmarks: ${benchmarks.length}`);
  console.log(`Model: ${options.model}`);
  console.log(`Max Parallel: ${maxParallel}`);
  console.log("=".repeat(80) + "\n");

  // Run with concurrency limit using Promise.allSettled to capture all results
  const limit = pLimit(maxParallel);
  const settledResults = await Promise.allSettled(
    benchmarks.map((benchmarkName) =>
      limit(async (): Promise<BenchmarkExecutionResult> => {
        // Construct benchmark path based on benchmark type
        const benchmarkPath =
          options.benchmarkType === "pace"
            ? path.join(options.repoPath, "docker", "FullChain", benchmarkName)
            : path.join(options.repoPath, "benchmarks", benchmarkName);

        try {
          const result = await runBenchmarkWithDaytona({
            benchmarkPath,
            benchmarkName,
            model: options.model,
            apiKey: options.apiKey,
            orgId: options.orgId,
            anthropicKey: options.anthropicKey,
            openrouterKey: options.openrouterKey,
            prefix: options.prefix,
            dockerUsername: options.dockerUsername,
            dockerPassword: options.dockerPassword,
            benchmarkType: options.benchmarkType,
            vulnsMode: options.vulnsMode,
            sandboxCpu: options.sandboxCpu,
            sandboxMemory: options.sandboxMemory,
            sandboxDisk: options.sandboxDisk,
          });
          return {
            benchmarkName,
            status: "success",
            result,
          };
        } catch (error) {
          const errorCategory = categorizeError(error);
          const errorMessage =
            error instanceof Error ? error.message : String(error);
          console.error(
            `\n❌ [${benchmarkName}] FAILED (${errorCategory}): ${errorMessage}`,
          );
          return {
            benchmarkName,
            status: "failed",
            error: errorMessage,
            errorCategory,
          };
        }
      }),
    ),
  );

  // Process settled results
  const executionResults: BenchmarkExecutionResult[] = settledResults.map(
    (settled, index) => {
      if (settled.status === "fulfilled") {
        return settled.value;
      } else {
        // Promise rejection (shouldn't happen with our try/catch, but handle it)
        const errorCategory = categorizeError(settled.reason);
        console.error(
          `\n❌ [${benchmarks[index]}] PROMISE REJECTED (${errorCategory}): ${settled.reason?.message || settled.reason}`,
        );
        if (settled.reason?.stack) {
          console.error(
            `[${benchmarks[index]}] Stack: ${settled.reason.stack}`,
          );
        }
        return {
          benchmarkName: benchmarks[index]!,
          status: "failed" as const,
          error: settled.reason?.message || String(settled.reason),
          errorCategory,
        };
      }
    },
  );

  // Separate successful and failed results
  const successfulResults = executionResults.filter(
    (r) => r.status === "success" && r.result,
  );
  const failedResults = executionResults.filter((r) => r.status === "failed");
  const results = successfulResults.map((r) => r.result!);

  // Categorize failures
  const rateLimitFailures = failedResults.filter(
    (r) => r.errorCategory === "rate_limit",
  );
  const transientFailures = failedResults.filter(
    (r) => r.errorCategory === "transient",
  );
  const permanentFailures = failedResults.filter(
    (r) => r.errorCategory === "permanent",
  );
  const unknownFailures = failedResults.filter(
    (r) => r.errorCategory === "unknown",
  );

  const totalDuration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
  const flagsDetected = results.filter((r) => r.flagDetection?.detected).length;
  const flagsMissed = results.filter((r) => !r.flagDetection?.detected).length;

  // Aggregate POC results
  const totalPocs = results.reduce(
    (sum, r) => sum + (r.pocRunSummary?.total || 0),
    0,
  );
  const passedPocs = results.reduce(
    (sum, r) => sum + (r.pocRunSummary?.passed || 0),
    0,
  );
  const failedPocs = results.reduce(
    (sum, r) => sum + (r.pocRunSummary?.failed || 0),
    0,
  );

  console.log("\n" + "=".repeat(80));
  console.log("📊 BENCHMARK SUMMARY");
  console.log("=".repeat(80));
  console.log(`Total Duration: ${totalDuration}m`);
  console.log(`Total Benchmarks: ${benchmarks.length}`);
  console.log(`Successful: ${successfulResults.length}/${benchmarks.length}`);
  console.log(`Failed: ${failedResults.length}/${benchmarks.length}`);
  if (failedResults.length > 0) {
    console.log(`  - Rate Limited: ${rateLimitFailures.length}`);
    console.log(`  - Transient Errors: ${transientFailures.length}`);
    console.log(`  - Permanent Errors: ${permanentFailures.length}`);
    console.log(`  - Unknown Errors: ${unknownFailures.length}`);
  }
  console.log(
    `Flags Detected: ${flagsDetected}/${successfulResults.length} (${successfulResults.length > 0 ? Math.round((flagsDetected / successfulResults.length) * 100) : 0}%)`,
  );
  console.log(`Flags Missed: ${flagsMissed}/${successfulResults.length}`);
  if (totalPocs > 0) {
    console.log(
      `POCs Passed: ${passedPocs}/${totalPocs} (${Math.round((passedPocs / totalPocs) * 100)}%)`,
    );
  }
  console.log("=".repeat(80));

  // Log failed benchmarks for easy retry
  if (failedResults.length > 0) {
    console.log("\n⚠️  FAILED BENCHMARKS:");
    for (const failed of failedResults) {
      console.log(
        `  - ${failed.benchmarkName} (${failed.errorCategory}): ${failed.error?.substring(0, 100)}`,
      );
    }
    console.log("\nTo retry failed benchmarks, run:");
    console.log(
      `  bun run scripts/daytona-benchmark.ts ${options.repoPath} ${failedResults.map((f) => f.benchmarkName).join(" ")}`,
    );
  }

  // Generate summary report
  const summaryDirName = options.prefix
    ? `${options.prefix}-${new Date().toISOString().replace(/[:.]/g, "-")}`
    : `daytona-run-${new Date().toISOString().replace(/[:.]/g, "-")}`;
  const summaryDir = path.join(
    process.cwd(),
    ".pensar",
    "benchmarks",
    "executions",
    summaryDirName,
  );

  mkdirSync(summaryDir, { recursive: true });

  const summary = {
    timestamp: new Date().toISOString(),
    repoPath: options.repoPath,
    model: options.model,
    mode: "daytona-dind",
    totalBenchmarks: benchmarks.length,
    successful: successfulResults.length,
    failed: failedResults.length,
    failureBreakdown: {
      rateLimited: rateLimitFailures.length,
      transient: transientFailures.length,
      permanent: permanentFailures.length,
      unknown: unknownFailures.length,
    },
    flagsDetected,
    flagsMissed,
    pocStats: {
      total: totalPocs,
      passed: passedPocs,
      failed: failedPocs,
    },
    duration: totalDuration,
    benchmarks: executionResults.map((r) => {
      if (r.status === "success" && r.result) {
        return {
          benchmark: r.benchmarkName,
          status: "success" as const,
          flagDetected: r.result.flagDetection?.detected || false,
          expectedFlag: r.result.expectedFlag,
          foundIn: r.result.flagDetection?.foundIn || [],
          sessionPath: r.result.sessionPath,
          pocResults: r.result.pocRunSummary
            ? {
                total: r.result.pocRunSummary.total,
                passed: r.result.pocRunSummary.passed,
                failed: r.result.pocRunSummary.failed,
              }
            : undefined,
        };
      } else {
        return {
          benchmark: r.benchmarkName,
          status: "failed" as const,
          error: r.error,
          errorCategory: r.errorCategory,
        };
      }
    }),
    failedBenchmarks: failedResults.map((f) => f.benchmarkName),
  };

  writeFileSync(
    path.join(summaryDir, "summary.json"),
    JSON.stringify(summary, null, 2),
  );

  // Generate markdown summary
  const markdown = generateMarkdownSummary(summary);
  writeFileSync(path.join(summaryDir, "summary.md"), markdown);

  console.log(`\n📄 Summary report saved to: ${summaryDir}/summary.json`);
  console.log(`📄 Markdown report saved to: ${summaryDir}/summary.md\n`);

  // Exit with non-zero code if any benchmarks failed
  // This ensures durable-benchmark.sh knows to retry
  if (failedResults.length > 0) {
    console.log(
      `\n⚠️  Exiting with code 1 due to ${failedResults.length} failed benchmark(s)`,
    );
    process.exit(1);
  }

  return results;
}
