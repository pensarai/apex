#!/usr/bin/env tsx

/**
 * Sandbox Playground Script
 *
 * Spins up a Daytona sandbox for a single benchmark and waits for user to press Ctrl+C
 * to gracefully shut down and cleanup the sandbox.
 *
 * Usage:
 *   bun run scripts/sandbox-playground.ts <repo-path> <benchmark-id>
 *
 * Example:
 *   bun run scripts/sandbox-playground.ts /path/to/xben-challenges XBEN-001-24
 */

import { Daytona, Image, Sandbox } from "@daytonaio/sdk";
import { existsSync, statSync, readdirSync, readFileSync } from "fs";
import path from "path";
import { parseDockerComposePort } from "../src/core/agents/legacy/benchmark/docker-utils";
import { extractFlagFromRepo } from "../src/core/agents/legacy/benchmark/flag-detector";

// Global sandbox reference for cleanup
let sandbox: Sandbox | undefined;
let isShuttingDown = false;

/**
 * Recursively collect all files from a directory
 */
function collectFilesRecursive(
  dirPath: string,
  baseDir: string,
  files: Array<{ source: Buffer; destination: string }> = [],
): Array<{ source: Buffer; destination: string }> {
  const entries = readdirSync(dirPath);

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry);
    const stat = statSync(fullPath);

    if (stat.isDirectory()) {
      collectFilesRecursive(fullPath, baseDir, files);
    } else if (stat.isFile()) {
      const relativePath = path.relative(baseDir, fullPath);
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
 * Gracefully cleanup the sandbox
 */
async function cleanup(
  benchmarkName: string,
  remoteBenchmarkPath: string,
): Promise<void> {
  if (isShuttingDown) {
    console.log(`\n[${benchmarkName}] ⚠️  Already shutting down...`);
    return;
  }

  isShuttingDown = true;

  if (!sandbox) {
    console.log(`\n[${benchmarkName}] ⚠️  No sandbox to cleanup`);
    return;
  }

  console.log(
    `\n[${benchmarkName}] 🛑 Received shutdown signal, cleaning up...`,
  );

  try {
    // Stop docker compose if we have the path
    if (remoteBenchmarkPath) {
      try {
        console.log(`[${benchmarkName}] 🐳 Stopping docker compose...`);
        await sandbox.process.executeCommand(
          `cd ${remoteBenchmarkPath} && docker compose down --timeout 10`,
          undefined,
          undefined,
          30000,
        );
        console.log(`[${benchmarkName}] ✅ Docker compose stopped`);
      } catch (dockerError: unknown) {
        const message =
          dockerError instanceof Error
            ? dockerError.message
            : String(dockerError);
        console.log(`[${benchmarkName}] ⚠️  Docker stop failed: ${message}`);
      }
    }

    // Wait for sandbox to settle
    console.log(`[${benchmarkName}] ⏳ Waiting for sandbox to settle...`);
    let attempts = 0;
    while (attempts < 5) {
      try {
        await sandbox.refreshData();
        if (sandbox.state !== "stopping" && sandbox.state !== "starting") {
          break;
        }
      } catch {
        // Ignore refresh errors
      }
      await new Promise((resolve) => setTimeout(resolve, 2000));
      attempts++;
    }

    // Delete the sandbox
    console.log(`[${benchmarkName}] 🗑️  Deleting sandbox...`);
    await sandbox.delete();
    console.log(`[${benchmarkName}] ✅ Sandbox deleted successfully`);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[${benchmarkName}] ❌ Cleanup error: ${message}`);
    if (sandbox) {
      console.error(
        `[${benchmarkName}] ⚠️  You may need to manually delete sandbox: ${sandbox.id}`,
      );
    }
  }
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length < 2) {
    console.error(
      "Usage: bun run scripts/sandbox-playground.ts <repo-path> <benchmark-id>",
    );
    console.error();
    console.error("Arguments:");
    console.error(
      "  <repo-path>      Local path to XBEN challenges repository",
    );
    console.error("  <benchmark-id>   Benchmark ID (e.g., XBEN-001-24)");
    console.error();
    console.error("Options:");
    console.error(
      "  --daytona-api-key <key>   Daytona API key (default: DAYTONA_API_KEY env)",
    );
    console.error(
      "  --daytona-org-id <id>     Daytona organization ID (default: DAYTONA_ORG_ID env)",
    );
    console.error();
    console.error("Environment Variables:");
    console.error("  DAYTONA_API_KEY           Daytona API key (required)");
    console.error(
      "  DAYTONA_ORG_ID            Daytona organization ID (optional)",
    );
    console.error();
    console.error("Examples:");
    console.error(
      "  bun run scripts/sandbox-playground.ts /path/to/xben-challenges XBEN-001-24",
    );
    console.error(
      "  bun run scripts/sandbox-playground.ts ~/xben XBEN-002-24 --daytona-api-key xxx",
    );
    console.error();
    console.error(
      "The sandbox will stay running until you press Ctrl+C to shut it down.",
    );
    process.exit(1);
  }

  const repoPath = args[0]!;
  const benchmarkName = args[1]!;

  // Parse optional flags
  let apiKey = process.env.DAYTONA_API_KEY;
  let orgId = process.env.DAYTONA_ORG_ID;

  const apiKeyIndex = args.indexOf("--daytona-api-key");
  if (apiKeyIndex !== -1 && args[apiKeyIndex + 1]) {
    apiKey = args[apiKeyIndex + 1];
  }

  const orgIdIndex = args.indexOf("--daytona-org-id");
  if (orgIdIndex !== -1 && args[orgIdIndex + 1]) {
    orgId = args[orgIdIndex + 1];
  }

  // Validate inputs
  if (!apiKey) {
    console.error("Error: DAYTONA_API_KEY is required");
    console.error("Set it via environment variable or --daytona-api-key flag");
    process.exit(1);
  }

  if (!existsSync(repoPath)) {
    console.error(`Error: Repository path does not exist: ${repoPath}`);
    process.exit(1);
  }

  const benchmarkPath = path.join(repoPath, "benchmarks", benchmarkName);
  if (!existsSync(benchmarkPath)) {
    console.error(
      `Error: Benchmark directory does not exist: ${benchmarkPath}`,
    );
    process.exit(1);
  }

  if (!statSync(benchmarkPath).isDirectory()) {
    console.error(`Error: Benchmark path is not a directory: ${benchmarkPath}`);
    process.exit(1);
  }

  let remoteBenchmarkPath = "";

  // Setup signal handlers for graceful shutdown
  const handleShutdown = async () => {
    await cleanup(benchmarkName, remoteBenchmarkPath);
    process.exit(0);
  };

  process.on("SIGINT", handleShutdown);
  process.on("SIGTERM", handleShutdown);

  console.log("\n" + "=".repeat(80));
  console.log("🎮 SANDBOX PLAYGROUND");
  console.log("=".repeat(80));
  console.log(`Repository: ${repoPath}`);
  console.log(`Benchmark: ${benchmarkName}`);
  console.log(`Benchmark Path: ${benchmarkPath}`);
  if (orgId) {
    console.log(`Daytona Org: ${orgId}`);
  }
  console.log("=".repeat(80));
  console.log();
  console.log("Press Ctrl+C to gracefully shutdown and cleanup the sandbox.");
  console.log();

  try {
    // Parse docker-compose port
    console.log(
      `[${benchmarkName}] 🔍 Parsing docker-compose for web service...`,
    );
    const portInfo = parseDockerComposePort(benchmarkPath);
    console.log(
      `[${benchmarkName}] ✅ Found web service: ${portInfo.serviceName} on port ${portInfo.hostPort}`,
    );

    // Create Daytona client
    const daytona = new Daytona({ apiKey });

    // Create sandbox with DinD support
    console.log(
      `[${benchmarkName}] 🚀 Creating Daytona sandbox with Docker-in-Docker...`,
    );

    const dindImage = Image.base("docker:28.3.3-dind").runCommands(
      "apk add --no-cache curl make bash coreutils git jq python3 py3-pip vim nano",
    );

    sandbox = await daytona.create(
      {
        language: "typescript",
        envVars: {
          ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY || "",
          OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY || "",
        },
        public: true,
        networkBlockAll: false,
        resources: {
          cpu: 4,
          memory: 8,
          disk: 4,
        },
        image: dindImage,
      },
      { timeout: 300000 },
    );

    console.log(`[${benchmarkName}] ✅ Sandbox created: ${sandbox.id}`);

    // Wait for sandbox to be ready
    console.log(`[${benchmarkName}] ⏳ Waiting for sandbox to be ready...`);
    await new Promise((resolve) => setTimeout(resolve, 5000));

    // Start Docker daemon
    console.log(`[${benchmarkName}] 🐳 Starting Docker daemon...`);

    await sandbox.process.executeCommand(
      `(dockerd-entrypoint.sh dockerd --storage-driver=vfs > /var/log/dockerd.log 2>&1 &) || (dockerd --storage-driver=vfs --host=unix:///var/run/docker.sock > /var/log/dockerd.log 2>&1 &)`,
      undefined,
      undefined,
      30000,
    );

    // Wait for Docker daemon to be ready
    console.log(`[${benchmarkName}] ⏳ Waiting for Docker daemon to start...`);
    let dockerReady = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 2000));

      const dockerCheckResult = await sandbox.process.executeCommand(
        "docker version --format '{{.Server.Version}}' 2>&1",
        undefined,
        undefined,
        10000,
      );

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

      if (attempt % 5 === 0) {
        console.log(
          `[${benchmarkName}] ⏳ Docker not ready, waiting... (attempt ${attempt + 1}/30)`,
        );
      }
    }

    if (!dockerReady) {
      throw new Error(
        "Docker daemon failed to start in sandbox after 30 attempts",
      );
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

    // Upload benchmark directory
    console.log(`[${benchmarkName}] 📦 Uploading benchmark directory...`);
    const userHome = await sandbox.getUserHomeDir();
    remoteBenchmarkPath = path.posix.join(userHome ?? "", "benchmark");

    const filesToUpload = collectFilesRecursive(benchmarkPath, benchmarkPath);
    console.log(
      `[${benchmarkName}] 📁 Found ${filesToUpload.length} files to upload`,
    );

    const uploadFiles = filesToUpload.map((file) => ({
      source: file.source,
      destination: path.posix.join(
        remoteBenchmarkPath,
        file.destination.replace(/\\/g, "/"),
      ),
    }));

    // Upload files in batches
    const BATCH_SIZE = 10;
    for (let i = 0; i < uploadFiles.length; i += BATCH_SIZE) {
      const batch = uploadFiles.slice(i, i + BATCH_SIZE);
      const batchNum = Math.floor(i / BATCH_SIZE) + 1;
      const totalBatches = Math.ceil(uploadFiles.length / BATCH_SIZE);
      console.log(
        `[${benchmarkName}] 📤 Uploading batch ${batchNum}/${totalBatches}...`,
      );
      await sandbox.fs.uploadFiles(batch, 300);
      if (i + BATCH_SIZE < uploadFiles.length) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }

    console.log(
      `[${benchmarkName}] ✅ Benchmark uploaded to ${remoteBenchmarkPath}`,
    );

    // Extract flag
    console.log(`[${benchmarkName}] 🔍 Extracting flag from benchmark...`);
    const expectedFlag = await extractFlagFromRepo(
      benchmarkPath,
      benchmarkName,
    );
    if (expectedFlag) {
      console.log(
        `[${benchmarkName}] ✅ FLAG found: ${expectedFlag.substring(0, 20)}...`,
      );
    } else {
      console.log(`[${benchmarkName}] ⚠️  FLAG not found in benchmark`);
    }

    // Build docker images
    console.log(
      `[${benchmarkName}] 🔨 Building docker images with make build...`,
    );

    const buildResult = await sandbox.process.executeCommand(
      `cd ${remoteBenchmarkPath} && make build`,
      undefined,
      {
        FLAG: expectedFlag || "",
      },
      300000,
    );

    if (buildResult.exitCode !== 0) {
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
          `Failed to build docker images: ${composeResult.result}`,
        );
      }
    }

    console.log(`[${benchmarkName}] ✅ Docker images built`);

    // Start docker compose
    console.log(`[${benchmarkName}] 🐳 Starting docker compose...`);
    const startDockerResult = await sandbox.process.executeCommand(
      `cd ${remoteBenchmarkPath} && docker compose up -d --wait`,
      undefined,
      undefined,
      180000,
    );

    if (startDockerResult.exitCode !== 0) {
      throw new Error(
        `Failed to start docker compose: ${startDockerResult.result}`,
      );
    }

    console.log(`[${benchmarkName}] ✅ Docker compose started`);

    // Wait for services
    console.log(`[${benchmarkName}] ⏳ Waiting for services to be ready...`);
    await new Promise((resolve) => setTimeout(resolve, 10000));

    // Get actual port mapping
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
    const targetUrl = `http://localhost:${actualHostPort}`;

    // Get preview URL for external access
    console.log(`[${benchmarkName}] 🔗 Getting preview URL...`);
    const previewInfo = await sandbox.getPreviewLink(actualHostPort);
    console.log(`[${benchmarkName}] ✅ Preview URL created`);

    // Show running containers
    const psResult = await sandbox.process.executeCommand(
      `cd ${remoteBenchmarkPath} && docker compose ps`,
      undefined,
      undefined,
      30000,
    );

    console.log("\n" + "=".repeat(80));
    console.log("🎉 SANDBOX READY");
    console.log("=".repeat(80));
    console.log();
    console.log(`📦 Sandbox ID: ${sandbox.id}`);
    console.log(`🎯 Target URL (inside sandbox): ${targetUrl}`);
    console.log(`📁 Benchmark path (inside sandbox): ${remoteBenchmarkPath}`);
    if (expectedFlag) {
      console.log(`🚩 Expected FLAG: ${expectedFlag}`);
    }
    console.log();
    console.log("=".repeat(80));
    console.log("🌐 PREVIEW ACCESS (external):");
    console.log("=".repeat(80));
    console.log(`  URL:   ${previewInfo.url}`);
    console.log(`  Token: ${previewInfo.token}`);
    console.log();
    console.log("Running containers:");
    console.log(psResult.result || "  (none)");
    console.log();
    console.log("=".repeat(80));
    console.log("📝 USEFUL COMMANDS (run inside sandbox):");
    console.log("=".repeat(80));
    console.log(
      `  curl ${targetUrl}                    # Test the web service`,
    );
    console.log(`  docker compose logs -f              # View container logs`);
    console.log(
      `  docker compose ps                   # List running containers`,
    );
    console.log(
      `  docker compose exec <svc> sh        # Shell into a container`,
    );
    console.log();
    console.log("=".repeat(80));
    console.log(
      "🛑 Press Ctrl+C to gracefully shutdown and cleanup the sandbox",
    );
    console.log("=".repeat(80));
    console.log();

    // Keep the process running until Ctrl+C
    await new Promise(() => {
      // Keep the event loop active with a long interval
      setInterval(() => {}, 1 << 30);
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`\n[${benchmarkName}] ❌ Error: ${message}`);
    if (error instanceof Error && error.stack) {
      console.error(error.stack);
    }

    // Cleanup on error
    await cleanup(benchmarkName, remoteBenchmarkPath);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});
