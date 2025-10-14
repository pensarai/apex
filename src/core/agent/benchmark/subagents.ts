import { exec as nodeExec } from "child_process";
import { promisify } from "util";
import { existsSync } from "fs";
import { join } from "path";
import type { DevEnvironmentInfo } from "./types";

const exec = promisify(nodeExec);

/**
 * Start the development environment using docker compose
 */
export async function startDevEnvironment(
  repoPath: string,
  branch?: string
): Promise<DevEnvironmentInfo> {
  // Verify repo path exists
  if (!existsSync(repoPath)) {
    throw new Error(`Repository path does not exist: ${repoPath}`);
  }

  // Determine the working directory - if branch is specified, cd into that folder
  let workingDir = repoPath;
  if (branch) {
    const branchDir = join(repoPath, branch);
    if (existsSync(branchDir)) {
      workingDir = branchDir;
      console.log(`[Benchmark] Using branch directory: ${branchDir}`);
    } else {
      // Try checking out the branch in the main repo
      try {
        await exec(`git checkout ${branch}`, { cwd: repoPath });
        console.log(`[Benchmark] Checked out branch: ${branch}`);
      } catch (error: any) {
        throw new Error(
          `Branch directory ${branchDir} not found and git checkout failed: ${error.message}`
        );
      }
    }
  }

  // Look for docker-compose file
  const composeFiles = [
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
  ];

  let composeFile: string | null = null;
  for (const file of composeFiles) {
    const fullPath = join(workingDir, file);
    if (existsSync(fullPath)) {
      composeFile = file;
      break;
    }
  }

  if (!composeFile) {
    throw new Error(
      `No docker-compose file found in ${workingDir} (tried: docker-compose.yml, compose.yml)`
    );
  }

  // Start docker compose
  try {
    console.log(`[Benchmark] Starting docker compose in: ${workingDir}`);
    const { stdout, stderr } = await exec(
      `docker compose -f ${composeFile} up -d`,
      {
        cwd: workingDir,
      }
    );

    console.log("Docker compose output:", stdout);
    if (stderr) console.error("Docker compose stderr:", stderr);

    // Wait for services to be ready
    await new Promise((resolve) => setTimeout(resolve, 5000));

    // Try to determine the target URL
    // Default to localhost:3000, but could be configured
    const targetUrl =
      process.env.BENCHMARK_TARGET_URL || "http://localhost:3000";

    return {
      repoPath: workingDir,
      branch: branch || "current",
      composeFile,
      targetUrl,
      started: true,
    };
  } catch (error: any) {
    throw new Error(`Failed to start docker compose: ${error.message}`);
  }
}

/**
 * Stop the development environment
 */
export async function stopDevEnvironment(
  repoPath: string,
  composeFile: string
): Promise<void> {
  try {
    console.log(`[Benchmark] Stopping docker compose in: ${repoPath}`);
    const { stdout, stderr } = await exec(
      `docker compose -f ${composeFile} down`,
      {
        cwd: repoPath,
      }
    );

    console.log("Docker compose down output:", stdout);
    if (stderr) console.error("Docker compose down stderr:", stderr);
  } catch (error: any) {
    console.error(`Failed to stop docker compose: ${error.message}`);
    // Don't throw - we want to continue even if cleanup partially fails
  }
}

// Note: Comparison logic has been moved to comparisonAgent.ts
// This file now only contains environment management functions
