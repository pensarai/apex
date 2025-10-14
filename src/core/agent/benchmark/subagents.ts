import { exec as nodeExec } from "child_process";
import { promisify } from "util";
import { existsSync } from "fs";
import { join } from "path";
import type { DevEnvironmentInfo } from "./types";
import { runDevEnvironmentAgent } from "./devEnvironmentAgent";
import type { AIModel } from "../../ai";

const exec = promisify(nodeExec);

/**
 * Start the development environment using an AI agent that can fix issues
 */
export async function startDevEnvironment(
  repoPath: string,
  branch: string,
  model: AIModel,
  abortSignal?: AbortSignal
): Promise<DevEnvironmentInfo> {
  // Verify repo path exists
  if (!existsSync(repoPath)) {
    console.log(`[Benchmark] Repository path does not exist: ${repoPath}`);
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
        console.log(`[Benchmark] Error: ${error.message}`);
        throw new Error(
          `Branch directory ${branchDir} not found and git checkout failed: ${error.message}`
        );
      }
    }
  }

  // Use the AI agent to start the environment
  console.log(`[Benchmark] Spawning dev environment agent for: ${workingDir}`);
  const agentResult = await runDevEnvironmentAgent(
    workingDir,
    model,
    abortSignal
  );

  if (!agentResult.success) {
    console.log(
      `[Benchmark] Failed to start development environment: ${agentResult.error}`
    );
    throw new Error(
      `Failed to start development environment: ${
        agentResult.error || "Unknown error"
      }`
    );
  }

  console.log(`[Benchmark] Dev environment ready at: ${agentResult.targetUrl}`);
  if (agentResult.changes && agentResult.changes.length > 0) {
    console.log(
      `[Benchmark] Agent made ${agentResult.changes.length} change(s) to docker-compose`
    );
  }

  return {
    repoPath: workingDir,
    branch: branch || "current",
    composeFile: agentResult.composeFile!,
    targetUrl: agentResult.targetUrl!,
    started: true,
  };
}

/**
 * Stop the development environment and commit any changes
 */
export async function stopDevEnvironment(
  repoPath: string,
  composeFile: string,
  commitChanges: boolean = true
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

    // Commit and push any changes made by the dev environment agent
    if (commitChanges) {
      try {
        // Check if there are any changes
        const { stdout: statusOutput } = await exec("git status --porcelain", {
          cwd: repoPath,
        });

        if (statusOutput.trim()) {
          console.log(
            `[Benchmark] Committing changes made by dev environment agent`
          );

          // Add all changes
          await exec("git add .", { cwd: repoPath });

          // Commit with descriptive message
          await exec(
            'git commit -m "fix: docker-compose changes from benchmark agent"',
            { cwd: repoPath }
          );

          // Push changes
          await exec("git push", { cwd: repoPath });

          console.log(`[Benchmark] Changes committed and pushed successfully`);
        } else {
          console.log(`[Benchmark] No changes to commit`);
        }
      } catch (gitError: any) {
        console.error(
          `[Benchmark] Failed to commit/push changes: ${gitError.message}`
        );
        // Don't throw - cleanup should continue even if git fails
      }
    }
  } catch (error: any) {
    console.error(`Failed to stop docker compose: ${error.message}`);
    // Don't throw - we want to continue even if cleanup partially fails
  }
}

// Note: Comparison logic has been moved to comparisonAgent.ts
// This file now only contains environment management functions
