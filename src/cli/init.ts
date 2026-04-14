#!/usr/bin/env bun

/**
 * pensar init — Set up CI/CD integration for Pensar pentesting
 *
 * Usage:
 *   pensar init                          Interactive setup (auto-detects CI platform)
 *   pensar init github-action            Generate .github/workflows/pensar.yml
 *   pensar init gitlab-ci                Append Pensar stage to .gitlab-ci.yml
 *   pensar init bitbucket-pipelines      Append Pensar step to bitbucket-pipelines.yml
 */

import * as fs from "fs";
import * as path from "path";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getFlag(flag: string, argv: string[]): string | undefined {
  const idx = argv.indexOf(flag);
  return idx !== -1 && idx + 1 < argv.length ? argv[idx + 1] : undefined;
}

function hasFlag(flag: string, argv: string[]): boolean {
  return argv.includes(flag);
}

function detectPlatform(
  cwd: string,
): "github-action" | "gitlab-ci" | "bitbucket-pipelines" | null {
  if (fs.existsSync(path.join(cwd, ".github"))) return "github-action";
  if (fs.existsSync(path.join(cwd, ".gitlab-ci.yml"))) return "gitlab-ci";
  if (fs.existsSync(path.join(cwd, "bitbucket-pipelines.yml")))
    return "bitbucket-pipelines";
  return null;
}

function detectDefaultBranch(cwd: string): string {
  try {
    const headRef = fs
      .readFileSync(path.join(cwd, ".git", "HEAD"), "utf-8")
      .trim();
    const match = headRef.match(/^ref: refs\/heads\/(.+)$/);
    if (match) return match[1];
  } catch {}
  return "main";
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

type Trigger = "push" | "deploy" | "pull_request";

interface WorkflowOptions {
  trigger: Trigger;
  branches: string[];
  level: "priority" | "full";
}

function generateGitHubAction(opts: WorkflowOptions): string {
  const branchList = opts.branches.join(", ");

  if (opts.trigger === "deploy") {
    return `name: Pensar Pentest (Post-Deploy)

on:
  workflow_dispatch:
  workflow_run:
    workflows: ['Deploy']
    types: [completed]
    branches: [${branchList}]

jobs:
  pentest:
    name: Pensar Pentest
    runs-on: ubuntu-latest
    if: \${{ github.event_name == 'workflow_dispatch' || github.event.workflow_run.conclusion == 'success' }}
    timeout-minutes: 60

    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.workflow_run.head_branch || github.ref }}

      - uses: pensarai/pentest-action@v1
        with:
          api-key: \${{ secrets.PENSAR_API_KEY }}
          branch: \${{ github.event.workflow_run.head_branch || github.ref_name }}
          level: ${opts.level}
`;
  }

  if (opts.trigger === "pull_request") {
    return `name: Pensar Pentest (PR)

on:
  pull_request:
    branches: [${branchList}]

jobs:
  pentest:
    name: Pensar Pentest
    runs-on: ubuntu-latest
    timeout-minutes: 60

    steps:
      - uses: actions/checkout@v4

      - uses: pensarai/pentest-action@v1
        with:
          api-key: \${{ secrets.PENSAR_API_KEY }}
          level: ${opts.level}
`;
  }

  // Default: push trigger
  return `name: Pensar Pentest

on:
  push:
    branches: [${branchList}]

jobs:
  pentest:
    name: Pensar Pentest
    runs-on: ubuntu-latest
    timeout-minutes: 60

    steps:
      - uses: actions/checkout@v4

      - uses: pensarai/pentest-action@v1
        with:
          api-key: \${{ secrets.PENSAR_API_KEY }}
          level: ${opts.level}
`;
}

function generateGitLabCI(opts: WorkflowOptions): string {
  const branchRule =
    opts.branches.length === 1
      ? `$CI_COMMIT_BRANCH == "${opts.branches[0]}"`
      : opts.branches.map((b) => `$CI_COMMIT_BRANCH == "${b}"`).join(" || ");

  return `# Pensar Pentest
pensar-pentest:
  stage: security
  image: node:22
  rules:
    - if: ${branchRule}
  before_script:
    - npm install -g @pensar/ci
  script:
    - pensar pentest --branch $CI_COMMIT_REF_NAME
  variables:
    PENSAR_API_KEY: $PENSAR_API_KEY
`;
}

function generateBitbucket(opts: WorkflowOptions): string {
  const steps = opts.branches
    .map(
      (branch) => `    ${branch}:
      - step:
          name: Pensar Pentest
          image: node:22
          script:
            - npm install -g @pensar/ci
            - pensar pentest --branch ${branch}`,
    )
    .join("\n");

  return `# Pensar Pentest
pipelines:
  branches:
${steps}
`;
}

function generatePensarConfig(): string {
  return JSON.stringify(
    {
      version: 1,
      mcp: {
        url: "https://api.pensar.dev/mcp",
        transport: "http",
      },
    },
    null,
    2,
  );
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

function showHelp(): void {
  console.log(`pensar init — Set up CI/CD integration for Pensar pentesting

Usage:
  pensar init                          Interactive setup (auto-detects CI platform)
  pensar init github-action            Generate GitHub Actions workflow
  pensar init gitlab-ci                Generate GitLab CI configuration
  pensar init bitbucket-pipelines      Generate Bitbucket Pipelines configuration

Options:
  --trigger <type>     Workflow trigger: push (default), deploy, pull_request
  --branches <list>    Comma-separated branches to test (default: auto-detect)
  --level <level>      Test depth: priority (fast) or full (default: full)
  --set-secret         Set PENSAR_API_KEY as GitHub secret (requires gh CLI)
  --dry-run            Print generated config without writing files
  -y, --yes            Skip prompts and use defaults
  -h, --help           Show this help message`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (hasFlag("--help", args) || hasFlag("-h", args)) {
    showHelp();
    return;
  }

  const cwd = process.cwd();
  const yes = hasFlag("--yes", args) || hasFlag("-y", args);
  const dryRun = hasFlag("--dry-run", args);
  const setSecret = hasFlag("--set-secret", args);

  // Determine platform
  let platform = args[0] as string | undefined;
  if (
    platform &&
    !["github-action", "gitlab-ci", "bitbucket-pipelines"].includes(platform)
  ) {
    platform = undefined;
  }

  if (!platform) {
    platform = detectPlatform(cwd) ?? undefined;
    if (!platform) {
      if (yes) {
        platform = "github-action";
      } else {
        console.log("Could not auto-detect CI platform.");
        console.log(
          "Specify one of: github-action, gitlab-ci, bitbucket-pipelines",
        );
        console.log("\nExample: pensar init github-action");
        process.exit(1);
      }
    }
    console.log(`Detected CI platform: ${platform}`);
  }

  // Resolve options
  const trigger = (getFlag("--trigger", args) ?? "push") as Trigger;
  const branchesArg = getFlag("--branches", args);
  const branches = branchesArg
    ? branchesArg.split(",").map((b) => b.trim())
    : [detectDefaultBranch(cwd)];
  const level = (getFlag("--level", args) ?? "full") as "priority" | "full";

  const opts: WorkflowOptions = { trigger, branches, level };

  // Generate content
  let content: string;
  let outputPath: string;

  switch (platform) {
    case "github-action": {
      content = generateGitHubAction(opts);
      outputPath = path.join(cwd, ".github", "workflows", "pensar.yml");
      break;
    }
    case "gitlab-ci": {
      content = generateGitLabCI(opts);
      outputPath = path.join(cwd, ".gitlab-ci.yml");
      break;
    }
    case "bitbucket-pipelines": {
      content = generateBitbucket(opts);
      outputPath = path.join(cwd, "bitbucket-pipelines.yml");
      break;
    }
    default: {
      console.error(`Unknown platform: ${platform}`);
      process.exit(1);
    }
  }

  if (dryRun) {
    console.log(`\n--- ${outputPath} ---\n`);
    console.log(content);
    console.log(`--- .pensar/config.json ---\n`);
    console.log(generatePensarConfig());
    return;
  }

  // Write workflow file
  const outputDir = path.dirname(outputPath);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  if (fs.existsSync(outputPath) && !yes) {
    console.log(`File already exists: ${outputPath}`);
    console.log("Use --yes to overwrite, or --dry-run to preview.");
    process.exit(1);
  }

  fs.writeFileSync(outputPath, content, "utf-8");
  console.log(`Created ${path.relative(cwd, outputPath)}`);

  // Write .pensar/config.json
  const configDir = path.join(cwd, ".pensar");
  const configPath = path.join(configDir, "config.json");
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }
  fs.writeFileSync(configPath, generatePensarConfig(), "utf-8");
  console.log(`Created ${path.relative(cwd, configPath)}`);

  // Set GitHub secret if requested
  if (setSecret && platform === "github-action") {
    try {
      const { execSync, spawnSync } = await import("child_process");
      execSync("gh --version", { stdio: "ignore" });
      console.log("\nSetting PENSAR_API_KEY as GitHub repository secret...");
      console.log("You will be prompted for the value:");
      const result = spawnSync("gh", ["secret", "set", "PENSAR_API_KEY"], {
        stdio: "inherit",
        cwd,
      });
      if (result.status === 0) {
        console.log("Secret set successfully.");
      } else {
        console.warn(
          "Failed to set secret. Set it manually in GitHub Settings > Secrets.",
        );
      }
    } catch {
      console.warn(
        "GitHub CLI (gh) not found. Set PENSAR_API_KEY manually in GitHub Settings > Secrets and variables > Actions.",
      );
    }
  }

  // Print next steps
  console.log(`
Next steps:
  1. Add PENSAR_API_KEY to your repository secrets
     GitHub: Settings > Secrets and variables > Actions > New repository secret
  2. Push the workflow file to trigger your first pentest
  3. View results at https://console.pensar.dev
`);
}

main();
