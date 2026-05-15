#!/usr/bin/env bun
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export type ScannerTool =
  | "semgrep"
  | "gitleaks"
  | "osv-scanner"
  | "trivy-fs"
  | "bandit"
  | "gosec"
  | "cargo-audit"
  | "pip-audit"
  | "npm-audit"
  | "trufflehog";

export interface ScannerInvocation {
  bin: string;
  args: string[];
  cwd?: string;
  /** Set when the tool writes its output to stdout instead of an --output flag. */
  captureStdout?: boolean;
  /** Returns a reason string when the tool cannot run (e.g. missing lockfile). */
  precondition?: () => string | null;
}

export interface ScannerResult {
  tool: ScannerTool | string;
  config: string;
  output?: string;
  error?: string;
}

function lockfileRequired(codebase: string, file: string): string | null {
  return existsSync(join(codebase, file)) ? null : `no ${file} at ${codebase}`;
}

function manifestRequired(codebase: string, file: string): string | null {
  return existsSync(join(codebase, file)) ? null : `no ${file} at ${codebase}`;
}

type RecipeBuilder = (
  codebase: string,
  config: string,
  output: string,
) => ScannerInvocation;

const RECIPES: Record<ScannerTool, { bin: string; build: RecipeBuilder }> = {
  semgrep: {
    bin: "semgrep",
    build: (codebase, config, output) => ({
      bin: "semgrep",
      args: [
        "--config",
        config === "-" ? "p/security-audit" : config,
        "--json",
        "--quiet",
        "--timeout",
        "300",
        "--max-target-bytes",
        "5000000",
        "--output",
        output,
        codebase,
      ],
    }),
  },
  gitleaks: {
    bin: "gitleaks",
    build: (codebase, config, output) => {
      const args = [
        "detect",
        "--source",
        codebase,
        "--no-banner",
        "--report-format",
        "json",
        "--report-path",
        output,
        "--exit-code",
        "0",
      ];
      if (config !== "-" && config) args.push("--config", config);
      return { bin: "gitleaks", args };
    },
  },
  "osv-scanner": {
    bin: "osv-scanner",
    build: (codebase, _config, output) => ({
      bin: "osv-scanner",
      args: ["--recursive", "--format", "json", "--output", output, codebase],
    }),
  },
  "trivy-fs": {
    bin: "trivy",
    build: (codebase, _config, output) => ({
      bin: "trivy",
      args: ["fs", "--quiet", "--format", "json", "--output", output, codebase],
    }),
  },
  bandit: {
    bin: "bandit",
    build: (codebase, config, output) => {
      const args = ["-r", codebase, "-f", "json", "-o", output, "--quiet"];
      if (config !== "-" && config) args.push("-c", config);
      return { bin: "bandit", args };
    },
  },
  gosec: {
    bin: "gosec",
    build: (codebase, _config, output) => ({
      bin: "gosec",
      args: ["-quiet", `-fmt=json`, `-out=${output}`, `${codebase}/...`],
    }),
  },
  "cargo-audit": {
    bin: "cargo-audit",
    build: (codebase, _config, output) => ({
      bin: "cargo-audit",
      args: ["audit", "--json"],
      cwd: codebase,
      captureStdout: true,
      precondition: () => lockfileRequired(codebase, "Cargo.lock"),
    }),
  },
  "pip-audit": {
    bin: "pip-audit",
    build: (codebase, config, output) => {
      const args = ["--format", "json", "--output", output];
      if (config !== "-" && existsSync(config)) {
        args.push("--requirement", config);
      } else if (existsSync(join(codebase, "requirements.txt"))) {
        args.push("--requirement", join(codebase, "requirements.txt"));
      } else {
        args.push("--strict");
      }
      return { bin: "pip-audit", args };
    },
  },
  "npm-audit": {
    bin: "npm",
    build: (codebase, _config, _output) => ({
      bin: "npm",
      args: ["audit", "--json"],
      cwd: codebase,
      captureStdout: true,
      precondition: () => manifestRequired(codebase, "package.json"),
    }),
  },
  trufflehog: {
    bin: "trufflehog",
    build: (codebase, _config, _output) => ({
      bin: "trufflehog",
      args: ["filesystem", codebase, "--json", "--no-update"],
      captureStdout: true,
    }),
  },
};

function isOnPath(bin: string): boolean {
  try {
    return (
      spawnSync("command", ["-v", bin], { shell: true, stdio: "ignore" })
        .status === 0
    );
  } catch {
    return false;
  }
}

// "Not installed" and "precondition failed" are returned as structured
// errors with exit 0 so the agent can skip rather than fail.
export function runScanner(
  tool: ScannerTool,
  codebase: string,
  config: string,
  output: string,
): ScannerResult {
  const recipe = RECIPES[tool];
  if (!recipe) {
    return { tool, config, error: `unknown tool: ${tool}` };
  }
  if (!isOnPath(recipe.bin)) {
    return { tool, config, error: `${recipe.bin} not installed`, output };
  }
  const invocation = recipe.build(codebase, config, output);
  const preconditionError = invocation.precondition?.();
  if (preconditionError) {
    return { tool, config, error: preconditionError, output };
  }
  mkdirSync(dirname(output), { recursive: true });

  const result = spawnSync(invocation.bin, invocation.args, {
    cwd: invocation.cwd,
    encoding: "utf-8",
  });

  if (invocation.captureStdout) {
    writeFileSync(output, result.stdout ?? "");
  }
  return { tool, config, output };
}

function parseArgs(argv: string[]): {
  tool: string;
  codebase: string;
  output: string;
  config: string;
} {
  let tool = "";
  let codebase = "";
  let output = "";
  let config = "-";
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--tool") tool = argv[++i] ?? "";
    else if (a === "--codebase") codebase = argv[++i] ?? "";
    else if (a === "--output") output = argv[++i] ?? "";
    else if (a === "--config") config = argv[++i] ?? "-";
  }
  if (!tool || !codebase || !output) {
    throw new Error(
      "Usage: bun scanners.ts --tool <tool> --codebase <path> --output <path> [--config <value>]",
    );
  }
  return { tool, codebase, output, config };
}

const SUPPORTED = Object.keys(RECIPES) as ScannerTool[];

function isCli(): boolean {
  return /scanners\.(ts|js)$/.test(process.argv[1] ?? "");
}

if (isCli()) {
  const { tool, codebase, output, config } = parseArgs(process.argv.slice(2));
  if (!SUPPORTED.includes(tool as ScannerTool)) {
    process.stderr.write(
      `Unknown tool "${tool}". Supported: ${SUPPORTED.join(", ")}\n`,
    );
    process.exit(2);
  }
  const result = runScanner(tool as ScannerTool, codebase, config, output);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
