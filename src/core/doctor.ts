import { execSync, spawnSync } from "node:child_process";
import readline from "node:readline";
import { toolExists } from "./agents/specialized/utils.js";

function detectPackageManager(): { name: string; installCmd: string } | null {
  const platform = process.platform;

  if (platform === "darwin" && toolExists("brew")) {
    return { name: "Homebrew", installCmd: "brew install nmap" };
  }
  if (toolExists("apt-get")) {
    return {
      name: "apt",
      installCmd: "sudo apt-get update && sudo apt-get install -y nmap",
    };
  }
  if (toolExists("dnf")) {
    return { name: "dnf", installCmd: "sudo dnf install -y nmap" };
  }
  if (toolExists("pacman")) {
    return { name: "pacman", installCmd: "sudo pacman -S --noconfirm nmap" };
  }
  return null;
}

function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function checkApiKeys(): { provider: string; configured: boolean }[] {
  const keys: { provider: string; env: string }[] = [
    { provider: "Anthropic", env: "ANTHROPIC_API_KEY" },
    { provider: "OpenAI", env: "OPENAI_API_KEY" },
    { provider: "Google", env: "GOOGLE_GENERATIVE_AI_API_KEY" },
    { provider: "OpenRouter", env: "OPENROUTER_API_KEY" },
    { provider: "Concentrate", env: "CONCENTRATE_API_KEY" },
    { provider: "AWS Bedrock", env: "BEDROCK_API_KEY" },
    { provider: "AWS IAM", env: "AWS_ACCESS_KEY_ID" },
    { provider: "vLLM (local)", env: "LOCAL_MODEL_URL" },
  ];

  return keys.map(({ provider, env }) => ({
    provider,
    configured: Boolean(process.env[env]),
  }));
}

export async function runDoctor(): Promise<void> {
  console.log();
  console.log("Pensar Doctor");
  console.log("=============");
  console.log();

  // --- nmap check ---
  console.log("System Tools");
  console.log("------------");

  const nmapInstalled = toolExists("nmap");
  if (nmapInstalled) {
    let version = "";
    try {
      version =
        execSync("nmap --version", { encoding: "utf-8" })
          .split("\n")[0]
          ?.trim() ?? "";
    } catch {
      // ignore
    }
    console.log(`  ✓ nmap ${version ? `(${version})` : "installed"}`);
  } else {
    console.log("  ✗ nmap — not found (recommended for network scanning)");
  }

  console.log();

  // --- API key check ---
  console.log("AI Providers");
  console.log("------------");

  const apiKeys = checkApiKeys();
  const anyConfigured = apiKeys.some((k) => k.configured);

  for (const key of apiKeys) {
    const icon = key.configured ? "✓" : "·";
    console.log(`  ${icon} ${key.provider}`);
  }

  if (!anyConfigured) {
    console.log();
    console.log(
      "  No AI provider configured. Set at least one API key to get started:",
    );
    console.log("    export ANTHROPIC_API_KEY=your-key-here");
  }

  console.log();

  // --- Offer to install nmap ---
  if (!nmapInstalled) {
    const pm = detectPackageManager();
    if (pm) {
      const answer = await prompt(
        `Install nmap via ${pm.name}? (${pm.installCmd}) [y/N] `,
      );
      if (/^y(es)?$/i.test(answer)) {
        console.log();
        const result = spawnSync(pm.installCmd, {
          stdio: "inherit",
          shell: true,
        });
        console.log();
        if (result.status === 0) {
          console.log("✓ nmap installed successfully!");
        } else {
          console.log("✗ Installation failed. You can install manually:");
          console.log(`    ${pm.installCmd}`);
        }
      } else {
        console.log("  Skipped nmap installation.");
      }
    } else {
      console.log(
        "  No supported package manager found. Install nmap manually:",
      );
      console.log("    https://nmap.org/download.html");
    }
    console.log();
  }
}
