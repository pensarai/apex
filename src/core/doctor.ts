import { execSync, spawnSync } from "child_process";
import readline from "readline";
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
  process.stdout.write("\n");
  process.stdout.write("Pensar Doctor\n");
  process.stdout.write("=============\n");
  process.stdout.write("\n");

  // --- nmap check ---
  process.stdout.write("System Tools\n");
  process.stdout.write("------------\n");

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
    process.stdout.write(
      `  ✓ nmap ${version ? `(${version})` : "installed"}\n`,
    );
  } else {
    process.stdout.write(
      "  ✗ nmap — not found (recommended for network scanning)\n",
    );
  }

  process.stdout.write("\n");

  // --- API key check ---
  process.stdout.write("AI Providers\n");
  process.stdout.write("------------\n");

  const apiKeys = checkApiKeys();
  const anyConfigured = apiKeys.some((k) => k.configured);

  for (const key of apiKeys) {
    const icon = key.configured ? "✓" : "·";
    process.stdout.write(`  ${icon} ${key.provider}\n`);
  }

  if (!anyConfigured) {
    process.stdout.write("\n");
    process.stdout.write(
      "  No AI provider configured. Set at least one API key to get started:\n",
    );
    process.stdout.write("    export ANTHROPIC_API_KEY=your-key-here\n");
  }

  process.stdout.write("\n");

  // --- Offer to install nmap ---
  if (!nmapInstalled) {
    const pm = detectPackageManager();
    if (pm) {
      const answer = await prompt(
        `Install nmap via ${pm.name}? (${pm.installCmd}) [y/N] `,
      );
      if (/^y(es)?$/i.test(answer)) {
        process.stdout.write("\n");
        const result = spawnSync(pm.installCmd, {
          stdio: "inherit",
          shell: true,
        });
        process.stdout.write("\n");
        if (result.status === 0) {
          process.stdout.write("✓ nmap installed successfully!\n");
        } else {
          process.stdout.write(
            "✗ Installation failed. You can install manually:\n",
          );
          process.stdout.write(`    ${pm.installCmd}\n`);
        }
      } else {
        process.stdout.write("  Skipped nmap installation.\n");
      }
    } else {
      process.stdout.write(
        "  No supported package manager found. Install nmap manually:\n",
      );
      process.stdout.write("    https://nmap.org/download.html\n");
    }
    process.stdout.write("\n");
  }
}
