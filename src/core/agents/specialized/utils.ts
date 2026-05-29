import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { getBundledWordlists } from "../../assets/wordlists";

type DetectedEnvironment = {
  isDocker: boolean;
  isKali: boolean;
  prettyName?: string;
  idLike?: string;
  availableTools: string[];
  missingTools: string[];
};

function readOsRelease(): Record<string, string> {
  try {
    const content = readFileSync("/etc/os-release", "utf8");
    const lines = content.split(/\r?\n/);
    const map: Record<string, string> = {};
    for (const line of lines) {
      const idx = line.indexOf("=");
      if (idx === -1) continue;
      const key = line.slice(0, idx);
      let value = line.slice(idx + 1);
      if (value.startsWith('"') && value.endsWith('"')) {
        value = value.slice(1, -1);
      }
      map[key] = value;
    }
    return map;
  } catch {
    return {};
  }
}

function detectDocker(): boolean {
  try {
    if (existsSync("/.dockerenv")) return true;
  } catch {
    // ignored
  }
  try {
    const cgroup = readFileSync("/proc/1/cgroup", "utf8");
    if (/docker|containerd|kubepods/i.test(cgroup)) return true;
  } catch {
    // ignored
  }
  return false;
}

export function toolExists(commandName: string): boolean {
  try {
    // Prefer a POSIX-compliant lookup via the shell builtin
    execSync(`command -v ${commandName} >/dev/null 2>&1`, {
      stdio: "ignore",
      shell: "/bin/bash",
    });
    return true;
  } catch {
    try {
      execSync(`which ${commandName} >/dev/null 2>&1`, {
        stdio: "ignore",
        shell: "/bin/bash",
      });
      return true;
    } catch {
      return false;
    }
  }
}

function detectEnvironment(): DetectedEnvironment {
  const osRelease = readOsRelease();
  const prettyName = osRelease["PRETTY_NAME"];
  const id = osRelease["ID"]?.toLowerCase();
  const idLike = osRelease["ID_LIKE"];

  const isKali = Boolean(
    (id && /kali/.test(id)) || (prettyName && /kali/i.test(prettyName)),
  );
  const isDocker = detectDocker();

  const toolsToCheck = [
    "nmap",
    "gobuster",
    "sqlmap",
    "nikto",
    "hydra",
    "john",
    "hashcat",
    "tcpdump",
    "tshark",
    "nc",
    "socat",
    "curl",
    "wget",
    "git",
  ];

  const availableTools: string[] = [];
  const missingTools: string[] = [];
  for (const tool of toolsToCheck) {
    (toolExists(tool) ? availableTools : missingTools).push(tool);
  }

  return { isDocker, isKali, prettyName, idLike, availableTools, missingTools };
}

function buildBundledAssetsBlock(): string | null {
  const wordlists = getBundledWordlists();
  if (wordlists === null) return null;

  return `[BUNDLED ASSETS]
This block is your authoritative inventory of wordlist assets shipped with the CLI. When the user asks what wordlists / assets / capabilities you have, answer directly from the entries below — do NOT probe the filesystem (\`ls /usr/share/wordlists\`, \`which gobuster\`, \`find / -name wordlists\`, etc.). Those paths are not where these live; the inventory is here.

TINY_WORDLIST=${wordlists.tiny} (~200 entries — smoke checks / time-pressured runs)
DEFAULT_WORDLIST=${wordlists.common} (~4.7k entries — normal recon, the default)
LARGE_WORDLIST=${wordlists.large} (~30k entries — escalation only)

These paths can be passed as \`-w\` arguments to gobuster/ffuf/dirb/wfuzz/dirsearch, OR iterated line-by-line in shell loops and \`http_request\` scripts. Their presence is NOT a reason to run a wordlist-based tool; choose techniques based on the task.

If you do invoke a wordlist-based tool: default to DEFAULT_WORDLIST. Use TINY only under explicit time pressure or for a first-pass smoke probe. Use LARGE only after DEFAULT finishes and the target still looks under-mapped, or when the user explicitly asked for a deeper scan. Do NOT chain tiers automatically. Do NOT assume /usr/share/wordlists/* exists — it is missing on macOS, Alpine, most Docker images, and CI.
[/BUNDLED ASSETS]`;
}

export function detectOSAndEnhancePrompt(prompt: string): string {
  try {
    const env = detectEnvironment();
    const lines: string[] = [];
    lines.push("[ENV CONTEXT]");
    lines.push(
      `OS: ${env.prettyName ?? process.platform} | InDocker: ${
        env.isDocker ? "yes" : "no"
      } | Kali: ${env.isKali ? "yes" : "no"}`,
    );
    if (env.availableTools.length > 0) {
      lines.push(`Tools available: ${env.availableTools.sort().join(", ")}`);
    }
    if (env.missingTools.length > 0) {
      lines.push(`Tools missing: ${env.missingTools.sort().join(", ")}`);
    }
    lines.push("[/ENV CONTEXT]");

    const bundledAssetsBlock = buildBundledAssetsBlock();
    if (bundledAssetsBlock !== null) {
      lines.push("");
      lines.push(bundledAssetsBlock);
    }
    lines.push("");

    return `${lines.join("\n")}\n${prompt}`;
  } catch (error) {
    console.error("Error detecting environment:", error);
    return prompt;
  }
}
