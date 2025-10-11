import { readFileSync, existsSync } from "fs";
import { execSync } from "child_process";

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
  } catch {}
  try {
    const cgroup = readFileSync("/proc/1/cgroup", "utf8");
    if (/docker|containerd|kubepods/i.test(cgroup)) return true;
  } catch {}
  return false;
}

function toolExists(commandName: string): boolean {
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
    (id && /kali/.test(id)) || (prettyName && /kali/i.test(prettyName))
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

export function detectOSAndEnhancePrompt(prompt: string): string {
  try {
    const env = detectEnvironment();
    const lines: string[] = [];
    lines.push("[ENV CONTEXT]");
    lines.push(
      `OS: ${env.prettyName ?? process.platform} | InDocker: ${
        env.isDocker ? "yes" : "no"
      } | Kali: ${env.isKali ? "yes" : "no"}`
    );
    if (env.availableTools.length > 0) {
      lines.push(`Tools available: ${env.availableTools.sort().join(", ")}`);
    }
    if (env.missingTools.length > 0) {
      lines.push(`Tools missing: ${env.missingTools.sort().join(", ")}`);
    }
    lines.push("[/ENV CONTEXT]\n");
    return `${lines.join("\n")}\n${prompt}`;
  } catch (error) {
    console.error("Error detecting environment:", error);
    return prompt;
  }
}
