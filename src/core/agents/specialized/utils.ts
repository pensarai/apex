import { execSync } from "node:child_process";

/**
 * Host-side tool lookup for diagnostics (`src/core/doctor.ts`): checks the
 * machine Apex itself runs on. Prompt-level runtime facts now come from the
 * agent's actual command backend instead — see
 * `src/core/agents/offSecAgent/runtimeContext.ts`.
 */
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
