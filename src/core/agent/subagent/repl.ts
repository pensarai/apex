import { join } from "path";
import { existsSync, mkdirSync, unlinkSync, writeFileSync, chmodSync } from "fs";
import { nanoid } from "nanoid";

export interface ScriptExecutionOpts {
  language: "bun" | "python";
  code: string;
  timeout?: number;
  workingDir?: string;
  env?: Record<string, string>;
}

export interface ScriptExecutionResult {
  success: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
  error?: string;
  scriptPath?: string;
}

const DEFAULT_TIMEOUT = 60000;

export async function executeScript(
  opts: ScriptExecutionOpts
): Promise<ScriptExecutionResult> {
  const { language, code, timeout = DEFAULT_TIMEOUT, workingDir, env } = opts;

  const tempDir = workingDir || "/tmp/apex-scripts";
  if (!existsSync(tempDir)) {
    mkdirSync(tempDir, { recursive: true });
  }

  const scriptId = nanoid(8);
  const extension = language === "bun" ? ".ts" : ".py";
  const scriptPath = join(tempDir, `script-${scriptId}${extension}`);

  try {
    writeFileSync(scriptPath, code, "utf-8");
    chmodSync(scriptPath, 0o755);

    const command = language === "bun"
      ? ["bun", "run", scriptPath]
      : ["python3", scriptPath];

    const proc = Bun.spawn(command, {
      cwd: workingDir,
      env: { ...process.env, ...env },
      stdout: "pipe",
      stderr: "pipe",
    });

    const timeoutId = setTimeout(() => {
      proc.kill();
    }, timeout);

    const [stdout, stderr] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);

    clearTimeout(timeoutId);
    const exitCode = await proc.exited;

    return {
      success: exitCode === 0,
      stdout: stdout.trim(),
      stderr: stderr.trim(),
      exitCode,
      scriptPath,
    };
  } catch (error: any) {
    return {
      success: false,
      stdout: "",
      stderr: error.message || "Script execution failed",
      exitCode: 1,
      error: error.message,
    };
  } finally {
    try {
      if (existsSync(scriptPath)) {
        unlinkSync(scriptPath);
      }
    } catch {}
  }
}

export async function executeScriptPersistent(
  opts: ScriptExecutionOpts & { scriptName: string; persistDir: string }
): Promise<ScriptExecutionResult> {
  const { language, code, timeout = DEFAULT_TIMEOUT, workingDir, env, scriptName, persistDir } = opts;

  if (!existsSync(persistDir)) {
    mkdirSync(persistDir, { recursive: true });
  }

  const extension = language === "bun" ? ".ts" : ".py";
  const sanitizedName = scriptName.replace(/[^a-z0-9_-]/gi, "_");
  const scriptPath = join(persistDir, `${sanitizedName}${extension}`);

  try {
    writeFileSync(scriptPath, code, "utf-8");
    chmodSync(scriptPath, 0o755);

    const command = language === "bun"
      ? ["bun", "run", scriptPath]
      : ["python3", scriptPath];

    const proc = Bun.spawn(command, {
      cwd: workingDir || persistDir,
      env: { ...process.env, ...env },
      stdout: "pipe",
      stderr: "pipe",
    });

    const timeoutId = setTimeout(() => {
      proc.kill();
    }, timeout);

    const [stdout, stderr] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);

    clearTimeout(timeoutId);
    const exitCode = await proc.exited;

    return {
      success: exitCode === 0,
      stdout: stdout.trim(),
      stderr: stderr.trim(),
      exitCode,
      scriptPath,
    };
  } catch (error: any) {
    return {
      success: false,
      stdout: "",
      stderr: error.message || "Script execution failed",
      exitCode: 1,
      error: error.message,
      scriptPath,
    };
  }
}
