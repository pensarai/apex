import { tool } from "ai";
import { z } from "zod";
import { execSync } from "child_process";
import type { ToolContext } from "./types";

const PS_CMD = "ps -eo pid,ppid,user,stat,command --no-headers";
const DEFAULT_DURATION_SEC = 10;
const DEFAULT_INTERVAL_SEC = 2;
const MAX_DURATION_SEC = 60;

export const observeProcessesInputSchema = z.object({
  durationSeconds: z
    .number()
    .int()
    .positive()
    .max(MAX_DURATION_SEC)
    .optional()
    .describe(
      `How long to watch for new processes, in seconds (default ${DEFAULT_DURATION_SEC}, max ${MAX_DURATION_SEC}).`,
    ),
  intervalSeconds: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(
      `Poll interval in seconds (default ${DEFAULT_INTERVAL_SEC}). Lower = finer resolution but more sandbox CPU.`,
    ),
  includeKernelThreads: z
    .boolean()
    .optional()
    .describe(
      "Whether to include kernel threads (\\[kthreadd\\] style, typically noise). Default: false.",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Watching for new processes while the artifact runs')",
    ),
});

export type ObserveProcessesInput = z.infer<
  typeof observeProcessesInputSchema
>;

type ProcessRow = {
  pid: number;
  ppid: number;
  user: string;
  stat: string;
  command: string;
};

export type ObserveProcessesResult = {
  success: boolean;
  snapshotCount: number;
  durationMs: number;
  newProcesses: ProcessRow[];
  error?: string;
};

function parsePs(raw: string, includeKernel: boolean): Map<number, ProcessRow> {
  const byPid = new Map<number, ProcessRow>();
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    const m = line.match(/^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$/);
    if (!m) continue;
    const pid = parseInt(m[1], 10);
    const ppid = parseInt(m[2], 10);
    const user = m[3];
    const stat = m[4];
    const command = m[5];
    if (!includeKernel && command.startsWith("[") && command.endsWith("]")) {
      continue;
    }
    byPid.set(pid, { pid, ppid, user, stat, command });
  }
  return byPid;
}

async function snapshot(ctx: ToolContext): Promise<string> {
  if (ctx.sandbox) {
    const r = await ctx.sandbox.execute(PS_CMD, { timeout: 10 });
    if (!r.success) throw new Error(`ps failed: ${r.stderr || r.stdout}`);
    return r.stdout;
  }
  return execSync(PS_CMD, { encoding: "utf8" });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function observeProcesses(ctx: ToolContext) {
  return tool({
    description: `Poll the sandbox process table at a fixed interval for a bounded duration and emit a \`process_spawn\` detection event for every process that appears between polls.

Use after triggering some effect inside the sandbox (extraction, execution
of a binary, launching a dev server) and you want to see what new processes
the action spawned. Grounded: events are emitted from real \`ps\` output —
there is no guesswork.

Limitations:
  • Polling-based: short-lived processes may be missed between intervals.
  • Kernel-level evasion (hidden PIDs, LD_PRELOAD hiding) is NOT detected.
  • Runs \`ps\` inside the sandbox when one is wired, else locally.`,
    inputSchema: observeProcessesInputSchema,
    execute: async (input): Promise<ObserveProcessesResult> => {
      const duration = Math.min(
        input.durationSeconds ?? DEFAULT_DURATION_SEC,
        MAX_DURATION_SEC,
      );
      const interval = Math.max(1, input.intervalSeconds ?? DEFAULT_INTERVAL_SEC);
      const includeKernel = input.includeKernelThreads ?? false;
      const startedAt = Date.now();
      const deadline = startedAt + duration * 1000;
      const seen = new Set<number>();
      let snapshotCount = 0;
      const newProcesses: ProcessRow[] = [];

      try {
        // Initial snapshot establishes baseline.
        const baseline = parsePs(await snapshot(ctx), includeKernel);
        snapshotCount++;
        for (const pid of baseline.keys()) seen.add(pid);

        while (Date.now() < deadline) {
          await sleep(Math.min(interval * 1000, deadline - Date.now()));
          const current = parsePs(await snapshot(ctx), includeKernel);
          snapshotCount++;
          for (const [pid, row] of current) {
            if (seen.has(pid)) continue;
            seen.add(pid);
            newProcesses.push(row);
            ctx.eventBus?.emit("detection_event", {
              kind: "process_spawn",
              severity: "medium",
              source: "sandbox",
              summary: `Process spawned: pid=${row.pid} user=${row.user} cmd=${row.command.slice(0, 140)}`,
              data: {
                pid: row.pid,
                ppid: row.ppid,
                user: row.user,
                state: row.stat,
                command: row.command,
              },
            });
          }
        }

        return {
          success: true,
          snapshotCount,
          durationMs: Date.now() - startedAt,
          newProcesses,
        };
      } catch (error) {
        return {
          success: false,
          snapshotCount,
          durationMs: Date.now() - startedAt,
          newProcesses,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}
