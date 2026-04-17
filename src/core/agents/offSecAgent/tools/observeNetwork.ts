import { tool } from "ai";
import { z } from "zod";
import { execSync } from "child_process";
import type { ToolContext } from "./types";

const SS_CMD = "ss -tupna 2>/dev/null || netstat -tupna";
const DEFAULT_DURATION_SEC = 10;
const DEFAULT_INTERVAL_SEC = 2;
const MAX_DURATION_SEC = 60;

export const observeNetworkInputSchema = z.object({
  durationSeconds: z
    .number()
    .int()
    .positive()
    .max(MAX_DURATION_SEC)
    .optional()
    .describe(
      `How long to watch for new sockets (default ${DEFAULT_DURATION_SEC}s, max ${MAX_DURATION_SEC}s).`,
    ),
  intervalSeconds: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(`Poll interval in seconds (default ${DEFAULT_INTERVAL_SEC}).`),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Watching for outbound connections during artifact execution')",
    ),
});

export type ObserveNetworkInput = z.infer<typeof observeNetworkInputSchema>;

type Conn = {
  proto: string;
  localAddr: string;
  remoteAddr: string;
  state: string;
  process?: string;
};

export type ObserveNetworkResult = {
  success: boolean;
  snapshotCount: number;
  durationMs: number;
  newConnections: Conn[];
  error?: string;
};

/**
 * Parse `ss -tupna` output. Columns: Netid, State, Recv-Q, Send-Q,
 * Local Address:Port, Peer Address:Port, Process. Tolerates the netstat
 * fallback format too (different column ordering but similar fields).
 */
function parseSs(raw: string): Conn[] {
  const lines = raw.split("\n");
  const conns: Conn[] = [];
  for (const line of lines) {
    if (!line.trim() || /^(Netid|Proto|Active)/.test(line)) continue;
    const cols = line.trim().split(/\s+/);
    if (cols.length < 5) continue;
    // Accept ss format: netid state rq sq local peer [process]
    const proto = cols[0];
    if (!/^(tcp|udp)/i.test(proto)) continue;
    const state = cols[1];
    const localAddr = cols[4];
    const remoteAddr = cols[5];
    if (!localAddr || !remoteAddr) continue;
    const process = cols.slice(6).join(" ") || undefined;
    conns.push({ proto, localAddr, remoteAddr, state, process });
  }
  return conns;
}

function keyFor(c: Conn): string {
  return `${c.proto}|${c.localAddr}|${c.remoteAddr}|${c.state}`;
}

async function snapshot(ctx: ToolContext): Promise<string> {
  if (ctx.sandbox) {
    const r = await ctx.sandbox.execute(SS_CMD, { timeout: 10 });
    if (!r.success) throw new Error(`ss failed: ${r.stderr || r.stdout}`);
    return r.stdout;
  }
  return execSync(SS_CMD, { encoding: "utf8" });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function isInternalRemote(addr: string): boolean {
  const host = addr.split(":").slice(0, -1).join(":").replace(/^\[|\]$/g, "");
  return (
    host === "" ||
    host === "0.0.0.0" ||
    host === "127.0.0.1" ||
    host === "*" ||
    host === "::" ||
    host === "::1" ||
    host.startsWith("[::1]") ||
    host.startsWith("10.") ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host) ||
    host.startsWith("192.168.")
  );
}

export function observeNetwork(ctx: ToolContext) {
  return tool({
    description: `Poll the sandbox network socket table and emit a \`network_egress\` detection event for every new outbound connection to an external host.

Grounded: events are emitted from real \`ss\`/\`netstat\` output. Uses a
reasonable internal-address heuristic (RFC1918, loopback, :: or 0.0.0.0
are considered internal and skipped) so local dev-server ports don't
trigger false positives.

Use after triggering an action inside the sandbox that you suspect might
phone home (artifact execution, extracted binary launch, follow-up probe).`,
    inputSchema: observeNetworkInputSchema,
    execute: async (input): Promise<ObserveNetworkResult> => {
      const duration = Math.min(
        input.durationSeconds ?? DEFAULT_DURATION_SEC,
        MAX_DURATION_SEC,
      );
      const interval = Math.max(1, input.intervalSeconds ?? DEFAULT_INTERVAL_SEC);
      const startedAt = Date.now();
      const deadline = startedAt + duration * 1000;
      const seen = new Set<string>();
      let snapshotCount = 0;
      const newConnections: Conn[] = [];

      try {
        const baseline = parseSs(await snapshot(ctx));
        snapshotCount++;
        for (const c of baseline) seen.add(keyFor(c));

        while (Date.now() < deadline) {
          await sleep(Math.min(interval * 1000, deadline - Date.now()));
          const current = parseSs(await snapshot(ctx));
          snapshotCount++;
          for (const c of current) {
            const k = keyFor(c);
            if (seen.has(k)) continue;
            seen.add(k);
            if (isInternalRemote(c.remoteAddr)) continue;
            newConnections.push(c);
            ctx.eventBus?.emit("detection_event", {
              kind: "network_egress",
              severity: "high",
              source: "sandbox",
              summary: `Outbound ${c.proto} connection to ${c.remoteAddr} (state=${c.state})`,
              data: {
                proto: c.proto,
                localAddr: c.localAddr,
                remoteAddr: c.remoteAddr,
                state: c.state,
                process: c.process,
              },
            });
          }
        }

        return {
          success: true,
          snapshotCount,
          durationMs: Date.now() - startedAt,
          newConnections,
        };
      } catch (error) {
        return {
          success: false,
          snapshotCount,
          durationMs: Date.now() - startedAt,
          newConnections,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}
