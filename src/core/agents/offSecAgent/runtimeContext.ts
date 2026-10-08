import { createHash } from "node:crypto";
import { getBundledWordlists } from "../../assets/wordlists";
import { resolveBackends } from "../../tools/backends/resolve";
import type {
  CommandEvent,
  RunOpts,
  ToolBackends,
} from "../../tools/backends/types";
import type { UnifiedSandbox } from "./tools/sandbox";
import type { ToolContext } from "./tools/types";

/**
 * Runtime execution facts, probed through the agent's actual command backend
 * with the configured execution env — never the host process. A failed,
 * timed-out, or truncated probe yields {@link UNKNOWN_FACTS}: unknown, not
 * absent, and not retained.
 */
export interface RuntimeExecutionFacts {
  /** False when the probe failed, timed out, was aborted, or came back truncated. */
  probed: boolean;
  /** `uname -sr` from the execution environment. */
  os?: string;
  available: string[];
  missing: string[];
}

export const UNKNOWN_FACTS: RuntimeExecutionFacts = {
  probed: false,
  available: [],
  missing: [],
};

/** Tools whose presence changes technique choice. */
export const PROBE_TOOL_NAMES = [
  "bash",
  "sh",
  "python3",
  "python",
  "node",
  "ffuf",
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
] as const;

const PROBE_TIMEOUT_SECONDS = 10;
// Runaway guard only — the probe emits ~600 B; hitting the cap (or a backend
// truncation flag) invalidates the probe.
const MAX_PROBE_OUTPUT_BYTES = 16 * 1024;

function posixProbeCommand(): string {
  const checks = PROBE_TOOL_NAMES.map(
    (t) =>
      `if command -v ${t} >/dev/null 2>&1; then echo "AVAIL ${t}"; else echo "MISSING ${t}"; fi`,
  ).join("; ");
  // Every branch succeeds, so a missing tool never fails the probe.
  return `${checks}; echo "OS: $(uname -sr 2>/dev/null)"`;
}

function windowsProbeCommand(): string {
  const checks = PROBE_TOOL_NAMES.map(
    (t) => `where ${t} >nul 2>&1 && echo AVAIL ${t} || echo MISSING ${t}`,
  ).join(" & ");
  // `ver` is a cmd built-in — no new interpreter, always succeeds — so a
  // missing tool still cannot fail the probe. A bare `OS:` marker line lets
  // the parser take ver's next line verbatim instead of pattern-matching
  // its (locale-dependent) text.
  return `${checks} & echo OS: & ver`;
}

function parseProbeOutput(output: string): RuntimeExecutionFacts {
  const available: string[] = [];
  const missing: string[] = [];
  let os: string | undefined;
  let osPending = false;

  for (const rawLine of output.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    // Windows probe: a bare `OS:` marker — the next non-empty line is ver's
    // output, captured verbatim.
    if (osPending) {
      os = line;
      osPending = false;
      continue;
    }
    if (line === "OS:") {
      osPending = true;
      continue;
    }
    const avail = /^AVAIL (\S+)$/.exec(line);
    if (avail) {
      available.push(avail[1]);
      continue;
    }
    const miss = /^MISSING (\S+)$/.exec(line);
    if (miss) {
      missing.push(miss[1]);
      continue;
    }
    const osMatch = /^OS: (.+)$/.exec(line);
    if (osMatch?.[1]) os = osMatch[1];
  }

  // A truncated or mangled probe must not read as "everything absent".
  const seen = new Set([...available, ...missing]);
  if (seen.size < PROBE_TOOL_NAMES.length) return UNKNOWN_FACTS;

  return {
    probed: true,
    ...(os ? { os } : {}),
    available: available.sort(),
    missing: missing.sort(),
  };
}

async function runProbe(ctx: ToolContext): Promise<RuntimeExecutionFacts> {
  try {
    // Shared discovery must outlive an individual agent's signal and shell.
    const backend = resolveBackends({
      ...ctx,
      abortSignal: undefined,
      commandShell: undefined,
    });
    const platform = backend.command.platform ?? "posix";
    const cmd =
      platform === "windows" ? windowsProbeCommand() : posixProbeCommand();
    // Injected transports only see RunOpts, so the configured execution env
    // must ride with the probe (the cache key is not execution env). Local
    // and sandbox paths re-merge the same values harmlessly.
    const opts: RunOpts = {
      timeoutSeconds: PROBE_TIMEOUT_SECONDS,
      abortSignal: AbortSignal.timeout(PROBE_TIMEOUT_SECONDS * 1000),
      envVars: ctx.environmentVariables,
    };

    let output = "";
    let outputTruncated = false;
    let exitCode: number | null = null;
    let timedOut = false;
    for await (const event of backend.command.run(cmd, opts)) {
      const e = event as CommandEvent;
      if (e.type === "stdout" || e.type === "stderr") {
        if (output.length >= MAX_PROBE_OUTPUT_BYTES) {
          outputTruncated = true;
        } else {
          const room = MAX_PROBE_OUTPUT_BYTES - output.length;
          output += e.bytes.slice(0, room);
          if (e.bytes.length > room) outputTruncated = true;
        }
      } else if (e.type === "end") {
        exitCode = e.exitCode;
        timedOut = e.timedOut;
        if (e.stdoutTruncated || e.stderrTruncated) outputTruncated = true;
      }
    }
    if (exitCode === null || exitCode !== 0 || timedOut || outputTruncated) {
      return UNKNOWN_FACTS;
    }
    return parseProbeOutput(output);
  } catch {
    return UNKNOWN_FACTS;
  }
}

// ---------------------------------------------------------------------------
// Cache / coalescing — one probe per distinct runtime configuration.
// ---------------------------------------------------------------------------

// Object identity per configured backend/sandbox object: workers spawned in
// one run share the parent's objects and therefore one probe; a host that
// swaps in a new backend object gets a fresh probe.
type ExecutorObject = ToolBackends | UnifiedSandbox;

const objectId = new WeakMap<ExecutorObject, number>();
let nextObjectId = 0;

function idFor(obj: ExecutorObject): number {
  let id = objectId.get(obj);
  if (id === undefined) {
    id = ++nextObjectId;
    objectId.set(obj, id);
  }
  return id;
}

// Env values can carry credential secrets; hash them so raw values are never
// retained in long-lived cache keys.
function envTag(env: Record<string, string> | undefined): string {
  if (!env || Object.keys(env).length === 0) return "";
  const sorted = JSON.stringify(
    Object.keys(env)
      .sort()
      .map((k) => [k, env[k]]),
  );
  return createHash("sha256").update(sorted).digest("hex").slice(0, 16);
}

function cacheKey(ctx: ToolContext): string {
  return [
    ctx.session.id,
    ctx.backends ? `b${idFor(ctx.backends)}` : "local",
    ctx.sandbox ? `s${idFor(ctx.sandbox)}` : "nosh",
    ctx.agentCwd,
    envTag(ctx.environmentVariables),
  ].join("|");
}

// Runaway guard only: distinct runtime configurations per process are few.
export const MAX_CACHE_ENTRIES = 32;
const factsByKey = new Map<string, Promise<RuntimeExecutionFacts>>();
// Settled snapshot for the synchronous escape hatch; bounded with factsByKey.
const settledFactsByKey = new Map<string, RuntimeExecutionFacts>();

function waitForProbe(
  pending: Promise<RuntimeExecutionFacts>,
  signal?: AbortSignal,
): Promise<RuntimeExecutionFacts> {
  if (!signal) return pending;
  if (signal.aborted) return Promise.resolve(UNKNOWN_FACTS);
  return new Promise((resolve) => {
    const finish = (facts: RuntimeExecutionFacts) => {
      signal.removeEventListener("abort", onAbort);
      resolve(facts);
    };
    const onAbort = () => finish(UNKNOWN_FACTS);
    signal.addEventListener("abort", onAbort, { once: true });
    pending.then(finish, () => finish(UNKNOWN_FACTS));
  });
}

export function probeRuntimeFacts(
  ctx: ToolContext,
): Promise<RuntimeExecutionFacts> {
  if (ctx.abortSignal?.aborted) return Promise.resolve(UNKNOWN_FACTS);
  const key = cacheKey(ctx);
  const cached = factsByKey.get(key);
  if (cached) return waitForProbe(cached, ctx.abortSignal);

  const pending = runProbe(ctx).then((facts) => {
    // A probe in flight when the cache was evicted must not touch whatever
    // a newer probe for the same key owns — guard on exact promise identity.
    if (factsByKey.get(key) !== pending) return facts;
    if (facts.probed) {
      settledFactsByKey.set(key, facts);
    } else {
      // Failure established nothing; drop the slot so the next agent retries.
      factsByKey.delete(key);
      settledFactsByKey.delete(key);
    }
    return facts;
  });
  // A rejected promise left cached would poison the slot for later agents.
  pending.catch(() => {
    if (factsByKey.get(key) !== pending) return;
    factsByKey.delete(key);
    settledFactsByKey.delete(key);
  });

  if (factsByKey.size >= MAX_CACHE_ENTRIES) {
    factsByKey.clear();
    settledFactsByKey.clear();
  }
  factsByKey.set(key, pending);
  return waitForProbe(pending, ctx.abortSignal);
}

/** Facts already discovered for this runtime scope, or null before a probe settles. */
export function peekSettledRuntimeFacts(
  ctx: ToolContext,
): RuntimeExecutionFacts | null {
  return settledFactsByKey.get(cacheKey(ctx)) ?? null;
}

/** Test seam: drop cached probes so a suite can exercise fresh probe paths. */
export function resetRuntimeFactsCache(): void {
  factsByKey.clear();
  settledFactsByKey.clear();
}

/** The command interpreter the agent's resolved backend will use. */
export function resolveCommandPlatform(ctx: ToolContext): "posix" | "windows" {
  return resolveBackends(ctx).command.platform ?? "posix";
}

// ---------------------------------------------------------------------------
// Prompt section
// ---------------------------------------------------------------------------

export interface RuntimeContextSectionOptions {
  platform: "posix" | "windows";
}

function hasTool(facts: RuntimeExecutionFacts, tool: string): boolean {
  return facts.available.includes(tool);
}

function toolFact(facts: RuntimeExecutionFacts, tool: string): string {
  if (!facts.probed) return "unknown";
  if (hasTool(facts, tool)) return "available";
  return facts.missing.includes(tool) ? "missing" : "unknown";
}

function shellFact(facts: RuntimeExecutionFacts): string {
  if (!facts.probed) return "unknown";
  if (hasTool(facts, "bash")) return "bash";
  if (hasTool(facts, "sh")) return "sh (no bash)";
  return "missing";
}

function pythonFact(facts: RuntimeExecutionFacts): string {
  if (!facts.probed) return "unknown";
  if (hasTool(facts, "python3")) return "available (python3)";
  if (hasTool(facts, "python")) return "available (python)";
  return "missing";
}

function inventoryLine(facts: RuntimeExecutionFacts): string {
  if (!facts.probed) {
    return "Command-tool inventory: unknown (not established — no probe has settled for this runtime). Verify each tool before first use.";
  }
  const lines: string[] = [];
  if (facts.available.length > 0) {
    lines.push(`Command tools present: ${facts.available.join(", ")}`);
  }
  if (facts.missing.length > 0) {
    lines.push(`Command tools absent: ${facts.missing.join(", ")}`);
  }
  return lines.join("\n");
}

/**
 * Compact, persona-neutral execution facts appended to every system prompt
 * the harness assembles. Emits no environment variable names or values and
 * no session paths — this text is embedded in the trace init record's base
 * prompt, whose hash must stay stable across workspaces; cwd and
 * file-workspace context live in the workspace section.
 */
export function buildRuntimeContextSection(
  facts: RuntimeExecutionFacts,
  opts: RuntimeContextSectionOptions,
): string {
  const verify =
    opts.platform === "windows" ? "where <tool>" : "command -v <tool>";
  const lines = [
    "[RUNTIME CONTEXT]",
    `OS: ${facts.probed ? (facts.os ?? "unknown") : "unknown"} | Shell: ${shellFact(facts)} | Python: ${pythonFact(facts)} | Node: ${toolFact(facts, "node")} | ffuf: ${toolFact(facts, "ffuf")}`,
    inventoryLine(facts),
    `Treat this inventory as facts, not as a checklist: pick techniques from evidence. When a tool is absent, build the equivalent with the available interpreters (shell/Python/Node) instead of assuming the tool exists. For tools listed unknown, verify with \`${verify}\` before first use.`,
    "Syntax-check or compile new or changed helper scripts with the runtime's available tools before execution; inspect the exit status and output, repair failures, and rerun. A successful file write alone does not establish that a helper works.",
    "[/RUNTIME CONTEXT]",
  ];
  return lines.filter(Boolean).join("\n");
}

/**
 * Authoritative inventory of CLI-bundled wordlist assets. The paths are
 * host-local: a sandbox or remote backend cannot resolve them without
 * staging, so callers advertise this only for local execution.
 */
export function buildBundledAssetsSection(): string | null {
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
