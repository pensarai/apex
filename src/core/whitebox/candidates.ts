import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { SessionInfo } from "../session";
import type {
  SourceTrace,
  WhiteboxArtifactRef,
  WhiteboxCandidate,
  WhiteboxCandidateState,
} from "./types";

const CANDIDATES_FILE = "candidates.json";

const writeLocks = new Map<string, Promise<void>>();

function withCandidateLock<T>(
  session: SessionInfo,
  fn: () => Promise<T>,
): Promise<T> {
  const key = session.scratchpadPath;
  const prev = writeLocks.get(key) ?? Promise.resolve();
  let release: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  writeLocks.set(key, gate);
  return prev.then(fn).finally(() => {
    release();
    if (writeLocks.get(key) === gate) {
      writeLocks.delete(key);
    }
  });
}

/** Legal state transitions (from -> allowed `to` states). */
const ALLOWED_TRANSITIONS: Record<
  WhiteboxCandidateState,
  readonly WhiteboxCandidateState[]
> = {
  hypothesis: ["investigating", "rejected", "deferred"],
  investigating: ["repro_attempted", "rejected", "deferred"],
  repro_attempted: ["confirmed", "rejected", "deferred"],
  confirmed: [],
  rejected: [],
  deferred: ["hypothesis", "investigating"],
};

function candidatesDir(session: SessionInfo): string {
  return join(session.scratchpadPath, "whitebox");
}

function candidatesPath(session: SessionInfo): string {
  return join(candidatesDir(session), CANDIDATES_FILE);
}

function makeId(title: string): string {
  const slug = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 48);
  return `wcand_${Date.now()}_${slug || "candidate"}`;
}

function sourceTraceHasEvidence(trace?: SourceTrace): boolean {
  if (!trace) return false;
  if (trace.source?.file || trace.sink?.file) return true;
  if (trace.path && trace.path.length > 0) return true;
  if (trace.notes?.trim()) return true;
  return false;
}

function hasEvidence(input: {
  artifacts: WhiteboxArtifactRef[];
  sourceTrace?: SourceTrace;
}): boolean {
  return (
    input.artifacts.length > 0 || sourceTraceHasEvidence(input.sourceTrace)
  );
}

function mergeSourceTrace(
  existing: WhiteboxCandidate["sourceTrace"],
  incoming: WhiteboxCandidate["sourceTrace"] | undefined,
): WhiteboxCandidate["sourceTrace"] | undefined {
  if (incoming === undefined) return existing;
  if (existing === undefined) return incoming;
  return {
    ...existing,
    ...incoming,
    path: incoming.path ?? existing.path,
  };
}

async function readCandidates(
  session: SessionInfo,
): Promise<WhiteboxCandidate[]> {
  const path = candidatesPath(session);
  if (!existsSync(path)) return [];
  try {
    const raw = await readFile(path, "utf-8");
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed as WhiteboxCandidate[];
  } catch {
    return [];
  }
}

async function writeCandidates(
  session: SessionInfo,
  candidates: WhiteboxCandidate[],
): Promise<void> {
  await mkdir(candidatesDir(session), { recursive: true });
  await writeFile(candidatesPath(session), JSON.stringify(candidates, null, 2));
}

function assertTransition(
  from: WhiteboxCandidateState,
  to: WhiteboxCandidateState,
) {
  const allowed = ALLOWED_TRANSITIONS[from];
  if (!allowed.includes(to)) {
    throw new Error(
      `Illegal whitebox candidate transition: ${from} -> ${to}. Allowed from ${from}: ${allowed.join(", ") || "(terminal)"}.`,
    );
  }
}

export type ListWhiteboxCandidatesOptions = {
  state?: WhiteboxCandidateState;
  limit?: number;
};

export async function listWhiteboxCandidates(
  session: SessionInfo,
  options?: ListWhiteboxCandidatesOptions,
): Promise<WhiteboxCandidate[]> {
  let list = await readCandidates(session);
  if (options?.state) {
    list = list.filter((c) => c.state === options.state);
  }
  const limit = options?.limit ?? 50;
  return list.slice(0, Math.max(1, Math.min(limit, 200)));
}

export function createWhiteboxCandidate(input: {
  session: SessionInfo;
  title: string;
  vulnerabilityClass: string;
  summary: string;
  confidence: WhiteboxCandidate["confidence"];
  artifacts?: WhiteboxArtifactRef[];
  sourceTrace?: WhiteboxCandidate["sourceTrace"];
}): Promise<WhiteboxCandidate> {
  return withCandidateLock(input.session, async () => {
    const now = new Date().toISOString();
    const candidate: WhiteboxCandidate = {
      id: makeId(input.title),
      title: input.title,
      vulnerabilityClass: input.vulnerabilityClass,
      state: "hypothesis",
      confidence: input.confidence,
      summary: input.summary,
      artifacts: input.artifacts ?? [],
      sourceTrace: input.sourceTrace,
      verification: { strategy: "", status: "not_started" },
      createdAt: now,
      updatedAt: now,
    };

    const candidates = await readCandidates(input.session);
    candidates.push(candidate);
    await writeCandidates(input.session, candidates);
    return candidate;
  });
}

export function updateWhiteboxCandidate(input: {
  session: SessionInfo;
  id: string;
  state?: WhiteboxCandidateState;
  confidence?: WhiteboxCandidate["confidence"];
  summary?: string;
  artifacts?: WhiteboxArtifactRef[];
  sourceTrace?: WhiteboxCandidate["sourceTrace"];
  verification?: WhiteboxCandidate["verification"];
}): Promise<WhiteboxCandidate> {
  return withCandidateLock(input.session, async () => {
    const candidates = await readCandidates(input.session);
    const index = candidates.findIndex(
      (candidate) => candidate.id === input.id,
    );
    if (index === -1) {
      throw new Error(`Whitebox candidate not found: ${input.id}`);
    }

    const existing = candidates[index];
    if (!existing) {
      throw new Error(`Whitebox candidate not found: ${input.id}`);
    }

    const artifacts = input.artifacts
      ? [...existing.artifacts, ...input.artifacts]
      : existing.artifacts;

    const mergedSourceTrace = mergeSourceTrace(
      existing.sourceTrace,
      input.sourceTrace,
    );

    if (input.state && input.state !== existing.state) {
      assertTransition(existing.state, input.state);

      const needsDeepEvidence =
        input.state === "investigating" || input.state === "repro_attempted";
      if (
        needsDeepEvidence &&
        !hasEvidence({ artifacts, sourceTrace: mergedSourceTrace })
      ) {
        throw new Error(
          `Transition to ${input.state} requires at least one artifact reference or a substantive sourceTrace (source/sink file, path chain, or notes).`,
        );
      }

      if (input.state === "confirmed") {
        if (existing.state !== "repro_attempted") {
          throw new Error(
            "Transition to confirmed requires state repro_attempted first.",
          );
        }
        const v = input.verification ?? existing.verification;
        if (v?.status !== "succeeded") {
          throw new Error(
            'Transition to confirmed requires verification.status === "succeeded" (set verification on the same update or beforehand).',
          );
        }
        if (!hasEvidence({ artifacts, sourceTrace: mergedSourceTrace })) {
          throw new Error(
            "Transition to confirmed requires artifact and/or sourceTrace evidence.",
          );
        }
      }
    }

    const updated: WhiteboxCandidate = {
      ...existing,
      ...(input.state ? { state: input.state } : {}),
      ...(input.confidence !== undefined
        ? { confidence: input.confidence }
        : {}),
      ...(input.summary !== undefined ? { summary: input.summary } : {}),
      ...(input.verification ? { verification: input.verification } : {}),
      artifacts,
      sourceTrace: mergedSourceTrace,
      updatedAt: new Date().toISOString(),
    };

    candidates[index] = updated;
    await writeCandidates(input.session, candidates);
    return updated;
  });
}
