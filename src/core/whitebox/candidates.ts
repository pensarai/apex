import { existsSync } from "fs";
import { mkdir, readFile, writeFile } from "fs/promises";
import { join } from "path";
import type { SessionInfo } from "../session";
import type {
  WhiteboxArtifactRef,
  WhiteboxCandidate,
  WhiteboxCandidateState,
} from "./types";

const CANDIDATES_FILE = "candidates.json";

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

async function readCandidates(
  session: SessionInfo,
): Promise<WhiteboxCandidate[]> {
  const path = candidatesPath(session);
  if (!existsSync(path)) return [];
  const parsed = JSON.parse(
    await readFile(path, "utf-8"),
  ) as WhiteboxCandidate[];
  return Array.isArray(parsed) ? parsed : [];
}

async function writeCandidates(
  session: SessionInfo,
  candidates: WhiteboxCandidate[],
): Promise<void> {
  await mkdir(candidatesDir(session), { recursive: true });
  await writeFile(candidatesPath(session), JSON.stringify(candidates, null, 2));
}

function requiresEvidence(state: WhiteboxCandidateState): boolean {
  return state !== "hypothesis";
}

export async function listWhiteboxCandidates(
  session: SessionInfo,
): Promise<WhiteboxCandidate[]> {
  return readCandidates(session);
}

export async function createWhiteboxCandidate(input: {
  session: SessionInfo;
  title: string;
  vulnerabilityClass: string;
  summary: string;
  confidence: WhiteboxCandidate["confidence"];
  artifacts?: WhiteboxArtifactRef[];
  sourceTrace?: WhiteboxCandidate["sourceTrace"];
}): Promise<WhiteboxCandidate> {
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
}

export async function updateWhiteboxCandidate(input: {
  session: SessionInfo;
  id: string;
  state?: WhiteboxCandidateState;
  confidence?: WhiteboxCandidate["confidence"];
  summary?: string;
  artifacts?: WhiteboxArtifactRef[];
  verification?: WhiteboxCandidate["verification"];
}): Promise<WhiteboxCandidate> {
  const candidates = await readCandidates(input.session);
  const index = candidates.findIndex((candidate) => candidate.id === input.id);
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

  if (input.state && requiresEvidence(input.state) && artifacts.length === 0) {
    throw new Error(
      `Transition to ${input.state} requires at least one artifact or source-trace evidence reference.`,
    );
  }

  const updated: WhiteboxCandidate = {
    ...existing,
    ...(input.state ? { state: input.state } : {}),
    ...(input.confidence ? { confidence: input.confidence } : {}),
    ...(input.summary ? { summary: input.summary } : {}),
    ...(input.verification ? { verification: input.verification } : {}),
    artifacts,
    updatedAt: new Date().toISOString(),
  };

  candidates[index] = updated;
  await writeCandidates(input.session, candidates);
  return updated;
}

export function getWhiteboxCandidatesPath(session: SessionInfo): string {
  return candidatesPath(session);
}
