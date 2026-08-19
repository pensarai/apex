import { createHash, randomBytes } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import type {
  AgentRedTeamArtifact,
  AgentRedTeamAttempt,
  AgentRedTeamCampaign,
  AgentRedTeamEvaluation,
  AgentRedTeamObservation,
} from "../types";

export const AGENT_REDTEAM_DIR = "agent-redteam";
export const ATTEMPT_LEDGER_FILE = "attempts.jsonl";
export const OBSERVATION_LEDGER_FILE = "observations.jsonl";
export const EVALUATION_LEDGER_FILE = "evaluations.jsonl";

export function sha256(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

export function stableAgentRedTeamId(
  prefix: string,
  ...parts: Array<string | number | undefined>
): string {
  const digest = sha256(parts.map((part) => String(part ?? "")).join("\u0000"));
  return `${prefix}_${digest.slice(0, 20)}`;
}

export function createCampaignSeed(): string {
  return randomBytes(16).toString("hex");
}

export function createArtifact(
  type: AgentRedTeamArtifact["type"],
  label: string,
  content: string,
): AgentRedTeamArtifact {
  const digest = sha256(content);
  return {
    id: `artifact_${digest.slice(0, 20)}`,
    type,
    label,
    content,
    sha256: digest,
  };
}

function appendJsonLine(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, `${JSON.stringify(value)}\n`, "utf8");
}

function readJsonLines<T>(path: string): T[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as T);
}

// The ledger is append-only, so retries (e.g. re-evaluating an attempt) can
// write duplicate rows sharing a stable id. Collapse them to the latest write
// so counts and coverage are not inflated by duplicates.
function dedupeById<T extends { id: string }>(items: T[]): T[] {
  const byId = new Map<string, T>();
  for (const item of items) byId.set(item.id, item);
  return [...byId.values()];
}

export class AgentRedTeamAttemptLedger {
  readonly directory: string;
  readonly ledgerPath: string;
  readonly observationLedgerPath: string;
  readonly evaluationLedgerPath: string;
  readonly campaignPath: string;

  constructor(sessionRootPath: string, campaignId = "legacy") {
    this.directory = join(
      sessionRootPath,
      AGENT_REDTEAM_DIR,
      "campaigns",
      campaignId,
    );
    this.ledgerPath = join(this.directory, ATTEMPT_LEDGER_FILE);
    this.observationLedgerPath = join(this.directory, OBSERVATION_LEDGER_FILE);
    this.evaluationLedgerPath = join(this.directory, EVALUATION_LEDGER_FILE);
    this.campaignPath = join(this.directory, "campaign.json");
  }

  writeCampaign(campaign: AgentRedTeamCampaign): void {
    mkdirSync(this.directory, { recursive: true });
    writeFileSync(
      this.campaignPath,
      `${JSON.stringify(campaign, null, 2)}\n`,
      "utf8",
    );
  }

  readCampaign(): AgentRedTeamCampaign | undefined {
    if (!existsSync(this.campaignPath)) return undefined;
    return JSON.parse(
      readFileSync(this.campaignPath, "utf8"),
    ) as AgentRedTeamCampaign;
  }

  append(attempt: AgentRedTeamAttempt): void {
    appendJsonLine(this.ledgerPath, attempt);
  }

  appendObservation(observation: AgentRedTeamObservation): void {
    appendJsonLine(this.observationLedgerPath, observation);
  }

  appendEvaluation(evaluation: AgentRedTeamEvaluation): void {
    appendJsonLine(this.evaluationLedgerPath, evaluation);
  }

  readAll(): AgentRedTeamAttempt[] {
    return readJsonLines<AgentRedTeamAttempt>(this.ledgerPath);
  }

  readObservations(): AgentRedTeamObservation[] {
    return dedupeById(
      readJsonLines<AgentRedTeamObservation>(this.observationLedgerPath),
    );
  }

  readEvaluations(): AgentRedTeamEvaluation[] {
    return dedupeById(
      readJsonLines<AgentRedTeamEvaluation>(this.evaluationLedgerPath),
    );
  }
}
