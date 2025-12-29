import { z } from "zod";

/**
 * Permission tiers for tool classification
 * Higher tier = more risk = more likely to need approval
 */
export type PermissionTier = 1 | 2 | 3 | 4 | 5;

export interface TierDefinition {
  tier: PermissionTier;
  name: string;
  shortName: string;
  description: string;
  examples: string[];
}

export const PERMISSION_TIERS: Record<PermissionTier, TierDefinition> = {
  1: {
    tier: 1,
    name: "Passive",
    shortName: "T1",
    description: "Read-only operations, no network requests to target",
    examples: ["DNS lookups", "Certificate inspection", "Scratchpad notes"],
  },
  2: {
    tier: 2,
    name: "Low-risk Active",
    shortName: "T2",
    description: "Light network interaction, observational only",
    examples: ["Crawling", "Endpoint discovery", "GET/HEAD requests"],
  },
  3: {
    tier: 3,
    name: "Probing",
    shortName: "T3",
    description: "Parameter testing, fuzzing with controlled payloads",
    examples: ["Parameter fuzzing", "Template scanning", "Auth probing"],
  },
  4: {
    tier: 4,
    name: "Intrusive",
    shortName: "T4",
    description: "Heavy testing that may trigger alerts",
    examples: ["Heavy fuzzing", "Shell commands", "File upload probing"],
  },
  5: {
    tier: 5,
    name: "Exploit",
    shortName: "T5",
    description: "State-changing actions, exploit attempts",
    examples: ["User creation", "Data modification", "RCE attempts"],
  },
};

/** HITL operating modes */
export type HITLMode = "plan" | "manual" | "auto";

export const HITL_MODES: Record<HITLMode, { name: string; description: string; color: string }> = {
  plan: { name: "Plan", description: "Read-only - agent proposes but cannot execute", color: "yellow" },
  manual: { name: "Manual", description: "Approve each action", color: "blue" },
  auto: { name: "Auto", description: "Auto-approve within tier", color: "green" },
};

/** HITL workflow stages */
export type HITLStage = "setup" | "recon" | "enumerate" | "test" | "validate" | "report";

export interface StageDefinition {
  stage: HITLStage;
  name: string;
  description: string;
  order: number;
  suggestedActions: string[];
}

export const HITL_STAGES: Record<HITLStage, StageDefinition> = {
  setup: { stage: "setup", name: "Setup", description: "Configure target and testing parameters", order: 1, suggestedActions: ["Verify target is accessible", "Check scope constraints"] },
  recon: { stage: "recon", name: "Recon", description: "Discover attack surface", order: 2, suggestedActions: ["Crawl application", "Enumerate endpoints", "Identify technologies"] },
  enumerate: { stage: "enumerate", name: "Enumerate", description: "Identify targets and parameters", order: 3, suggestedActions: ["Map parameters", "Catalog API endpoints", "Find hidden params"] },
  test: { stage: "test", name: "Test", description: "Execute vulnerability tests", order: 4, suggestedActions: ["Test SQLi", "Test XSS", "Test IDOR", "Test auth bypass"] },
  validate: { stage: "validate", name: "Validate", description: "Verify findings and create POCs", order: 5, suggestedActions: ["Verify vulnerabilities", "Create POC scripts", "Capture evidence"] },
  report: { stage: "report", name: "Report", description: "Generate final report", order: 6, suggestedActions: ["Review findings", "Generate report", "Export artifacts"] },
};

export function getStagesInOrder(): StageDefinition[] {
  return Object.values(HITL_STAGES).sort((a, b) => a.order - b.order);
}

export function getNextStage(current: HITLStage): HITLStage | null {
  const stages = getStagesInOrder();
  const idx = stages.findIndex((s) => s.stage === current);
  return idx === -1 || idx === stages.length - 1 ? null : stages[idx + 1].stage;
}

/** Pending approval request */
export interface PendingApproval {
  id: string;
  toolName: string;
  toolCallId: string;
  args: Record<string, unknown>;
  tier: PermissionTier;
  reasoning?: string;
  timestamp: number;
}

export type ApprovalDecision = "approved" | "denied" | "auto-approved";

/** Action history entry for audit log */
export interface ActionHistoryEntry {
  id: string;
  toolName: string;
  toolCallId: string;
  tier: PermissionTier;
  decision: ApprovalDecision;
  timestamp: number;
  duration?: number;
  resultSummary?: string;
}

/** Stage progress tracking */
export interface StageProgress {
  started: boolean;
  startedAt?: number;
  completed: boolean;
  completedAt?: number;
}

/** HITL session state */
export interface HITLSessionState {
  mode: HITLMode;
  currentStage: HITLStage;
  autoApproveTier: PermissionTier;
  pendingApprovals: PendingApproval[];
  actionHistory: ActionHistoryEntry[];
  stageProgress: Record<HITLStage, StageProgress>;
}

export function createInitialHITLState(initialMode: HITLMode = "manual", autoApproveTier: PermissionTier = 2): HITLSessionState {
  const stageProgress = {} as Record<HITLStage, StageProgress>;
  for (const stage of Object.keys(HITL_STAGES) as HITLStage[]) {
    stageProgress[stage] = { started: false, completed: false };
  }
  return { mode: initialMode, currentStage: "setup", autoApproveTier, pendingApprovals: [], actionHistory: [], stageProgress };
}

/** HITL settings for session config */
export const HITLSettingsObject = z.object({
  initialMode: z.enum(["plan", "manual", "auto"]).default("manual"),
  autoApproveTier: z.number().min(1).max(5).default(2),
  enableSuggestions: z.boolean().default(true),
});

export type HITLSettings = z.infer<typeof HITLSettingsObject>;

/** Events emitted by HITL system */
export type HITLEvent =
  | { type: "mode-changed"; mode: HITLMode }
  | { type: "stage-changed"; stage: HITLStage }
  | { type: "approval-needed"; approval: PendingApproval }
  | { type: "approval-resolved"; id: string; decision: ApprovalDecision }
  | { type: "action-completed"; entry: ActionHistoryEntry };
