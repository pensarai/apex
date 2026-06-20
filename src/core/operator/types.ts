import { z } from "zod";
import type { ActionId, ApprovalId } from "./ids";

/**
 * Permission tiers for tool classification
 * Higher tier = more risk = more likely to need approval
 */
export type PermissionTier = 1 | 2 | 3 | 4 | 5;

interface TierDefinition {
  tier: PermissionTier;
  name: string;
  shortName: string;
  description: string;
  examples: string[];
}

const PERMISSION_TIERS: Record<PermissionTier, TierDefinition> = {
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

/** Operator operating modes */
export type OperatorMode = "plan" | "manual" | "auto";

export const OPERATOR_MODES: Record<
  OperatorMode,
  {
    name: string;
    description: string;
    color: string;
    icon: string;
    label: string;
    colorKey: string;
  }
> = {
  plan: {
    name: "Plan",
    description: "Read-only - agent proposes but cannot execute",
    color: "yellow",
    icon: "\u23F8",
    label: "Plan",
    colorKey: "secondary",
  },
  manual: {
    name: "Manual",
    description: "Approve each action",
    color: "blue",
    icon: "\u25B6",
    label: "Approvals On",
    colorKey: "primary",
  },
  auto: {
    name: "Auto",
    description: "Auto-approve within tier",
    color: "green",
    icon: "\u25B6\u25B6",
    label: "Approvals Off",
    colorKey: "error",
  },
};

/** Cycle order for ⇧Tab rotation through operator modes. */
export const OPERATOR_MODE_CYCLE: OperatorMode[] = ["manual", "auto", "plan"];

/** Operator workflow stages */
export type OperatorStage =
  | "setup"
  | "recon"
  | "enumerate"
  | "test"
  | "validate"
  | "report";

interface StageDefinition {
  stage: OperatorStage;
  name: string;
  description: string;
  order: number;
  suggestedActions: string[];
}

const OPERATOR_STAGES: Record<OperatorStage, StageDefinition> = {
  setup: {
    stage: "setup",
    name: "Setup",
    description: "Configure target and testing parameters",
    order: 1,
    suggestedActions: [
      "Verify target is accessible",
      "Check scope constraints",
    ],
  },
  recon: {
    stage: "recon",
    name: "Recon",
    description: "Discover attack surface",
    order: 2,
    suggestedActions: [
      "Crawl application",
      "Enumerate endpoints",
      "Identify technologies",
    ],
  },
  enumerate: {
    stage: "enumerate",
    name: "Enumerate",
    description: "Identify targets and parameters",
    order: 3,
    suggestedActions: [
      "Map parameters",
      "Catalog API endpoints",
      "Find hidden params",
    ],
  },
  test: {
    stage: "test",
    name: "Test",
    description: "Execute vulnerability tests",
    order: 4,
    suggestedActions: [
      "Test SQLi",
      "Test XSS",
      "Test IDOR",
      "Test auth bypass",
    ],
  },
  validate: {
    stage: "validate",
    name: "Validate",
    description: "Verify findings and create POCs",
    order: 5,
    suggestedActions: [
      "Verify vulnerabilities",
      "Create POC scripts",
      "Capture evidence",
    ],
  },
  report: {
    stage: "report",
    name: "Report",
    description: "Generate final report",
    order: 6,
    suggestedActions: [
      "Review findings",
      "Generate report",
      "Export artifacts",
    ],
  },
};

function getStagesInOrder(): StageDefinition[] {
  return Object.values(OPERATOR_STAGES).sort((a, b) => a.order - b.order);
}

function getNextStage(current: OperatorStage): OperatorStage | null {
  const stages = getStagesInOrder();
  const idx = stages.findIndex((s) => s.stage === current);
  return idx === -1 || idx === stages.length - 1 ? null : stages[idx + 1].stage;
}

/** Pending approval request. `id` is an internal correlation key, not a label. */
export interface PendingApproval {
  id: ApprovalId;
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
  id: ActionId;
  toolName: string;
  toolCallId: string;
  tier: PermissionTier;
  decision: ApprovalDecision;
  timestamp: number;
  duration?: number;
  resultSummary?: string;
}

/** Stage progress tracking */
interface StageProgress {
  started: boolean;
  startedAt?: number;
  completed: boolean;
  completedAt?: number;
}

/** Operator session state */
export interface OperatorSessionState {
  mode: OperatorMode;
  currentStage: OperatorStage;
  requireApproval: boolean;
  pendingApprovals: PendingApproval[];
  actionHistory: ActionHistoryEntry[];
  stageProgress: Record<OperatorStage, StageProgress>;
}

export function createInitialOperatorState(
  initialMode: OperatorMode = "manual",
  requireApproval: boolean = true,
): OperatorSessionState {
  const stageProgress = {} as Record<OperatorStage, StageProgress>;
  for (const stage of Object.keys(OPERATOR_STAGES) as OperatorStage[]) {
    stageProgress[stage] = { started: false, completed: false };
  }
  return {
    mode: initialMode,
    currentStage: "setup",
    requireApproval,
    pendingApprovals: [],
    actionHistory: [],
    stageProgress,
  };
}

/** Operator settings for session config */
const OperatorSettingsObject = z.object({
  initialMode: z.enum(["plan", "manual", "auto"]).default("manual"),
  requireApproval: z.boolean().default(true),
});

type OperatorSettings = z.infer<typeof OperatorSettingsObject>;

/** Endpoint discovered during attack surface mapping */
export interface DiscoveredEndpoint {
  id: string;
  path: string;
  method: string;
  category?: string;
  params?: string[];
  status?: "untested" | "suspicious" | "confirmed" | "clean" | "blocked";
  vulnType?: string;
}

/** Credential discovered during testing */
export interface DiscoveredCredential {
  id: string;
  username: string;
  secret: string;
  type: "password" | "cookie" | "jwt" | "ssh_key" | "api_key";
  source: string;
  scope: string;
  isActive?: boolean;
}

/** Verified vulnerability finding */
export interface VerifiedFinding {
  id: string;
  type: string;
  endpoint: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  summary: string;
  pocPath?: string;
}

/** Target state for sidebar panel */
export interface SidebarTargetState {
  host?: string;
  ports?: number[];
  authState?: string;
  phase?: string;
  objective?: string;
}

/** Hypothesis for stuck detection */
export interface SidebarHypothesis {
  id: string;
  description: string;
  confidence: number;
  timestamp: number;
}

/** Evidence captured during testing */
export interface SidebarEvidence {
  id: string;
  type: string;
  path: string;
  description: string;
  timestamp: number;
}

/** Events emitted by Operator system */
export type OperatorEvent =
  | { type: "mode-changed"; mode: OperatorMode }
  | { type: "stage-changed"; stage: OperatorStage }
  | { type: "approval-needed"; approval: PendingApproval }
  | {
      type: "approval-resolved";
      id: ApprovalId;
      decision: ApprovalDecision;
      approval: PendingApproval;
    }
  | { type: "action-completed"; entry: ActionHistoryEntry }
  // Sidebar population events
  | { type: "attack-surface-updated"; endpoints: DiscoveredEndpoint[] }
  | {
      type: "endpoint-status-changed";
      endpointId: string;
      status: string;
      vulnType?: string;
    }
  | { type: "finding-verified"; finding: VerifiedFinding }
  | { type: "credential-found"; credential: DiscoveredCredential }
  | { type: "target-state-updated"; state: Partial<SidebarTargetState> }
  | { type: "hypothesis-recorded"; hypothesis: SidebarHypothesis }
  | { type: "evidence-captured"; evidence: SidebarEvidence }
  | { type: "phase-transition-suggested"; phase: string }
  | { type: "objective-proposed"; objective: string }
  // Auth subagent events
  | { type: "auth-subagent-started"; target: string }
  | {
      type: "auth-subagent-completed";
      success: boolean;
      cookies?: string;
      headers?: Record<string, string>;
    };
