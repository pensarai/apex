import type { AutocompleteOption } from "../shared/prompt-input";
import type { OperatorSessionState } from "../../../core/operator";
import { buildBaseSystemPrompt } from "../../../core/agents/offSecAgent/prompt";

// ---------------------------------------------------------------------------
// Autocomplete option filtering for operator mode
// ---------------------------------------------------------------------------

const OPERATOR_ALLOWED_COMMANDS = new Set([
  "/models",
  "/login",
  "/auth",
  "/themes",
  "/new",
  "/operator",
  "/pentest",
  "/skills",
  "/plan",
  "/help",
]);

export function filterOperatorAutocomplete(
  allOptions: AutocompleteOption[],
): AutocompleteOption[] {
  return allOptions.filter((opt) => OPERATOR_ALLOWED_COMMANDS.has(opt.value));
}

// ---------------------------------------------------------------------------
// Submit gating
// ---------------------------------------------------------------------------

export type DashboardStatus = "idle" | "running" | "waiting" | "done";

export interface SubmitResult {
  action: "run" | "blocked" | "empty";
  prompt?: string;
  denyPending: boolean;
}

export function resolveSubmit(
  value: string,
  status: DashboardStatus,
  hasPendingApprovals: boolean,
): SubmitResult {
  const trimmed = value.trim();
  if (!trimmed) return { action: "empty", denyPending: false };
  if (status === "running")
    return { action: "blocked", denyPending: hasPendingApprovals };
  return { action: "run", prompt: trimmed, denyPending: hasPendingApprovals };
}

// ---------------------------------------------------------------------------
// Command routing
// ---------------------------------------------------------------------------

export type CommandAction =
  | { type: "show-models" }
  | { type: "show-plan" }
  | { type: "run-skill"; slug: string; autopilot: boolean }
  | { type: "execute-command"; command: string };

export function routeCommand(
  command: string,
  resolveSkill: (cmd: string) => string | null,
): CommandAction {
  const commandLower = command.trim().replace(/^\/+/, "").toLowerCase();

  if (commandLower === "models" || commandLower === "model") {
    return { type: "show-models" };
  }

  if (commandLower === "plan" || commandLower.startsWith("plan ")) {
    return { type: "show-plan" };
  }

  if (commandLower === "skills") {
    return { type: "execute-command", command };
  }

  const autopilot = command.includes("--autopilot");
  const cleanedCommand = command.replace(/\s*--autopilot\s*/g, "").trim();

  if (resolveSkill(cleanedCommand)) {
    // Reuse commandLower but take only the first word (slug without args)
    const slug = commandLower.split(/\s+/)[0] ?? commandLower;
    return { type: "run-skill", slug, autopilot };
  }

  return { type: "execute-command", command };
}

// ---------------------------------------------------------------------------
// Keyboard shortcut routing
// ---------------------------------------------------------------------------

interface KeyInfo {
  name: string;
  ctrl?: boolean;
  shift?: boolean;
  meta?: boolean;
  super?: boolean;
  raw?: string;
}

export type KeyboardAction =
  | { type: "skip" }
  | { type: "ctrl-c-abort" }
  | { type: "ctrl-c-clear" }
  | { type: "escape" }
  | { type: "toggle-verbose" }
  | { type: "toggle-expanded-logs" }
  | { type: "cycle-mode" }
  | { type: "approve" }
  | { type: "auto-approve" };

export function resolveKeyboardShortcut(
  key: KeyInfo,
  status: DashboardStatus,
  inputValue: string,
  hasPendingApprovals: boolean,
  dialogOpen: boolean,
): KeyboardAction {
  if (dialogOpen) return { type: "skip" };

  // Terminal-native copy (Cmd+C / Super+C) passes through
  if ((key.meta || key.super) && key.name === "c") return { type: "skip" };

  // Ctrl+C
  if (key.ctrl && key.name === "c") {
    if (status === "running" || status === "waiting")
      return { type: "ctrl-c-abort" };
    if (inputValue.trim()) return { type: "ctrl-c-clear" };
    return { type: "skip" };
  }

  // Escape
  if (key.name === "escape" && status !== "running" && status !== "waiting") {
    return { type: "escape" };
  }

  // Ctrl+V — toggle verbose
  if (key.ctrl && key.name === "v") return { type: "toggle-verbose" };

  // Ctrl+L — toggle expanded logs
  if (key.ctrl && key.name === "l") return { type: "toggle-expanded-logs" };

  // Shift+Tab — cycle operator mode (approvals-on → approvals-off → plan)
  if (key.name === "tab" && key.shift) return { type: "cycle-mode" };

  // Y to approve
  if (
    status === "waiting" &&
    hasPendingApprovals &&
    (key.name === "y" || key.raw === "Y")
  ) {
    return { type: "approve" };
  }

  // A to auto-approve
  if (
    status === "waiting" &&
    hasPendingApprovals &&
    (key.name === "a" || key.raw === "A")
  ) {
    return { type: "auto-approve" };
  }

  return { type: "skip" };
}

// ---------------------------------------------------------------------------
// Two-stage abort logic
// ---------------------------------------------------------------------------

export type AbortAction = { type: "cancel-command" } | { type: "kill-agent" };

export function resolveAbortAction(
  commandCancelled: boolean,
  cancelCommand: () => boolean,
): AbortAction {
  if (!commandCancelled && cancelCommand()) {
    return { type: "cancel-command" };
  }
  return { type: "kill-agent" };
}

// ---------------------------------------------------------------------------
// System prompt builder
// ---------------------------------------------------------------------------

export function buildOperatorSystemPrompt(
  target: string | undefined,
  operatorState: OperatorSessionState,
  agentMode?: "default" | "plan",
  opts?: {
    requireApproval?: boolean;
    sandboxMode?: boolean;
    skillsCatalog?: string;
    activeSkillInstructions?: Array<{ name: string; instructions: string }>;
    planFilePath?: string;
    existingPlanContent?: string | null;
    approvedPlanContent?: string | null;
    taskDriven?: boolean;
  },
): string {
  const { skillsCatalog, activeSkillInstructions } = opts ?? {};

  const approvalEnabled =
    opts?.requireApproval ?? operatorState.requireApproval;

  let modeSection = "";

  if (agentMode === "plan") {
    modeSection = buildPlanModePrompt(
      opts?.planFilePath,
      opts?.existingPlanContent,
    );
  } else if (opts?.approvedPlanContent) {
    modeSection = `

# Approved Plan

The operator has approved the following pentest plan. Execute it systematically, following the prioritized attack vectors and testing methodology outlined below.

<plan>
${opts.approvedPlanContent}
</plan>`;
  }

  let prompt = `${buildBaseSystemPrompt({ sandboxMode: opts?.sandboxMode })}

# Operator Mode

You are operating in interactive operator mode. The human operator will guide your actions through directives.

Target: ${target || "unknown"}
Stage: ${operatorState.currentStage}
Command approval: ${approvalEnabled ? "enabled — the operator will approve each tool call" : "disabled — tool calls execute automatically"}${modeSection}`;

  if (skillsCatalog) {
    prompt += `\n\n# Skills\n\n${skillsCatalog}`;
  }

  if (activeSkillInstructions && activeSkillInstructions.length > 0) {
    for (const skill of activeSkillInstructions) {
      prompt += `\n\n# Active Skill: ${skill.name}\n\n${skill.instructions}`;
    }
  }

  if (opts?.taskDriven && agentMode !== "plan") {
    prompt += `

# Task-Driven Testing

You have task decomposition tools available. Use them to structure your work:

1. **DECOMPOSE** — Before testing, call \`create_task\` for each technique × endpoint combination you plan to try. One task per atomic test.
2. **EXECUTE** — Pick a pending task, call \`update_task\` with status="in_progress", then test it.
3. **RECORD** — After testing, call \`update_task\` with status="completed" (found something or conclusively not vulnerable) or status="failed" (technique blocked, dead end).
4. **ADAPT** — If a task fails, call \`create_task\` with an alternative technique.
5. **COVERAGE** — Call \`list_tasks\` to check progress. Ensure all tasks reach a terminal state before wrapping up.

CRITICAL task rules:
- BEFORE making ANY \`http_request\` or \`execute_command\` call, you MUST call \`create_task\` first. Your first tool calls for each directive must be \`create_task\`.
- Every operator directive should map to one or more tasks
- Always include a result or observation when completing/failing a task`;
  }

  return prompt;
}

// ---------------------------------------------------------------------------
// Plan mode system prompt
// ---------------------------------------------------------------------------

function buildPlanModePrompt(
  planFilePath?: string,
  existingPlanContent?: string | null,
): string {
  const refinementBlock = existingPlanContent
    ? `

## Current Plan (Refine — Do NOT Rewrite)

The operator has reviewed this plan and requested changes. Read the existing plan on disk via \`read_file\`, then use \`write_plan\` to apply targeted modifications. The \`write_plan\` tool overwrites the file, so include the full plan content — but only change the sections the operator requested. Do NOT regenerate the plan from scratch.

<current-plan>
${existingPlanContent}
</current-plan>
`
    : "";

  return `

# PLAN MODE — Read-Only Reconnaissance & Planning

You are in PLAN MODE. This is a read-only phase for reconnaissance and pentest planning. You MUST NOT:
- Mutate the target's state (no POST/PUT/DELETE that changes data, no account creation, no data modification)
- Write to the filesystem except via the \`write_plan\` tool
- Execute exploit payloads or state-changing attacks
- Document vulnerabilities (use the plan to propose what to test)

Actively reconnoiter the target using the available read-only tools before planning.

## Workflow

1. **Recon** — Actively reconnoiter the target. Crawl the application, fingerprint tech stack, enumerate endpoints, discover authentication mechanisms, identify input surfaces.
2. **Analyze** — Map what you found into an attack surface. Identify which areas are most exposed and which vulnerability classes are most likely.
3. **Plan** — Write a structured pentest plan using \`write_plan\`.${planFilePath ? ` The plan is stored at: ${planFilePath}` : ""}
4. **Submit** — When the plan is complete, call \`submit_plan\` to present it to the operator for approval.

The \`write_plan\` tool description specifies the required plan sections. Follow that structure.
${refinementBlock}`;
}

// ---------------------------------------------------------------------------
// Input focus resolution
// ---------------------------------------------------------------------------

export function resolveInputFocused(
  status: DashboardStatus,
  dialogStackLength: number,
  externalDialogOpen: boolean,
): boolean {
  return status !== "running" && dialogStackLength === 0 && !externalDialogOpen;
}

// ---------------------------------------------------------------------------
// Token usage accumulation
// ---------------------------------------------------------------------------

export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  cachedTokens: number;
  cacheWriteTokens: number;
}

export function accumulateTokenUsage(
  current: TokenUsage,
  stepInputTokens: number,
  stepOutputTokens: number,
): TokenUsage | null {
  if (stepInputTokens <= 0 && stepOutputTokens <= 0) return null;
  return {
    inputTokens: current.inputTokens + stepInputTokens,
    outputTokens: current.outputTokens + stepOutputTokens,
    totalTokens: current.totalTokens + stepInputTokens + stepOutputTokens,
    cachedTokens: current.cachedTokens,
    cacheWriteTokens: current.cacheWriteTokens,
  };
}
