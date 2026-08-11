import {
  type AgentMode,
  buildBaseSystemPrompt,
} from "../../../core/agents/offSecAgent";
import { detectOSAndEnhancePrompt } from "../../../core/agents/specialized/utils";
import type {
  OperatorMode,
  OperatorSessionState,
} from "../../../core/operator";
import type { AutocompleteOption } from "../shared";

// ---------------------------------------------------------------------------
// Autocomplete option filtering for operator mode
// ---------------------------------------------------------------------------

const OPERATOR_ALLOWED_COMMANDS = new Set([
  "/models",
  "/login",
  "/themes",
  "/new",
  "/operator",
  "/pentest",
  "/skills",
  "/plan",
  "/advanced",
  "/obfuscate",
  "/headers",
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

export function resolveOperatorAgentMode(
  operatorMode: OperatorMode,
  strikeMode: boolean,
): AgentMode {
  if (operatorMode === "plan") return "plan";
  return strikeMode ? "fast-strike" : "default";
}

interface StrikeModeResolutionInput {
  resuming: boolean;
  savedSessionValue?: boolean;
  routeOverride?: boolean;
  persistedDefault?: boolean;
}

export function resolveOperatorStrikeMode({
  resuming,
  savedSessionValue,
  routeOverride,
  persistedDefault,
}: StrikeModeResolutionInput): boolean {
  if (resuming) return savedSessionValue ?? false;
  return routeOverride ?? persistedDefault ?? false;
}

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

export type HeadersOp =
  | { kind: "list"; showSecrets: boolean }
  | { kind: "add"; line: string; allowOverwrite: boolean }
  | { kind: "remove"; name: string }
  | { kind: "clear" }
  | { kind: "invalid"; reason: string };

export type CommandAction =
  | { type: "show-models" }
  | { type: "show-plan" }
  | { type: "open-session" }
  | { type: "run-skill"; slug: string; autopilot: boolean }
  | { type: "headers"; op: HeadersOp }
  | { type: "execute-command"; command: string };

function parseHeadersSlashCommand(rest: string): HeadersOp {
  const trimmed = rest.trim();
  if (!trimmed) {
    return { kind: "list", showSecrets: false };
  }

  const [verb, ...tailParts] = trimmed.split(/\s+/);
  const tail = trimmed.slice(verb.length).trim();

  switch (verb.toLowerCase()) {
    case "list":
      return { kind: "list", showSecrets: tailParts.includes("--show") };
    case "add":
      if (!tail) return { kind: "invalid", reason: 'expected "Name: Value"' };
      return { kind: "add", line: tail, allowOverwrite: false };
    case "set":
      if (!tail) return { kind: "invalid", reason: 'expected "Name: Value"' };
      return { kind: "add", line: tail, allowOverwrite: true };
    case "remove":
    case "rm":
    case "delete":
      if (!tail) return { kind: "invalid", reason: "expected header name" };
      return { kind: "remove", name: tail };
    case "clear":
      return { kind: "clear" };
    default:
      return {
        kind: "invalid",
        reason: `unknown subcommand "${verb}". Use list, add, set, remove, or clear.`,
      };
  }
}

export function routeCommand(
  command: string,
  resolveSkill: (cmd: string) => string | null,
): CommandAction {
  const stripped = command.trim().replace(/^\/+/, "");
  const commandLower = stripped.toLowerCase();

  if (commandLower === "models" || commandLower === "model") {
    return { type: "show-models" };
  }

  if (commandLower === "plan" || commandLower.startsWith("plan ")) {
    return { type: "show-plan" };
  }

  if (commandLower === "open-session") {
    return { type: "open-session" };
  }

  if (commandLower === "skills") {
    return { type: "execute-command", command };
  }

  if (commandLower === "headers" || commandLower.startsWith("headers ")) {
    const rest = stripped.slice("headers".length);
    return { type: "headers", op: parseHeadersSlashCommand(rest) };
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
  agentMode?: AgentMode,
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
  } else {
    if (agentMode === "fast-strike") {
      modeSection = `

# Strike Mode

Work as one focused vulnerability researcher under the human operator's direction. Do not delegate, spawn agents, map the entire attack surface, or create task lists.

For each directive, run a tight loop:
1. OBSERVE — read the available evidence and state the strongest new signal.
2. HYPOTHESIZE — choose the single most likely vulnerability or next pivot.
3. ACT — use direct tools for quick probes, but treat the shell as a working environment rather than merely a way to issue one-off commands. When the work becomes stateful, repetitive, concurrent, protocol-heavy, or multi-stage, externalize it into an editable script in the session scratchpad directory identified in the Session Workspace or Working Directory section. Never create a scratchpad/ directory inside the target repository. Run the script, inspect the results, modify it, and rerun it as the attack develops.
4. PRUNE — drop disproven leads instead of repeating them.
5. EXPLOIT — preserve viable primitives and build on them. Prefer extending a working script into an end-to-end exploit over rebuilding the chain with repeated one-off tool calls or stopping at the next network or protocol boundary. Prove impact and document confirmed vulnerabilities.

Spend your reasoning on choosing techniques and interpreting evidence; use scripts for deterministic mechanics, iteration, and chain execution. Before stopping with the objective unmet, account for each viable primitive and pursue any concrete path that could still close it. Stop and summarize when the objective is met, credible leads are genuinely exhausted, or human input is needed. Stay in scope and never trade verification for speed.`;
    }

    if (opts?.approvedPlanContent) {
      modeSection += `

# Approved Plan

The operator has approved the following pentest plan. Execute it systematically, following the prioritized attack vectors and testing methodology outlined below.

<plan>
${opts.approvedPlanContent}
</plan>`;
    }
  }

  let prompt = `${detectOSAndEnhancePrompt(buildBaseSystemPrompt({ sandboxMode: opts?.sandboxMode }))}

# Operator Mode

You are operating in interactive operator mode. The human operator will guide your actions through directives.

Target: ${target || "unknown"}
Stage: ${operatorState.currentStage}
Command approval: ${approvalEnabled ? "enabled — the operator will approve each tool call" : "disabled — tool calls execute automatically"}

## Session-wide Custom HTTP Headers

The operator can attach custom HTTP headers (Authorization tokens, X-API-Key,
tenant IDs, etc.) that are automatically applied to every in-scope
\`http_request\`, \`execute_command\` (curl/nuclei/etc.), and Playwright
navigation. You do NOT have a tool to mutate these — they are operator-owned.

If the operator asks you to "set/add/remove/list a header," do NOT refuse
and do NOT try to inject it per-call. Tell them to type one of these
commands directly into the chat input (the slash-command bar, not as a
message to you):

  /headers add Name: Value     # error if Name already set
  /headers set Name: Value     # overwrite
  /headers remove Name
  /headers list                # masked
  /headers list --show         # reveal values
  /headers clear

Once set, the header is applied automatically — you don't need to do
anything to use it. Per-request \`headers\` you pass to \`http_request\`
still win over session headers if you need a one-off override.${modeSection}`;

  if (skillsCatalog) {
    prompt += `\n\n# Skills\n\n${skillsCatalog}`;
  }

  if (activeSkillInstructions && activeSkillInstructions.length > 0) {
    for (const skill of activeSkillInstructions) {
      prompt += `\n\n# Active Skill: ${skill.name}\n\n${skill.instructions}`;
    }
  }

  if (opts?.taskDriven && (agentMode ?? "default") === "default") {
    prompt += `

# Task-Driven Testing

You have task decomposition tools available. Use them to structure your work:

These rules apply only to reconnaissance and security testing. Authenticated workspace management through the workspace tools is not a pentest task: do not create tasks, run discovery, or generate threat models for it. Execute the explicitly requested workspace operation directly.

1. **DECOMPOSE** — Before testing, call \`create_task\` for each technique × endpoint combination you plan to try. One task per atomic test.
2. **EXECUTE** — Pick a pending task, call \`update_task\` with status="in_progress", then test it.
3. **RECORD** — After testing, call \`update_task\` with status="completed" (found something or conclusively not vulnerable) or status="failed" (technique blocked, dead end).
4. **ADAPT** — If a task fails, call \`create_task\` with an alternative technique.
5. **COVERAGE** — Call \`list_tasks\` to check progress. Ensure all tasks reach a terminal state before wrapping up.

CRITICAL task rules:
- BEFORE making any \`http_request\` or \`execute_command\` call for reconnaissance or security testing, you MUST call \`create_task\` first.
- Every reconnaissance or security-testing directive should map to one or more tasks
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
