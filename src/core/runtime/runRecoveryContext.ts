import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import type { ModelMessage } from "ai";
import { buildSessionWorkspaceSection } from "../agents/offSecAgent";
import type { SessionInfo } from "../session";
import type { ContextReference } from "./runContext";
import type { RunRecord } from "./runStore";

export interface RestoreRunContextInput {
  record: RunRecord;
  session: SessionInfo;
  context: ContextReference & {
    messages: ModelMessage[];
    system: string | null;
  };
}

export interface RestoredRunContext {
  /** Conversation head without any leading system message. */
  messages: ModelMessage[];
  /** Saved base prompt; the agent re-appends current runtime facts, assets, and workspace. */
  baseSystem: string;
}

// Mirrors the taskDriven derivation in recordedRun admission.
const TASK_TOOL_NAMES = new Set(["create_task", "update_task", "list_tasks"]);

function blocker(message: string): Error {
  return new Error(`Run recovery blocked: ${message}`);
}

function requireSessionConsistency(
  record: RunRecord,
  session: SessionInfo,
): void {
  const { spec } = record;
  if (session.id !== record.sessionId) {
    throw blocker(
      `session id ${session.id} does not match the admitted record ${record.sessionId}`,
    );
  }
  if (!isDeepStrictEqual(session.targets, [spec.target])) {
    throw blocker("session targets do not match the admitted spec target");
  }
  const config = session.config;
  if (!config) {
    throw blocker("session has no recorded-run configuration");
  }
  if (config.agentCwd !== spec.environment.cwd) {
    throw blocker(
      `session working directory ${config.agentCwd ?? "(unset)"} does not match the admitted ${spec.environment.cwd}`,
    );
  }
  const scope = config.scopeConstraints;
  if (
    !scope ||
    !isDeepStrictEqual(scope.allowedHosts ?? [], spec.scope.allowedHosts) ||
    !isDeepStrictEqual(scope.allowedPorts ?? [], spec.scope.allowedPorts) ||
    scope.strictScope !== spec.scope.strictScope
  ) {
    throw blocker("session scope constraints do not match the admitted spec");
  }
  if (
    (config.allowDestructiveActions ?? false) !==
    spec.scope.allowDestructiveActions
  ) {
    throw blocker(
      "session destructive-action flag does not match the admitted spec",
    );
  }
  if (
    (config.allowRateLimitTesting ?? false) !== spec.scope.allowRateLimitTesting
  ) {
    throw blocker(
      "session rate-limit-testing flag does not match the admitted spec",
    );
  }
  if (config.disableSubagents !== true) {
    throw blocker(
      "session does not disable subagents as recorded runs require",
    );
  }
  const taskDriven = spec.activeTools.some((tool) => TASK_TOOL_NAMES.has(tool));
  if ((config.taskDriven ?? false) !== taskDriven) {
    throw blocker("session task-driven flag does not match the admitted tools");
  }
  // Artifact locations are derived from the session root at creation; a
  // changed leaf means the stored evidence lives somewhere else now.
  for (const [field, leaf] of [
    ["findingsPath", "findings"],
    ["scratchpadPath", "scratchpad"],
    ["logsPath", "logs"],
    ["pocsPath", "pocs"],
  ] as const) {
    if (session[field] !== join(session.rootPath, leaf)) {
      throw blocker(
        `session ${field} ${session[field]} is not the standard ${leaf}/ location under the session root`,
      );
    }
  }
  if (config.headers !== undefined && !isDeepStrictEqual(config.headers, {})) {
    throw blocker(
      "session carries custom HTTP headers that fresh admission never set",
    );
  }
  if (config.authCredentials !== undefined) {
    throw blocker("session carries auth credentials outside the admitted run");
  }
  if (config.smtpConfig !== undefined) {
    throw blocker(
      "session carries SMTP configuration outside the admitted run",
    );
  }
  if (config.emailIntegration !== undefined) {
    throw blocker("session carries email inboxes outside the admitted run");
  }
  if (session.credentialManager !== undefined) {
    throw blocker(
      "session holds an in-memory credential manager outside the admitted run",
    );
  }
}

/** Restores the committed conversation and base prompt without retaining transient harness sections. */
export function restoreRunContext(
  input: RestoreRunContextInput,
): RestoredRunContext {
  const { record, session, context } = input;
  requireSessionConsistency(record, session);

  const workspace = buildSessionWorkspaceSection(
    session,
    record.spec.environment.cwd,
    record.spec.activeTools,
  );
  if (workspace.length === 0) {
    throw blocker(
      "the session workspace section is empty; the base system cannot be recovered",
    );
  }

  let effectiveSystem: string;
  let messages: ModelMessage[];
  if (context.system !== null) {
    if (context.messages[0]?.role === "system") {
      throw blocker(
        "saved context carries both a system field and a leading system message",
      );
    }
    effectiveSystem = context.system;
    messages = context.messages;
  } else {
    const [leading] = context.messages;
    if (
      !leading ||
      leading.role !== "system" ||
      typeof leading.content !== "string"
    ) {
      throw blocker(
        "saved context has no leading system message to recover the cached effective system",
      );
    }
    effectiveSystem = leading.content;
    messages = context.messages.slice(1);
  }

  if (!effectiveSystem.endsWith(workspace)) {
    throw blocker(
      "the saved effective system does not end with the current session workspace section",
    );
  }
  const firstOccurrence = effectiveSystem.indexOf(workspace);
  if (firstOccurrence !== effectiveSystem.length - workspace.length) {
    throw blocker(
      "the session workspace section occurs more than once in the saved effective system",
    );
  }
  let baseSystem = effectiveSystem.slice(0, firstOccurrence);
  // Peel only trailing harness blocks, in reverse assembly order. Never strip an admitted custom base.
  for (const section of ["BUNDLED ASSETS", "RUNTIME CONTEXT"]) {
    if (baseSystem === record.spec.system) break;
    const start = baseSystem.lastIndexOf(`\n\n[${section}]\n`);
    if (start !== -1 && baseSystem.endsWith(`\n[/${section}]`)) {
      baseSystem = baseSystem.slice(0, start);
    }
  }

  if (record.spec.system !== undefined && baseSystem !== record.spec.system) {
    throw blocker(
      "the recovered base system does not match the system admitted with the run spec",
    );
  }

  return { messages: structuredClone(messages), baseSystem };
}
