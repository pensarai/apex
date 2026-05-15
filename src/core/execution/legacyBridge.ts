import type { AgentEventBus } from "../eventBus";
import type { ExecutionContext } from "./context";
import type { NodeID } from "./ids";

export interface AttachLegacyBridgeOptions {
  bus: AgentEventBus;
  context: ExecutionContext;
  rootNodeId: NodeID;
}

export function attachLegacyBridge(opts: AttachLegacyBridgeOptions): void {
  const { bus, context, rootNodeId } = opts;

  bus.on("subagent-spawn", (payload) => {
    if (context.resolveLegacySubagent(payload.subagentId)) return;
    const parentNodeId = payload.parentSubagentId
      ? context.resolveLegacySubagent(payload.parentSubagentId) ?? rootNodeId
      : rootNodeId;
    context.registerNode({
      kind: "agent",
      name: payload.name ?? payload.subagentId,
      parentNodeId,
      legacySubagentId: payload.subagentId,
      payload: { input: payload.input },
      initialState: "running",
    });
  });

  bus.on("subagent-complete", (payload) => {
    const nodeId = context.resolveLegacySubagent(payload.subagentId);
    if (!nodeId) return;
    context.completeNode({
      nodeId,
      errorMessage: payload.status === "failed" ? "subagent failed" : undefined,
    });
  });

  bus.on("tool-call-complete", (payload) => {
    const emitterNodeId = payload.subagentId
      ? context.resolveLegacySubagent(payload.subagentId) ?? rootNodeId
      : rootNodeId;
    if (context.resolveExternalToolCall(payload.toolCallId)) return;
    context.registerNode({
      kind: "tool_call",
      name: payload.toolName,
      parentNodeId: emitterNodeId,
      externalToolCallId: payload.toolCallId,
      payload: { toolName: payload.toolName, args: payload.args },
      initialState: "running",
    });
  });

  bus.on("tool-result", (payload) => {
    const nodeId = context.resolveExternalToolCall(payload.toolCallId);
    if (!nodeId) return;
    context.completeNode({ nodeId, result: payload.result });
  });

  bus.on("error", (payload) => {
    const nodeId = payload.subagentId
      ? context.resolveLegacySubagent(payload.subagentId) ?? rootNodeId
      : rootNodeId;
    const message =
      payload.error instanceof Error
        ? payload.error.message
        : String(payload.error);
    context.transitionNode(nodeId, "error", message);
  });

  bus.on("command-output", (payload) => {
    const nodeId = payload.subagentId
      ? context.resolveLegacySubagent(payload.subagentId) ?? rootNodeId
      : rootNodeId;
    context.emitCommandOutput(nodeId, payload.data);
  });

  bus.on("workflow-phase-start", (payload) => {
    const phaseKey = `__phase__:${payload.phase}`;
    if (context.resolveLegacySubagent(phaseKey)) return;
    context.registerNode({
      kind: "workflow",
      name: payload.label,
      parentNodeId: rootNodeId,
      legacySubagentId: phaseKey,
      payload: {
        workflow: payload.label,
        phase: payload.phase,
        input: payload.metadata,
      },
      initialState: "running",
    });
  });

  bus.on("workflow-phase-complete", (payload) => {
    const phaseKey = `__phase__:${payload.phase}`;
    const nodeId = context.resolveLegacySubagent(phaseKey);
    if (!nodeId) return;
    context.completeNode({ nodeId, result: payload.summary });
  });
}
