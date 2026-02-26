/**
 * TUI Hooks
 *
 * Reusable React hooks for TUI components.
 */

export {
  useAgentMessages,
  toolResultUpdater,
  type UseAgentMessagesReturn,
} from "./use-agent-messages";

export {
  usePentestOrchestration,
  type Phase,
  type AgentState,
  type UsePentestOrchestrationReturn,
} from "./use-pentest-orchestration";

export {
  useAssetPolling,
  type UseAssetPollingReturn,
} from "./use-asset-polling";
