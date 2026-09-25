import { stepCountIs } from "ai";
import type {
  AgentToolProtocolPreference,
  AIModel,
  OpenAIReasoningEffort,
  ThinkingEffort,
} from "../../../ai";
import type { AIAuthConfig } from "../../../ai/utils";
import type { AgentEventBus } from "../../../eventBus";
import type { SessionInfo } from "../../../session";
import type { EngagementContext } from "../../../workflows/engagementSurface";
import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import type { UnifiedSandbox } from "../../offSecAgent/tools";
import { detectOSAndEnhancePrompt } from "../utils";
import {
  buildFindingJudgePrompt,
  FINDING_JUDGE_SYSTEM_PROMPT,
} from "./prompts";
import {
  type FindingJudgeAgentOutput,
  type FindingJudgeInput,
  FindingJudgeOutputSchema,
} from "./types";

export interface FindingJudgeAgentInput {
  finding: FindingJudgeInput;
  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  eventBus?: AgentEventBus;
  /** Id used to tag the judge's stream events. Defaults to "finding-judge". */
  subagentId?: string;
  /** Human-readable label for readable OTel span names. Defaults to "Finding Judge". */
  subagentName?: string;
  sandbox?: UnifiedSandbox;
  target?: string;
  enableThinking?: boolean;
  thinkingEffort?: ThinkingEffort | null;
  openAIReasoningEffort?: OpenAIReasoningEffort | null;
  toolProtocol?: AgentToolProtocolPreference;
  engagementContext?: EngagementContext;
}

const FINDING_JUDGE_ACTIVE_TOOLS = [
  "execute_command",
  "http_request",
  "read_file",
  "list_files",
  "grep",
  "web_search",
  "get_page",
  "response",
] as const;

export class FindingJudgeAgent extends OffensiveSecurityAgent<FindingJudgeAgentOutput> {
  constructor(opts: FindingJudgeAgentInput) {
    const target =
      opts.finding.target ?? opts.target ?? opts.session.targets[0];

    super({
      system: detectOSAndEnhancePrompt(FINDING_JUDGE_SYSTEM_PROMPT),
      prompt: buildFindingJudgePrompt({ ...opts.finding, target }),
      model: opts.model,
      session: opts.session,
      target,
      authConfig: opts.authConfig,
      abortSignal: opts.abortSignal,
      eventBus: opts.eventBus,
      sandbox: opts.sandbox,
      enableThinking: opts.enableThinking,
      thinkingEffort: opts.thinkingEffort,
      openAIReasoningEffort: opts.openAIReasoningEffort,
      toolProtocol: opts.toolProtocol,
      engagementContext: opts.engagementContext,
      subagentId: opts.subagentId ?? "finding-judge",
      subagentName: opts.subagentName ?? "Finding Judge",
      activeTools: [...FINDING_JUDGE_ACTIVE_TOOLS],
      responseSchema: FindingJudgeOutputSchema,
      responseGuard: () => {
        if (!opts.engagementContext || !opts.finding.sourceTargetId) return;
        const receipt = opts.engagementContext
          .receipts()
          .find((item) => item.targetId === opts.finding.sourceTargetId);
        if (!receipt) {
          return `Read the complete authorized target context for ${opts.finding.sourceTargetId} before deciding.`;
        }
        if (receipt.status === "read" && !receipt.complete) {
          return `Read every target-context page for ${opts.finding.sourceTargetId} before deciding.`;
        }
      },
      stopWhen: stepCountIs(60),
    });
  }
}
