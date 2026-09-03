import type { LanguageModelMiddleware } from "ai";
import { stepCountIs } from "ai";
import type {
  AIModel,
  OpenAIReasoningEffort,
  ThinkingEffort,
  UsageRecorder,
} from "../../../ai";
import type { AIAuthConfig } from "../../../ai/utils";
import type { AgentEventBus } from "../../../eventBus";
import type { SessionInfo } from "../../../session";
import { OffensiveSecurityAgent } from "../../offSecAgent";
import type { UnifiedSandbox } from "../../offSecAgent/tools";
import type { StreamIdFactory } from "../../offSecAgent/types";
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
  /** Provider middleware applied only to this agent's model calls. Unset → raw model. */
  languageModelMiddleware?: LanguageModelMiddleware | LanguageModelMiddleware[];
  /** Per-run usage recorder. Unset → the process-global usage callback fires as today. */
  usageRecorder?: UsageRecorder;
  /** Factory for streamed message/part ids. Unset → random ULIDs, unchanged. */
  streamIdFactory?: StreamIdFactory;
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
    const {
      finding,
      target: targetOpt,
      subagentId,
      subagentName,
      ...base
    } = opts;
    const target = finding.target ?? targetOpt ?? base.session.targets[0];

    super({
      ...base,
      system: detectOSAndEnhancePrompt(FINDING_JUDGE_SYSTEM_PROMPT),
      activeTools: [...FINDING_JUDGE_ACTIVE_TOOLS],
      responseSchema: FindingJudgeOutputSchema,
      stopWhen: stepCountIs(60),
      target,
      prompt: buildFindingJudgePrompt({ ...finding, target }),
      subagentId: subagentId ?? "finding-judge",
      subagentName: subagentName ?? "Finding Judge",
    });
  }
}
