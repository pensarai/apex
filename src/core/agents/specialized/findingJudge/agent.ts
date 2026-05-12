import { stepCountIs } from "ai";
import type { AIModel } from "../../../ai";
import type { AIAuthConfig } from "../../../ai/utils";
import type { AgentEventBus } from "../../../eventBus";
import type { SessionInfo } from "../../../session";
import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import type { UnifiedSandbox } from "../../offSecAgent/tools";
import { detectOSAndEnhancePrompt } from "../utils";
import { buildFindingJudgePrompt, FINDING_JUDGE_SYSTEM_PROMPT } from "./prompts";
import {
  FindingJudgeOutputSchema,
  type FindingJudgeAgentOutput,
  type FindingJudgeInput,
} from "./types";

export interface FindingJudgeAgentInput {
  finding: FindingJudgeInput;
  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  eventBus?: AgentEventBus;
  sandbox?: UnifiedSandbox;
  target?: string;
  enableThinking?: boolean;
}

export const FINDING_JUDGE_ACTIVE_TOOLS = [
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
    const target = opts.finding.target ?? opts.target ?? opts.session.targets[0];

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
      subagentId: "finding-judge",
      activeTools: [...FINDING_JUDGE_ACTIVE_TOOLS],
      responseSchema: FindingJudgeOutputSchema,
      stopWhen: stepCountIs(60),
    });
  }
}
