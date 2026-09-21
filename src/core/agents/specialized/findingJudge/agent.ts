import { stepCountIs } from "ai";
import { AgentRuntime } from "../../agentRuntime";
import { defineAgent } from "../../defineAgent";
import type { SpecializedAgentInput } from "../../offSecAgent";
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

export interface FindingJudgeAgentInput extends SpecializedAgentInput {
  finding: FindingJudgeInput;
  target?: string;
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

function resolveTarget(opts: FindingJudgeAgentInput): string | undefined {
  return opts.finding.target ?? opts.target ?? opts.session.targets[0];
}

export const findingJudgeDefinition = defineAgent<
  FindingJudgeAgentInput,
  FindingJudgeAgentOutput
>({
  name: "finding-judge",
  role: "judge",
  system: () => detectOSAndEnhancePrompt(FINDING_JUDGE_SYSTEM_PROMPT),
  activeTools: () => [...FINDING_JUDGE_ACTIVE_TOOLS],
  responseSchema: () => FindingJudgeOutputSchema,
  stopWhen: () => stepCountIs(60),
  target: resolveTarget,
  prompt: (opts) =>
    buildFindingJudgePrompt({ ...opts.finding, target: resolveTarget(opts) }),
  subagentId: (opts) => opts.subagentId ?? "finding-judge",
  subagentName: (opts) => opts.subagentName ?? "Finding Judge",
});

export class FindingJudgeAgent extends AgentRuntime<
  FindingJudgeAgentInput,
  FindingJudgeAgentOutput
> {
  constructor(opts: FindingJudgeAgentInput) {
    super(findingJudgeDefinition, opts);
  }
}
