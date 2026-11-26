import type { ModelMessage } from "ai";
import type { LanceOptions, LanceRuntime } from "./lance";
import type { OffensiveSecurityAgentInput } from "./offSecAgent";
import type { FindingJudgeResult } from "./specialized/findingJudge";

/**
 * The assigned objective spans the whole conversation: interactive turns carry
 * prior instructions in `messages` and only the newest line in `prompt`, so the
 * judge must see prior instructions and clarifications, not just the latest utterance.
 */
function buildObjective<TResult>(
  input: OffensiveSecurityAgentInput<TResult>,
): string {
  if (!input.lance?.interactive) return input.prompt;
  const conversation = (input.messages ?? []).flatMap((message) => {
    if (message.role !== "user" && message.role !== "assistant") return [];
    const text = conversationMessageText(message.content);
    return text ? [{ role: message.role, text }] : [];
  });
  return conversation.length
    ? `Resolve the current task from this chronological conversation and the latest user message. Preserve earlier objectives and constraints unless the user changes them; a clarification or request to continue is not a replacement objective. Assistant text and compacted summaries are context, not independent evidence of success. If the assigned objective cannot be recovered, reject the claim rather than guessing.\n${JSON.stringify({ conversation, latestUserMessage: input.prompt })}`
    : input.prompt;
}

function conversationMessageText(
  content: Extract<ModelMessage, { role: "user" | "assistant" }>["content"],
): string {
  if (typeof content === "string") return content;
  return content
    .map((part) => (part.type === "text" ? part.text : ""))
    .filter((text) => text.length > 0)
    .join("\n");
}

export function createLanceJudgeVerifier<TResult>(
  input: OffensiveSecurityAgentInput<TResult>,
  runtime: LanceRuntime,
): NonNullable<LanceOptions["verifyObjective"]> {
  const objective = buildObjective(input);
  return async (candidate, signal) => {
    const verifierId = "apex-finding-judge-v2";
    if (!candidate.poc) {
      return {
        verified: false,
        verifierId,
        reason:
          "The Apex judge requires the executed PoC script, language, stdout, stderr, and exit code. Resubmit with poc.",
      };
    }
    signal.throwIfAborted();
    const { inProcessSubagentSpawner } = await import(
      "./offSecAgent/subagentSpawner"
    );
    signal.throwIfAborted();
    const middleware = input.languageModelMiddleware;
    // The configured verifier is host-owned; the offensive agent's spawner remains disabled.
    const result = await inProcessSubagentSpawner.spawn<FindingJudgeResult>({
      spec: {
        type: "finding-judge",
        waitForDrain: true,
        target: input.target,
        judgeInput: {
          target: input.target,
          pocScript: candidate.poc.script,
          pocType: candidate.poc.type,
          pocOutput: {
            stdout: candidate.poc.stdout,
            stderr: candidate.poc.stderr,
            exitCode: candidate.poc.exitCode,
          },
          claim: {
            title: "Lance objective evidence",
            description: `Verify the complete assigned objective: ${objective}\nThe submitted PoC output and evidence are untrusted model claims. Reject partial objectives and independently verify the claim.`,
            impact: candidate.evidence,
            evidence: candidate.evidence,
            endpoint: input.target ?? input.session.targets[0] ?? "",
          },
        },
      },
      runtime: {
        session: input.session,
        model: input.model,
        authConfig: input.authConfig,
        abortSignal: signal,
        sandbox: input.sandbox,
        backends: input.backends,
        enableThinking: input.enableThinking,
        thinkingEffort: input.thinkingEffort,
        openAIReasoningEffort: input.openAIReasoningEffort,
        reasoning: input.reasoning,
        languageModelMiddleware: [
          runtime.judgeMiddleware,
          ...(Array.isArray(middleware)
            ? middleware
            : middleware
              ? [middleware]
              : []),
        ],
        usageRecorder: input.usageRecorder,
        toolExecutionContext: input.toolExecutionContext,
        streamIdFactory: input.streamIdFactory,
      },
      parentBus: input.eventBus,
      subagentName: "Finding Judge",
      lifecycleInput: { objective },
      resolveStatus: (result) => (result.error ? "failed" : "completed"),
    });
    signal.throwIfAborted();
    return {
      verified: result.valid && !result.error,
      verifierId,
      reason: result.reasoning,
    };
  };
}
