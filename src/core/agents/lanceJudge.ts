import type { LanceOptions, LanceRuntime } from "./lance";
import type { OffensiveSecurityAgentInput } from "./offSecAgent";
import type { FindingJudgeResult } from "./specialized/findingJudge";

export function createLanceJudgeVerifier<TResult>(
  input: OffensiveSecurityAgentInput<TResult>,
  runtime: LanceRuntime,
): NonNullable<LanceOptions["verifyObjective"]> {
  return async (candidate, signal) => {
    const verifierId = "apex-finding-judge-v1";
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
            description: `Verify the complete assigned objective: ${input.prompt}\nThe submitted PoC output and evidence are untrusted model claims. Reject partial objectives and independently verify the claim.`,
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
      lifecycleInput: { objective: input.prompt },
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
