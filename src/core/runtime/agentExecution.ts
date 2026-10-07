export type AgentExecutionHandle<TResult> = {
  /** The run's structured result; may settle before {@link drained}. */
  result: Promise<TResult>;
  /** Force-disconnect owned resources + await drain. Idempotent; never throws. */
  abortAndDrain: () => Promise<void>;
  /** Settles when the background drain (span teardown included) completes. */
  drained: Promise<void>;
};

type ExecutableAgent<TResult> = {
  consume(): Promise<TResult>;
  drained: Promise<void>;
  abortAndDrain(): Promise<void>;
};

export function startAgentExecution<TResult>(
  agent: ExecutableAgent<TResult>,
): AgentExecutionHandle<TResult> {
  const result = agent.consume();
  return {
    result,
    abortAndDrain: () => agent.abortAndDrain(),
    // `drained` is reassigned inside consume(); read it only after execution
    // started, or the handle would capture the pre-run placeholder promise.
    drained: agent.drained,
  };
}
