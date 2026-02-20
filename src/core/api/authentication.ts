import {
  AuthenticationAgent,
  type AuthenticationAgentInput,
} from "../agents/specialized/authenticationAgent/agent";
// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

export async function runAuthenticationAgent(input: AuthenticationAgentInput) {
  const agent = new AuthenticationAgent(input);

  const {
    success,
    summary,
    exportedCookies,
    exportedHeaders,
    strategy,
    authBarrier,
    authDataPath,
  } = await agent.consume({
    onTextDelta: (d) => input.callbacks?.onTextDelta?.(d),
    onToolCall: (d) => input.callbacks?.onToolCall?.(d),
    onToolResult: (d) => input.callbacks?.onToolResult?.(d),
    onError: (e) => input.callbacks?.onError?.(e),
    subagentCallbacks: input.callbacks?.subagentCallbacks,
  });

  console.log(
    `\nAuthentication ${success ? "succeeded" : "failed"}: ${summary}`,
  );
  return {
    success,
    summary,
    exportedCookies,
    exportedHeaders,
    strategy,
    authBarrier,
    authDataPath,
  };
}
