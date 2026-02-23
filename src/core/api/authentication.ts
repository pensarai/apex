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
  } = await agent.consume();

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
