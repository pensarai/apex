import {
  AuthenticationAgent,
  type AuthenticationAgentInput,
} from "../agents/authenticationAgent";
// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

export async function runAuthenticationAgent(input: AuthenticationAgentInput) {
  const agent = new AuthenticationAgent(input);

  const { success, summary } = await agent.consume({
    onTextDelta: (d) => process.stdout.write(d.text),
    onToolCall: (d) => console.log(`→ calling ${d.toolName}`),
    onToolResult: (d) => console.log(`✓ ${d.toolName} completed`),
    onError: (e) => console.error("Agent error:", e),
  });

  console.log(
    `\nAuthentication ${success ? "succeeded" : "failed"}: ${summary}`
  );
  return { success, summary };
}
