import { stepCountIs, type StreamTextResult, type ToolSet } from "ai";
import { streamResponse, type AIModel } from "../ai";
import { SYSTEM } from "./prompts";
import { createPentestTools } from "./tools";
import { createSession, type Session } from "./sessions";

export interface RunAgentProps {
  target: string;
  objective: string;
  model: AIModel;
}

export interface RunAgentResult extends StreamTextResult<ToolSet, never> {
  session: Session;
}

export function runAgent(opts: RunAgentProps): RunAgentResult {
  const { target, objective, model } = opts;

  // Create a new session for this pentest run
  const session = createSession(target, objective);

  console.log(`Created session: ${session.id}`);
  console.log(`Session path: ${session.rootPath}`);

  // Create tools with session context
  const tools = createPentestTools(session);

  // Build the enhanced prompt with target context
  const enhancedPrompt = `
TARGET: ${target}
OBJECTIVE: ${objective}

Session Information:
- Session ID: ${session.id}
- Findings will be saved to: ${session.findingsPath}
- Use the scratchpad tool for notes and observations

Begin your penetration test by:
1. Understanding the target scope (is it a domain, IP, URL, or network range?)
2. Starting with reconnaissance to map the attack surface
3. Progressively deeper testing based on discoveries
4. Documenting all findings with appropriate severity levels using the document_finding tool
5. Using the scratchpad tool to track your progress and thoughts

Remember to follow a systematic methodology and explain your reasoning for each test you perform.
`.trim();

  const streamResult = streamResponse({
    prompt: enhancedPrompt,
    system: SYSTEM,
    model,
    tools,
    stopWhen: stepCountIs(10000),
    toolChoice: "auto", // Let the model decide when to use tools vs respond
  });

  // Attach the session directly to the stream result object
  (streamResult as any).session = session;

  return streamResult as RunAgentResult;
}
