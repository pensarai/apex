import type { AgenticTranscript } from "../types";
import type { CreateSessionInput, TargetAdapter } from "./types";

/**
 * Offline adapter for dry runs / tests. Echoes the prompt and never fires
 * canaries, so the full pipeline (scoring, findings, reporting) can be
 * exercised without network access or credentials.
 */
export class MockAdapter implements TargetAdapter {
  private readonly prompts = new Map<string, string>();
  private counter = 0;

  async createSession(
    input: CreateSessionInput,
  ): Promise<{ sessionId: string }> {
    const sessionId = `mock-${++this.counter}`;
    this.prompts.set(sessionId, input.prompt);
    return { sessionId };
  }

  async getTranscript(sessionId: string): Promise<AgenticTranscript> {
    return {
      sessionId,
      status: "completed",
      messages: [
        { role: "user", text: this.prompts.get(sessionId) ?? "" },
        {
          role: "agent",
          text: "[mock] dry run — no request was sent to a live agent.",
        },
      ],
    };
  }

  async pollUntilTerminal(sessionId: string): Promise<AgenticTranscript> {
    return this.getTranscript(sessionId);
  }
}
