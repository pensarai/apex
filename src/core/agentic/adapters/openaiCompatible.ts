import type { AgenticAdapterConfig } from "../config";
import type { AgenticTranscript } from "../types";
import { asText, authHeaders, getByPath } from "./paths";
import type { CreateSessionInput, TargetAdapter } from "./types";

const DEFAULT_TEXT_PATH = "choices.0.message.content";

/**
 * Adapter for OpenAI chat-completions-shaped endpoints. Sends a `messages`
 * array (seed turns then the attack) and reads the assistant text from
 * `choices[0].message.content` (override via `response.textPath`).
 */
export class OpenAICompatibleAdapter implements TargetAdapter {
  private readonly transcripts = new Map<string, AgenticTranscript>();
  private counter = 0;

  constructor(
    private readonly cfg: AgenticAdapterConfig,
    private readonly timeoutMs = 120_000,
  ) {}

  async createSession(
    input: CreateSessionInput,
  ): Promise<{ sessionId: string }> {
    const sessionId = `oai-${++this.counter}`;
    const wire: { role: string; content: string }[] = [];
    const rows: AgenticTranscript["messages"] = [];

    const turns = [...(input.seedMessages ?? []), input.prompt];
    for (const content of turns) {
      wire.push({ role: "user", content });
      rows.push({ role: "user", text: content });
      const reply = await this.send(wire);
      wire.push({ role: "assistant", content: reply });
      rows.push({ role: "assistant", text: reply });
    }

    this.transcripts.set(sessionId, {
      sessionId,
      status: "completed",
      messages: rows,
    });
    return { sessionId };
  }

  private async send(
    messages: { role: string; content: string }[],
  ): Promise<string> {
    const res = await fetch(this.cfg.endpoint, {
      method: "POST",
      headers: authHeaders(this.cfg),
      body: JSON.stringify({
        ...(this.cfg.model ? { model: this.cfg.model } : {}),
        messages,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) {
      throw new Error(
        `OpenAI-compatible request failed: ${res.status} ${await res.text()}`,
      );
    }
    const json = await res.json().catch(() => ({}));
    return asText(
      getByPath(json, this.cfg.response?.textPath ?? DEFAULT_TEXT_PATH),
    );
  }

  async getTranscript(sessionId: string): Promise<AgenticTranscript> {
    return (
      this.transcripts.get(sessionId) ?? {
        sessionId,
        status: "unknown",
        messages: [],
      }
    );
  }

  async pollUntilTerminal(sessionId: string): Promise<AgenticTranscript> {
    return this.getTranscript(sessionId);
  }
}
