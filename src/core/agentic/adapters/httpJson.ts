import type { AgenticAdapterConfig } from "../config";
import type { AgenticTranscript } from "../types";
import { asText, authHeaders, getByPath, setByPath } from "./paths";
import type { CreateSessionInput, TargetAdapter } from "./types";

const DEFAULT_MESSAGE_PATH = "message";
const DEFAULT_TEXT_PATH = "output";

/**
 * Generic single-shot JSON adapter. Injects the user message into a request
 * body (a static `request.template` cloned, with the message set at
 * `request.messagePath`) and reads the assistant text from `response.textPath`.
 *
 * Single-shot endpoints have no conversation state, so seed turns are folded
 * into the prompt as a prefixed context block.
 */
export class HttpJsonAdapter implements TargetAdapter {
  private readonly transcripts = new Map<string, AgenticTranscript>();
  private counter = 0;

  constructor(
    private readonly cfg: AgenticAdapterConfig,
    private readonly timeoutMs = 120_000,
  ) {}

  async createSession(
    input: CreateSessionInput,
  ): Promise<{ sessionId: string }> {
    const sessionId = `http-${++this.counter}`;
    const seeds = input.seedMessages ?? [];
    const content = seeds.length
      ? `${seeds.join("\n\n")}\n\n${input.prompt}`
      : input.prompt;

    const body: Record<string, unknown> = structuredClone(
      this.cfg.request?.template ?? {},
    );
    setByPath(
      body,
      this.cfg.request?.messagePath ?? DEFAULT_MESSAGE_PATH,
      content,
    );

    const res = await fetch(this.cfg.endpoint, {
      method: "POST",
      headers: authHeaders(this.cfg),
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) {
      throw new Error(
        `http-json request failed: ${res.status} ${await res.text()}`,
      );
    }
    const json = await res.json().catch(() => ({}));
    const text = asText(
      getByPath(json, this.cfg.response?.textPath ?? DEFAULT_TEXT_PATH),
    );

    this.transcripts.set(sessionId, {
      sessionId,
      status: "completed",
      messages: [
        { role: "user", text: content },
        { role: "agent", text },
      ],
      structuredOutput: json,
    });
    return { sessionId };
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
