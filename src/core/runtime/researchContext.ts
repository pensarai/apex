import { existsSync, readFileSync } from "node:fs";
import { appendFile, mkdir, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import type { ModelMessage } from "ai";
import {
  getReasoningCapabilities,
  type ReasoningSetting,
} from "../ai/reasoning";
import { RunPersistenceError } from "./persistenceError";
import type { RunContextRecorder } from "./runContext";

interface ResearchState {
  version: 1;
  messages: ModelMessage[];
  system?: string;
  currentSystem?: string;
  model: string;
  reasoning?: ReasoningSetting;
  currentReasoning?: ReasoningSetting;
  pendingInputs?: { id: string; text: string }[];
}

/** Durable v2 conversation authority; interfaces submit new messages, never rewrite history. */
export class ResearchContext implements RunContextRecorder {
  private state: ResearchState;
  private tail: Promise<void> = Promise.resolve();
  private failure?: Error;
  private readonly path: string;
  private readonly journal: string;
  private committed: ModelMessage[] = [];
  private handoff = false;
  private inputPending = true;

  constructor(
    private readonly rootPath: string,
    input: {
      model: string;
      reasoning?: ReasoningSetting;
      prompt: string;
      messages?: ModelMessage[];
      newMessages?: ModelMessage[];
      recorder?: RunContextRecorder;
    },
  ) {
    this.path = join(rootPath, "research-context.json");
    this.journal = join(rootPath, "research-context.jsonl");
    this.upstream = input.recorder;
    const stored: ResearchState | undefined = existsSync(this.path)
      ? JSON.parse(readFileSync(this.path, "utf8"))
      : undefined;
    if (stored && (stored.version !== 1 || !Array.isArray(stored.messages)))
      throw new Error(
        "Invalid v2 research context; refusing to discard history",
      );
    const legacyPath = join(rootPath, "messages.json");
    const bootstrap =
      input.recorder?.latest() ??
      input.messages ??
      (!stored && existsSync(legacyPath)
        ? (JSON.parse(readFileSync(legacyPath, "utf8")) as ModelMessage[])
        : []);
    this.committed = stored?.messages ?? [];
    this.state = stored ?? {
      version: 1,
      model: input.model,
      reasoning: input.reasoning,
      currentReasoning: input.reasoning,
      messages: structuredClone(bootstrap),
    };
    if (input.recorder?.latest())
      this.state.messages = structuredClone(bootstrap);
    let additions: ModelMessage[];
    if (input.newMessages !== undefined) {
      additions = input.newMessages;
    } else if (stored && input.messages) {
      const history = this.state.messages;
      if (
        !history.every((message, index) =>
          isDeepStrictEqual(message, input.messages?.[index]),
        )
      )
        throw new Error(
          "V2 history is owned by the session. Pass newMessages to append input.",
        );
      additions = input.messages.slice(history.length);
    } else {
      additions =
        input.prompt && !(bootstrap.length && !stored)
          ? [{ role: "user", content: input.prompt }]
          : [];
    }
    additions = [
      ...(this.state.pendingInputs ?? []).map(
        ({ text }): ModelMessage => ({ role: "user", content: text }),
      ),
      ...additions,
    ];
    this.state.pendingInputs = [];
    this.state.messages = [
      ...this.state.messages,
      ...structuredClone(additions),
    ];
    if (this.state.model !== input.model) {
      // Opaque provider state cannot migrate between models; replay the retained evidence.
      this.handoff = true;
      if (existsSync(this.journal)) {
        const events = readFileSync(this.journal, "utf8")
          .trim()
          .split("\n")
          .filter(Boolean)
          .map(
            (line) =>
              JSON.parse(line) as { kind: string; messages: ModelMessage[] },
          );
        const history = events.reduce<ModelMessage[]>(
          (messages, event) =>
            event.kind === "handoff"
              ? event.messages
              : event.kind === "append"
                ? [...messages, ...event.messages]
                : messages,
          [],
        );
        this.state.messages = [...history, ...additions].flatMap((message) => {
          if (message.role === "system" && message.content === "") return [];
          if (
            message.role !== "assistant" ||
            typeof message.content === "string"
          )
            return [message];
          const content = message.content.filter(
            (part) => part.type !== "reasoning" && part.type !== "custom",
          );
          return content.length ? [{ ...message, content }] : [];
        });
      }
      this.state.model = input.model;
      this.state.reasoning = input.reasoning;
      this.state.currentReasoning = input.reasoning;
    } else if (input.reasoning !== this.state.currentReasoning) {
      if (
        /^gpt-6(?:[.-]|$)/.test(input.model) &&
        input.reasoning &&
        !["enabled", "disabled", "minimal"].includes(input.reasoning)
      ) {
        this.state.messages.splice(
          this.state.messages.length - additions.length,
          0,
          {
            role: "system",
            content: "",
            providerOptions: {
              openai: {
                reasoningEffortUpdate:
                  input.reasoning === "default"
                    ? getReasoningCapabilities(input.model).defaultEffort
                    : input.reasoning,
              },
            },
          },
        );
      } else {
        this.state.reasoning = input.reasoning;
      }
      this.state.currentReasoning = input.reasoning;
    }
  }

  private readonly upstream?: RunContextRecorder;

  prepare(system: string): {
    system: string;
    messages: ModelMessage[];
    reasoning?: ReasoningSetting;
  } {
    if (this.state.system === undefined) this.state.system = system;
    else if ((this.state.currentSystem ?? this.state.system) !== system) {
      const before = (this.state.currentSystem ?? this.state.system).split(
        "\n",
      );
      const after = system.split("\n");
      let start = 0;
      while (
        start < before.length &&
        start < after.length &&
        before[start] === after[start]
      )
        start++;
      let end = 0;
      while (
        end < before.length - start &&
        end < after.length - start &&
        before[before.length - 1 - end] === after[after.length - 1 - end]
      )
        end++;
      const removed = before.slice(start, before.length - end).join("\n");
      const added = after.slice(start, after.length - end).join("\n");
      this.state.messages.push({
        role: "system",
        content: `Session instruction update. Keep all other instructions unchanged.\n\nWithdraw these earlier instructions:\n${removed || "(none)"}\n\nApply these replacement instructions:\n${added || "(none)"}`,
      });
    }
    this.state.currentSystem = system;
    return {
      system: this.state.system,
      messages: this.latest(),
      reasoning: this.state.reasoning,
    };
  }

  checkpoint(input: {
    messages: ModelMessage[];
    system?: string | null;
  }): Promise<void> {
    if (this.inputPending) {
      this.inputPending = false;
      // Journal fresh input before provider preparation can compact its prefix.
      // Queue both writes immediately so concurrent checkpoints retain their order.
      if (
        !this.state.messages.every((message, index) =>
          isDeepStrictEqual(message, input.messages[index]),
        )
      )
        void this.checkpoint({ messages: this.latest() }).catch(() => {});
    }
    const messages = structuredClone(input.messages);
    return this.enqueue(() =>
      this.commit({ ...this.state, messages }, input.system),
    );
  }

  queueInput(input: { id: string; text: string }): Promise<void> {
    return this.enqueue(() =>
      this.save({
        ...this.state,
        pendingInputs: [...(this.state.pendingInputs ?? []), input],
      }),
    );
  }

  takeInputs(messages: ModelMessage[]): Promise<{
    messages: ModelMessage[];
    ids: string[];
  }> {
    return this.enqueue(async () => {
      const inputs = this.state.pendingInputs ?? [];
      const next: ModelMessage[] = [
        ...messages,
        ...inputs.map(
          ({ text }): ModelMessage => ({ role: "user", content: text }),
        ),
      ];
      if (inputs.length)
        await this.commit({ ...this.state, messages: next, pendingInputs: [] });
      return { messages: next, ids: inputs.map(({ id }) => id) };
    });
  }

  private async commit(
    state: ResearchState,
    system?: string | null,
  ): Promise<void> {
    const upstreamMessages = state.messages;
    // Anthropic's cache marker is transport-only; system text is retained separately.
    if (
      state.messages[0]?.role === "system" &&
      state.messages[0].content === state.system
    )
      state.messages = state.messages.slice(1);
    await this.upstream?.checkpoint({ messages: upstreamMessages, system });
    await this.upstream?.flush();
    await mkdir(this.rootPath, { recursive: true });
    const previous = this.committed;
    const append = previous.every((message, index) =>
      isDeepStrictEqual(message, state.messages[index]),
    );
    await appendFile(
      this.journal,
      `${JSON.stringify({
        kind: this.handoff ? "handoff" : append ? "append" : "replace",
        messages:
          append && !this.handoff
            ? state.messages.slice(previous.length)
            : state.messages,
        system: state.system,
      })}\n`,
    );
    await this.save(state);
    this.handoff = false;
    this.committed = state.messages;
  }

  private async save(state: ResearchState): Promise<void> {
    await mkdir(this.rootPath, { recursive: true });
    await writeFile(`${this.path}.tmp`, JSON.stringify(state));
    await rename(`${this.path}.tmp`, this.path);
    this.state = state;
  }

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const work = this.tail
      .then(() => {
        if (this.failure) throw this.failure;
        return operation();
      })
      .catch((cause) => {
        this.failure ??= new RunPersistenceError(cause);
        throw this.failure;
      });
    this.tail = work.then(
      () => {},
      () => {},
    );
    return work;
  }

  async flush(): Promise<void> {
    await this.tail;
    if (this.failure) throw this.failure;
    await this.upstream?.flush();
  }

  latest(): ModelMessage[] {
    return structuredClone(this.state.messages);
  }
}
