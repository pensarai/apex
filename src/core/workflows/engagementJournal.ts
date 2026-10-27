import { randomUUID } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ModelMessage } from "ai";

export type EngagementEventKind =
  | "mail"
  | "delivery"
  | "board"
  | "progress"
  | "help"
  | "finding"
  | "blocked"
  | "failed"
  | "completed";

export interface EngagementJournalEvent {
  id: string;
  kind: EngagementEventKind;
  at: string;
  from: string;
  to?: string;
  missionId?: string;
  text?: string;
  deliveredIds?: string[];
}

const MATERIAL_KINDS = new Set<EngagementEventKind>([
  "mail",
  "help",
  "finding",
  "blocked",
  "failed",
  "completed",
]);

export class EngagementJournal {
  private readonly path: string;
  private readonly events: EngagementJournalEvent[];
  private readonly listeners = new Set<
    (event: EngagementJournalEvent) => void
  >();

  constructor(sessionRoot: string) {
    this.path = join(sessionRoot, "coordination", "engagement-journal.jsonl");
    mkdirSync(dirname(this.path), { recursive: true });
    this.events = existsSync(this.path)
      ? readFileSync(this.path, "utf8")
          .split("\n")
          .filter(Boolean)
          .map((line) => JSON.parse(line) as EngagementJournalEvent)
      : [];
  }

  read(): EngagementJournalEvent[] {
    return [...this.events];
  }

  append(
    input: Omit<EngagementJournalEvent, "id" | "at">,
  ): EngagementJournalEvent {
    const event = { ...input, id: randomUUID(), at: new Date().toISOString() };
    appendFileSync(this.path, `${JSON.stringify(event)}\n`, "utf8");
    this.events.push(event);
    if (MATERIAL_KINDS.has(event.kind)) {
      for (const listener of this.listeners) listener(event);
    }
    return event;
  }

  onMaterial(listener: (event: EngagementJournalEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  board(
    offset = 0,
    limit = 50,
  ): { entries: EngagementJournalEvent[]; nextOffset: number | null } {
    const entries = this.read().filter((event) => event.kind === "board");
    return {
      entries: entries.slice(offset, offset + limit),
      nextOffset: offset + limit < entries.length ? offset + limit : null,
    };
  }

  private deliveredIds(recipient: string): Set<string> {
    return new Set(
      this.read()
        .filter((event) => event.kind === "delivery" && event.to === recipient)
        .flatMap((event) => event.deliveredIds ?? []),
    );
  }

  pending(recipient: string): EngagementJournalEvent[] {
    const delivered = this.deliveredIds(recipient);
    return this.read().filter(
      (event) =>
        event.kind === "mail" &&
        event.to === recipient &&
        !delivered.has(event.id),
    );
  }

  take(recipient: string): ModelMessage[] {
    const messages = this.pending(recipient);
    if (messages.length === 0) return [];
    // The delivery record is durable before the model can see these messages.
    // Resume replays it if the model step never reached transcript persistence.
    this.append({
      kind: "delivery",
      from: "host",
      to: recipient,
      deliveredIds: messages.map((message) => message.id),
    });
    return messages.map((message) => this.asModelMessage(message));
  }

  resumeMessages(
    recipient: string,
    transcript: ModelMessage[],
  ): ModelMessage[] {
    const delivered = this.deliveredIds(recipient);
    const serialized = JSON.stringify(transcript);
    const missing = this.read().filter(
      (event) =>
        event.kind === "mail" &&
        event.to === recipient &&
        delivered.has(event.id) &&
        !serialized.includes(`[engagement-mail:${event.id}]`),
    );
    return [
      ...transcript,
      ...missing.map((message) => this.asModelMessage(message)),
    ];
  }

  private asModelMessage(message: EngagementJournalEvent): ModelMessage {
    return {
      role: "user",
      content: `[engagement-mail:${message.id}] From ${message.from}: ${message.text ?? ""}`,
    };
  }
}
