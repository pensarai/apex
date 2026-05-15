import { createReadStream } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import type { SessionID } from "./ids.ts";
import { type ApexMessage, ApexMessageSchema } from "./messages.ts";

function getBaseDir(): string {
  return process.env.PENSAR_DATA_DIR ?? path.join(os.homedir(), ".pensar");
}

export function sessionEventsPath(sessionId: SessionID): string {
  return path.join(getBaseDir(), "sessions", sessionId, "events.jsonl");
}

/**
 * Local on-disk JSONL writer/reader for an ApexMessage stream.
 *
 * Shape parity with `agent_events`: one ApexMessage per line, JSON-encoded.
 * The DB schema and the JSONL format share the same union — flipping between
 * them is "use a different consumer," not "translate."
 */
export class SessionStorage {
  private writeChain: Promise<unknown> = Promise.resolve();

  constructor(public readonly sessionId: SessionID) {}

  get filePath(): string {
    return sessionEventsPath(this.sessionId);
  }

  /** Append a single message. Awaits sequentially to preserve JSONL line order. */
  append(message: ApexMessage): Promise<void> {
    const line = `${JSON.stringify(message)}\n`;
    this.writeChain = this.writeChain
      .then(() => fs.mkdir(path.dirname(this.filePath), { recursive: true }))
      .then(() => fs.appendFile(this.filePath, line, "utf-8"));
    return this.writeChain as Promise<void>;
  }

  /** Yield every message from disk, validated against the Zod schema. */
  async *read(): AsyncGenerator<ApexMessage, void, unknown> {
    let exists = true;
    try {
      await fs.access(this.filePath);
    } catch {
      exists = false;
    }
    if (!exists) return;

    // Wait for any in-flight write before reading.
    await this.writeChain;

    const stream = createReadStream(this.filePath, { encoding: "utf-8" });
    const lines = createInterface({ input: stream, crlfDelay: Infinity });
    for await (const raw of lines) {
      if (raw.length === 0) continue;
      const parsed = JSON.parse(raw);
      yield ApexMessageSchema.parse(parsed);
    }
  }

  /** Read all messages eagerly. Convenient for tests. */
  async readAll(): Promise<ApexMessage[]> {
    const out: ApexMessage[] = [];
    for await (const m of this.read()) out.push(m);
    return out;
  }

  /** Delete the session's on-disk state. Used by tests. */
  async clear(): Promise<void> {
    await this.writeChain.catch(() => {});
    await fs.rm(path.dirname(this.filePath), { recursive: true, force: true });
    this.writeChain = Promise.resolve();
  }
}
