import { randomUUID } from "node:crypto";
import type { ModelMessage } from "ai";
import type { ResearchContext } from "./researchContext";

export interface SteerInput {
  expectedTurnId: string;
  text: string;
  inputId?: string;
}

export type SteerResult =
  | { accepted: true; turnId: string; inputId: string }
  | { accepted: false; reason: "inactive" | "stale-turn" };

/** One admission gate per run; delivery happens only between model steps. */
export class TurnSteering {
  readonly turnId = randomUUID();
  private context?: ResearchContext;
  private closed = false;
  private pending = new Set<string>();
  private receipts = new Map<
    string,
    { text: string; result: Promise<SteerResult> }
  >();

  attach(context: ResearchContext): void {
    this.context = context;
  }

  latest(): ModelMessage[] {
    if (!this.context) throw new Error("Steering has no active context");
    return this.context.latest();
  }

  async steer(input: SteerInput): Promise<SteerResult> {
    if (input.expectedTurnId !== this.turnId)
      return { accepted: false, reason: "stale-turn" };
    const id = input.inputId ?? randomUUID();
    const previous = this.receipts.get(id);
    if (previous) {
      if (previous.text !== input.text)
        throw new Error("Steering inputId already belongs to different input");
      return previous.result;
    }
    if (this.closed || !this.context)
      return { accepted: false, reason: "inactive" };
    if (!input.text.trim()) throw new Error("Steering input cannot be empty");
    this.pending.add(id);
    const result = this.context.queueInput({ id, text: input.text }).then(
      (): SteerResult => ({
        accepted: true,
        turnId: this.turnId,
        inputId: id,
      }),
    );
    this.receipts.set(id, { text: input.text, result });
    return result;
  }

  async take(messages: ModelMessage[]): Promise<ModelMessage[]> {
    if (!this.pending.size || !this.context) return messages;
    const delivered = await this.context.takeInputs(messages);
    for (const id of delivered.ids) this.pending.delete(id);
    return delivered.messages;
  }

  /** Close synchronously with the empty check so late input cannot be accepted and lost. */
  continue(): boolean {
    if (this.closed) return false;
    if (this.pending.size) return true;
    this.close();
    return false;
  }

  close(): void {
    this.closed = true;
  }
}
