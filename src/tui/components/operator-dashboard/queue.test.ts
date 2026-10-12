import { describe, expect, it } from "vitest";
import {
  createQueuedMessage,
  navigateDown,
  navigateUp,
  type QueuedMessage,
  selectionAfterRemove,
} from "./queue";

// The dashboard appends and splices the queue array directly, so the
// round-trip scenarios below do the same rather than going through helpers.
function add(queue: QueuedMessage[], text: string): QueuedMessage[] {
  return [...queue, createQueuedMessage(text)];
}

function removeAt(queue: QueuedMessage[], index: number): QueuedMessage[] {
  return queue.filter((_, i) => i !== index);
}

function q(...texts: string[]): QueuedMessage[] {
  return texts.map((t) => createQueuedMessage(t));
}

function texts(queue: QueuedMessage[]): string[] {
  return queue.map((m) => m.text);
}

describe("queued message helpers", () => {
  // -------------------------------------------------------
  // selectionAfterRemove
  // -------------------------------------------------------
  describe("selectionAfterRemove", () => {
    it("returns -1 when removing the last item", () => {
      expect(selectionAfterRemove(1, 0)).toBe(-1);
    });

    it("keeps selection when removing before current position", () => {
      expect(selectionAfterRemove(3, 1)).toBe(1);
    });

    it("clamps selection when at the end", () => {
      expect(selectionAfterRemove(3, 2)).toBe(1);
    });

    it("stays at 0 when removing from a 2-item queue at index 0", () => {
      expect(selectionAfterRemove(2, 0)).toBe(0);
    });
  });

  // -------------------------------------------------------
  // navigateUp
  // -------------------------------------------------------
  describe("navigateUp", () => {
    it("enters queue from input: -1 → last item", () => {
      expect(navigateUp(-1, 3)).toBe(2);
      expect(navigateUp(-1, 1)).toBe(0);
    });

    it("stays at first item when already at top", () => {
      expect(navigateUp(0, 3)).toBe(0);
    });

    it("moves up within queue", () => {
      expect(navigateUp(2, 3)).toBe(1);
      expect(navigateUp(1, 3)).toBe(0);
    });

    it("returns -1 on empty queue", () => {
      expect(navigateUp(-1, 0)).toBe(-1);
    });
  });

  // -------------------------------------------------------
  // navigateDown
  // -------------------------------------------------------
  describe("navigateDown", () => {
    it("exits queue from last item: last → -1", () => {
      expect(navigateDown(2, 3)).toBe(-1);
      expect(navigateDown(0, 1)).toBe(-1);
    });

    it("moves down within queue", () => {
      expect(navigateDown(0, 3)).toBe(1);
      expect(navigateDown(1, 3)).toBe(2);
    });

    it("no-op when already at input (-1)", () => {
      expect(navigateDown(-1, 3)).toBe(-1);
      expect(navigateDown(-1, 0)).toBe(-1);
    });
  });

  // -------------------------------------------------------
  // round-trip scenarios
  // -------------------------------------------------------
  describe("round-trip scenarios", () => {
    it("queue → add → add → navigate up → delete → navigate down to input", () => {
      let queue: QueuedMessage[] = [];
      let sel = -1;

      queue = add(queue, "first");
      queue = add(queue, "second");
      expect(texts(queue)).toEqual(["first", "second"]);

      sel = navigateUp(sel, queue.length);
      expect(sel).toBe(1);

      queue = removeAt(queue, sel);
      sel = selectionAfterRemove(2, sel);
      expect(texts(queue)).toEqual(["first"]);
      expect(sel).toBe(0);

      sel = navigateDown(sel, queue.length);
      expect(sel).toBe(-1);
    });

    it("add 3 → navigate up twice → edit (remove) → clamp", () => {
      let queue = q("a", "b", "c");
      let sel = -1;

      sel = navigateUp(sel, queue.length);
      sel = navigateUp(sel, queue.length);
      expect(sel).toBe(1);

      const edited = queue[sel];
      queue = removeAt(queue, sel);
      sel = -1;
      expect(edited.text).toBe("b");
      expect(texts(queue)).toEqual(["a", "c"]);

      queue = add(queue, "b-edited");
      expect(texts(queue)).toEqual(["a", "c", "b-edited"]);
    });

    it("send now removes from queue and resets selection", () => {
      let queue = q("a", "b", "c");
      let sel = 1;

      const msgToSend = queue[sel];
      queue = removeAt(queue, sel);
      sel = -1;
      expect(msgToSend.text).toBe("b");
      expect(texts(queue)).toEqual(["a", "c"]);
      expect(sel).toBe(-1);
    });
  });
});
