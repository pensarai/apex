import { describe, expect, it } from "vitest";
import {
  queueAdd,
  queueRemove,
  clampQueueSelection,
  selectionAfterRemove,
  navigateUp,
  navigateDown,
} from "./queue";

describe("queued message helpers", () => {
  // -------------------------------------------------------
  // queueAdd
  // -------------------------------------------------------
  describe("queueAdd", () => {
    it("appends to an empty queue", () => {
      expect(queueAdd([], "hello")).toEqual(["hello"]);
    });

    it("appends to a non-empty queue", () => {
      expect(queueAdd(["a", "b"], "c")).toEqual(["a", "b", "c"]);
    });

    it("does not mutate the original array", () => {
      const orig = ["a"];
      const result = queueAdd(orig, "b");
      expect(orig).toEqual(["a"]);
      expect(result).toEqual(["a", "b"]);
    });
  });

  // -------------------------------------------------------
  // queueRemove
  // -------------------------------------------------------
  describe("queueRemove", () => {
    it("removes the only item", () => {
      expect(queueRemove(["a"], 0)).toEqual([]);
    });

    it("removes first item from multi-item queue", () => {
      expect(queueRemove(["a", "b", "c"], 0)).toEqual(["b", "c"]);
    });

    it("removes middle item", () => {
      expect(queueRemove(["a", "b", "c"], 1)).toEqual(["a", "c"]);
    });

    it("removes last item", () => {
      expect(queueRemove(["a", "b", "c"], 2)).toEqual(["a", "b"]);
    });

    it("does not mutate the original array", () => {
      const orig = ["a", "b"];
      queueRemove(orig, 0);
      expect(orig).toEqual(["a", "b"]);
    });
  });

  // -------------------------------------------------------
  // clampQueueSelection
  // -------------------------------------------------------
  describe("clampQueueSelection", () => {
    it("returns -1 for empty queue", () => {
      expect(clampQueueSelection(0, 0)).toBe(-1);
      expect(clampQueueSelection(0, 2)).toBe(-1);
      expect(clampQueueSelection(0, -1)).toBe(-1);
    });

    it("clamps index to last position when out of bounds", () => {
      expect(clampQueueSelection(2, 5)).toBe(1);
      expect(clampQueueSelection(1, 1)).toBe(0);
    });

    it("preserves valid index", () => {
      expect(clampQueueSelection(3, 0)).toBe(0);
      expect(clampQueueSelection(3, 2)).toBe(2);
      expect(clampQueueSelection(3, -1)).toBe(-1);
    });
  });

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
      let queue: string[] = [];
      let sel = -1;

      queue = queueAdd(queue, "first");
      queue = queueAdd(queue, "second");
      expect(queue).toEqual(["first", "second"]);

      sel = navigateUp(sel, queue.length);
      expect(sel).toBe(1);

      queue = queueRemove(queue, sel);
      sel = selectionAfterRemove(2, sel);
      expect(queue).toEqual(["first"]);
      expect(sel).toBe(0);

      sel = navigateDown(sel, queue.length);
      expect(sel).toBe(-1);
    });

    it("add 3 → navigate up twice → edit (remove) → clamp", () => {
      let queue = ["a", "b", "c"];
      let sel = -1;

      sel = navigateUp(sel, queue.length);
      sel = navigateUp(sel, queue.length);
      expect(sel).toBe(1);

      const edited = queue[sel];
      queue = queueRemove(queue, sel);
      sel = -1;
      expect(edited).toBe("b");
      expect(queue).toEqual(["a", "c"]);

      queue = queueAdd(queue, "b-edited");
      expect(queue).toEqual(["a", "c", "b-edited"]);
    });

    it("send now removes from queue and resets selection", () => {
      let queue = ["a", "b", "c"];
      let sel = 1;

      const msgToSend = queue[sel];
      queue = queueRemove(queue, sel);
      sel = -1;
      expect(msgToSend).toBe("b");
      expect(queue).toEqual(["a", "c"]);
      expect(sel).toBe(-1);
    });
  });
});
