import { describe, expect, it } from "vitest";
import { type SessionLayout, sessionLayout } from "./session-layout";

const initial: SessionLayout = {
  order: ["a", "b", "c"],
  primary: "a",
  focused: "a",
};

describe("session layout", () => {
  it("opens a new tab in the focused pane without replacing the other pane", () => {
    const split = sessionLayout(initial, {
      type: "dock",
      id: "b",
      side: "right",
    });
    expect(sessionLayout(split, { type: "open", id: "d" })).toEqual({
      order: ["a", "b", "c", "d"],
      primary: "a",
      secondary: "d",
      focused: "d",
    });
  });

  it("focuses an already visible tab without duplicating its view", () => {
    const split = sessionLayout(initial, {
      type: "dock",
      id: "b",
      side: "right",
    });
    expect(sessionLayout(split, { type: "open", id: "a" })).toEqual({
      order: initial.order,
      primary: "a",
      secondary: "b",
      focused: "a",
    });
  });

  it("moves either visible session across the divider without duplicating it", () => {
    const split = sessionLayout(initial, {
      type: "dock",
      id: "b",
      side: "right",
    });
    expect(
      sessionLayout(split, { type: "dock", id: "a", side: "right" }),
    ).toEqual({
      order: initial.order,
      primary: "b",
      secondary: "a",
      focused: "a",
    });
  });

  it("keeps the surviving pane when a visible session closes", () => {
    const split = sessionLayout(initial, {
      type: "dock",
      id: "b",
      side: "right",
    });
    expect(sessionLayout(split, { type: "close", id: "a" })).toEqual({
      order: ["b", "c"],
      primary: "b",
      secondary: undefined,
      focused: "b",
    });
    expect(sessionLayout(split, { type: "close", id: "b" })).toEqual({
      order: ["a", "c"],
      primary: "a",
      secondary: undefined,
      focused: "a",
    });
  });

  it("docks beside the conversation visible before dragging selected another tab", () => {
    const selected = sessionLayout(
      { ...initial, primary: "b", focused: "b" },
      { type: "select", id: "c" },
    );
    const docked = sessionLayout(selected, {
      type: "dock",
      id: "c",
      side: "right",
      beside: "b",
    });
    expect(docked.primary).toBe("b");
    expect(docked.secondary).toBe("c");
    expect(docked.focused).toBe("c");
  });

  it("reorders tabs without changing either pane or focus", () => {
    const split = sessionLayout(initial, {
      type: "dock",
      id: "b",
      side: "right",
    });
    expect(
      sessionLayout(split, { type: "reorder", id: "c", target: "a" }),
    ).toEqual({
      ...split,
      order: ["c", "a", "b"],
    });
    expect(
      sessionLayout(initial, {
        type: "reorder",
        id: "a",
        target: "c",
        after: true,
      }).order,
    ).toEqual(["b", "c", "a"]);
  });

  it("collapses to the focused pane and ignores stale drag identifiers", () => {
    const split = sessionLayout(initial, {
      type: "dock",
      id: "b",
      side: "right",
    });
    expect(sessionLayout(split, { type: "single" })).toEqual({
      ...split,
      primary: "b",
      secondary: undefined,
    });
    expect(
      sessionLayout(initial, { type: "dock", id: "closed", side: "left" }),
    ).toBe(initial);
  });
});
