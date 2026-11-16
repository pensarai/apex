import { describe, expect, it } from "vitest";
import { advanceStream, streamFadePlugin } from "./stream-fade";

describe("stream arrival fades", () => {
  it("fades only appended text and expires old arrivals", () => {
    const first = advanceStream(
      { text: "Existing", arrivals: [] },
      "Existing new",
      100,
      true,
    );
    expect(first.arrivals).toEqual([{ start: 8, end: 12, time: 100 }]);
    const next = advanceStream(first, "Existing new tokens", 200, true);
    expect(next.arrivals).toEqual([
      { start: 8, end: 12, time: 100 },
      { start: 12, end: 19, time: 200 },
    ]);
    expect(
      advanceStream(next, "Existing new tokens!", 400, true).arrivals,
    ).toEqual([{ start: 19, end: 20, time: 400 }]);
  });

  it("does not replay history, replacements, or hidden updates", () => {
    const previous = {
      text: "Hello",
      arrivals: [{ start: 0, end: 5, time: 100 }],
    };
    expect(advanceStream(previous, "Hello again", 120, false).arrivals).toEqual(
      [],
    );
    expect(advanceStream(previous, "Corrected", 120, true).arrivals).toEqual(
      [],
    );
    expect(
      advanceStream({ text: "History", arrivals: [] }, "History", 120, true)
        .arrivals,
    ).toEqual([]);
  });

  it("wraps only the new suffix while preserving markdown structure", () => {
    const text = {
      type: "text",
      value: "hello world",
      position: { start: { offset: 2 }, end: { offset: 13 } },
    };
    const tree = {
      type: "root",
      children: [{ type: "element", tagName: "strong", children: [text] }],
    };
    streamFadePlugin([{ start: 8, end: 13, time: 100 }], 120)()(tree);
    expect(tree.children[0]).toMatchObject({
      tagName: "strong",
      children: [
        { type: "text", value: "hello " },
        {
          tagName: "span",
          properties: { style: "animation-delay: -20ms" },
          children: [{ value: "world" }],
        },
      ],
    });
  });

  it("leaves syntax-renderer input and decoded entities intact", () => {
    const text = {
      type: "text",
      value: "const x = 1",
      position: { start: { offset: 0 }, end: { offset: 11 } },
    };
    const code = { type: "element", tagName: "code", children: [text] };
    const entity = {
      type: "text",
      value: "&",
      position: { start: { offset: 12 }, end: { offset: 17 } },
    };
    const tree = { type: "root", children: [code, entity] };
    streamFadePlugin([{ start: 0, end: 17, time: 100 }], 100)()(tree);
    expect(tree.children).toEqual([code, entity]);
    expect(code.children).toEqual([text]);
  });
});
