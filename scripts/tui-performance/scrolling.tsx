import assert from "node:assert/strict";
import { Renderable, ScrollBoxRenderable } from "@opentui/core";
import { testRender } from "@opentui/react/test-utils";
import { act, useState } from "react";
import type { DisplayMessage } from "../../src/tui/components/agent-display";
import { MessageList } from "../../src/tui/components/chat/message-list";
import { appendStreamedText } from "../../src/tui/components/operator-dashboard/display-state";
import { ObfuscationProvider } from "../../src/tui/context/obfuscation";
import { registerBuiltinThemes, ThemeProvider } from "../../src/tui/theme";

export async function runScrollingJourney(
  historySize: number,
  streamEvery: number,
  initialReply = "LIVE_START",
) {
  registerBuiltinThemes();
  let layoutReads = 0;
  let transcriptTraversals = 0;
  const updateFromLayout = Renderable.prototype.updateFromLayout;
  const track = (messages: DisplayMessage[]) => {
    Object.defineProperty(messages, "map", {
      value<T>(callback: (message: DisplayMessage, index: number) => T) {
        transcriptTraversals++;
        return Array.prototype.map.call(messages, callback) as T[];
      },
    });
    return messages;
  };
  const initial = track(
    Array.from(
      { length: historySize },
      (_, index): DisplayMessage => ({
        role: index % 2 === 0 ? "user" : "assistant",
        content: `MSG_${String(index).padStart(5, "0")} **synthetic** transcript.\n\nA second paragraph with a short code span: \`value\`.`,
        createdAt: new Date(1_700_000_000_000 + index),
      }),
    ).concat({
      role: "assistant",
      content: initialReply,
      createdAt: new Date(1_700_001_000_000),
    }),
  );
  let publish: (content: string) => void = () => {
    throw new Error("Host not mounted");
  };
  function Host() {
    const [messages, setMessages] = useState(initial);
    publish = (content) =>
      setMessages((previous) => track(appendStreamedText(previous, content)));
    return (
      <box id="scroll-fixture" width="100%" height="100%">
        <MessageList messages={messages} focused={false} />
      </box>
    );
  }
  let timerId = 0;
  const setup = await testRender(
    <ThemeProvider initialMode="dark">
      <ObfuscationProvider initialEnabled={false}>
        <Host />
      </ObfuscationProvider>
    </ThemeProvider>,
    {
      width: 100,
      height: 30,
      useThread: false,
      useMouse: true,
      screenMode: "alternate-screen",
      exitOnCtrlC: false,
      clock: {
        now: () => 0,
        setTimeout: () => ++timerId,
        clearTimeout: () => {},
        setInterval: () => ++timerId,
        clearInterval: () => {},
      },
    },
  );
  const frame = async (action: () => void | Promise<void>) => {
    const before = setup.renderer.frameId;
    await act(async () => {
      await action();
      await new Promise<void>((resolve) => setImmediate(resolve));
    });
    await act(setup.renderOnce);
    assert.equal(setup.renderer.frameId - before, 1);
  };
  Renderable.prototype.updateFromLayout = function () {
    layoutReads++;
    return updateFromLayout.call(this);
  };
  try {
    await frame(() => {});
    const scroll = setup.renderer.root
      .findDescendantById("scroll-fixture")
      ?.getChildren()
      .find((child) => child instanceof ScrollBoxRenderable);
    assert(scroll instanceof ScrollBoxRenderable);
    const bottom = () =>
      Math.max(0, scroll.scrollHeight - scroll.viewport.height);
    const wheel = (direction: "up" | "down") =>
      setup.mockMouse.scroll(
        scroll.viewport.x + Math.floor(scroll.viewport.width / 2),
        scroll.viewport.y + Math.floor(scroll.viewport.height / 2),
        direction,
      );
    assert(bottom() > 150);
    assert.equal(scroll.scrollTop, bottom());
    assert(setup.captureCharFrame().includes("LIVE_START"));
    assert(layoutReads > historySize);
    assert(transcriptTraversals > 0);
    await frame(() => scroll.scrollTo(Math.floor(bottom() / 2)));
    for (const direction of ["up", "down"] as const) {
      for (let step = 0; step < 8; step++) await frame(() => wheel(direction));
    }
    const historyFrame = setup.captureCharFrame();
    const initialHeight = scroll.scrollHeight;
    layoutReads = 0;
    transcriptTraversals = 0;
    const cpuStart = process.cpuUsage();
    const wheelMs: number[] = [];
    const streamMs: number[] = [];
    let text = initialReply;
    const initialTop = scroll.scrollTop;
    for (let step = 0; step < 120; step++) {
      const previous: number = scroll.scrollTop;
      const streaming = streamEvery > 0 && step % streamEvery === 0;
      const start = performance.now();
      await frame(async () => {
        if (streaming) {
          text += `\n\nLIVE_${step}`;
          publish(text);
        }
        await wheel(step < 60 ? "up" : "down");
      });
      (streaming ? streamMs : wheelMs).push(performance.now() - start);
      assert.equal(scroll.scrollTop, previous + (step < 60 ? -1 : 1));
    }
    const cpu = process.cpuUsage(cpuStart);
    const work = { layoutReads, transcriptTraversals };
    assert.equal(scroll.scrollTop, initialTop);
    assert.equal(
      transcriptTraversals,
      streamEvery > 0 ? Math.ceil(120 / streamEvery) : 0,
    );
    const growthRows = scroll.scrollHeight - initialHeight;
    assert.equal(
      growthRows,
      transcriptTraversals * 2,
      "Every streamed line must contribute to the scroll extent",
    );
    const anchoredFrame = setup.captureCharFrame();
    const anchor = anchoredFrame
      .split("\n")
      .map((line, row) => ({ marker: line.match(/MSG_\d+/)?.[0], row }))
      .find(({ marker }) => marker);
    assert(anchor?.marker);
    assert(
      historyFrame.split("\n")[anchor.row].includes(anchor.marker),
      "Streaming below the viewport must not move history",
    );
    const anchoredTop = scroll.scrollTop;
    const previousHeight = scroll.scrollHeight;
    text += "\n\nLIVE_ANCHORED\n\nAdditional output while reading history.";
    await frame(() => publish(text));
    assert(scroll.scrollHeight > previousHeight);
    assert.equal(scroll.scrollTop, anchoredTop);
    assert(
      setup.captureCharFrame().split("\n")[anchor.row].includes(anchor.marker),
    );
    assert(!setup.captureCharFrame().includes("LIVE_ANCHORED"));
    await frame(() => scroll.scrollTo(bottom() - 8));
    for (let step = 0; step < 8; step++) await frame(() => wheel("down"));
    assert.equal(scroll.scrollTop, bottom());
    for (let step = 0; step < 3; step++) {
      const before = bottom();
      text += `\n\nFOLLOW_${step}`;
      await frame(() => publish(text));
      assert(bottom() > before);
      assert.equal(scroll.scrollTop, bottom());
      assert(setup.captureCharFrame().includes(`FOLLOW_${step}`));
    }
    await frame(() => setup.resize(80, 24));
    assert.equal(scroll.scrollTop, bottom());
    assert(setup.captureCharFrame().includes("FOLLOW_2"));
    if (streamEvery > 0) {
      text += `\n\n${Array.from({ length: 40 }, (_, index) => `WRAP_${index} ${"word ".repeat(35)}`).join("\n\n")}\n\nTAIL_END`;
      await frame(() => publish(text));
      for (const [width, height] of [
        [100, 30],
        [80, 24],
        [40, 15],
      ]) {
        await frame(() => setup.resize(width, height));
        assert.equal(scroll.scrollTop, bottom());
        assert(setup.captureCharFrame().includes("TAIL_END"));
      }
    }
    const summarize = (samples: number[]) => {
      const sorted = [...samples].sort((a, b) => a - b);
      return {
        samples: sorted.length,
        p95: sorted[Math.ceil(sorted.length * 0.95) - 1] ?? null,
        max: sorted.at(-1) ?? null,
      };
    };
    return {
      fixture: "transcript-scrolling-v1",
      historySize,
      streamEvery,
      work,
      growthRows,
      wheelToFrameMs: summarize(wheelMs),
      streamAndWheelToFrameMs: summarize(streamMs),
      cpuMs: (cpu.user + cpu.system) / 1000,
      assertions:
        "wheel up/down, anchor while streaming, return-to-bottom, follow, resize",
    };
  } finally {
    Renderable.prototype.updateFromLayout = updateFromLayout;
    await act(() => setup.renderer.destroy());
  }
}

if (import.meta.main) {
  const historySize = Number(process.argv[2]);
  const streamEvery = Number(process.argv[3]);
  assert(Number.isSafeInteger(historySize) && historySize >= 100);
  assert(Number.isSafeInteger(streamEvery) && streamEvery >= 0);
  console.log(
    JSON.stringify(await runScrollingJourney(historySize, streamEvery)),
  );
}
