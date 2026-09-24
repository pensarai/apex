import assert from "node:assert/strict";
import { testRender } from "@opentui/react/test-utils";
import { act, useState } from "react";
import type { DisplayMessage } from "../../src/tui/components/agent-display";
import { MessageList } from "../../src/tui/components/chat/message-list";
import { appendStreamedText } from "../../src/tui/components/operator-dashboard/display-state";
import {
  PromptInput,
  type PromptInputRef,
} from "../../src/tui/components/shared/prompt-input";
import { FocusProvider } from "../../src/tui/context/focus";
import { InputProvider, useInput } from "../../src/tui/context/input";
import { ObfuscationProvider } from "../../src/tui/context/obfuscation";
import { registerBuiltinThemes, ThemeProvider } from "../../src/tui/theme";

export interface JourneyOptions {
  historySize: number;
  streamEvery: number;
}

const INPUT = "abcdefghijklmnopqrstuvwxyz0123456789";
const WIDTH = 100;
const HEIGHT = 30;

export async function runTypingJourney(options: JourneyOptions) {
  registerBuiltinThemes();
  const counts = { transcriptTraversals: 0, messageVisits: 0 };
  const track = (messages: DisplayMessage[]): DisplayMessage[] => {
    // Count actual list traversals without adding instrumentation to shipped code.
    Object.defineProperty(messages, "map", {
      value<T>(callback: (message: DisplayMessage, index: number) => T) {
        counts.transcriptTraversals++;
        counts.messageVisits += messages.length;
        return Array.prototype.map.call(messages, callback) as T[];
      },
    });
    return messages;
  };
  const initialMessages = track(
    Array.from(
      { length: options.historySize },
      (_, index): DisplayMessage => ({
        role: index % 2 === 0 ? "user" : "assistant",
        content: `Message ${index}: **synthetic** transcript with a short code span: \`value\`.`,
        createdAt: new Date(1_700_000_000_000 + index),
      }),
    ).concat({
      role: "assistant",
      content: "LIVE",
      createdAt: new Date(1_700_001_000_000),
    }),
  );
  let prompt: PromptInputRef | null = null;
  let publishText: (text: string) => void = () => {
    throw new Error("Journey has not mounted");
  };
  let submitted = "";
  let observedInput = "";
  let timerId = 0;

  function Journey() {
    // The dashboard also owns input state above the transcript.
    const { inputValue } = useInput();
    observedInput = inputValue;
    const [messages, setMessages] = useState(initialMessages);
    publishText = (text) => {
      setMessages((previous) => track(appendStreamedText(previous, text)));
    };
    return (
      <box width="100%" height="100%" flexDirection="column">
        <MessageList messages={messages} focused={false} />
        <box height={3} flexShrink={0}>
          <PromptInput
            ref={(value) => {
              prompt = value;
            }}
            focused
            onSubmit={(value) => {
              submitted = value;
            }}
          />
        </box>
      </box>
    );
  }

  const setup = await testRender(
    <ThemeProvider initialMode="dark">
      <ObfuscationProvider initialEnabled={false}>
        <FocusProvider>
          <InputProvider>
            <Journey />
          </InputProvider>
        </FocusProvider>
      </ObfuscationProvider>
    </ThemeProvider>,
    {
      width: WIDTH,
      height: HEIGHT,
      useThread: false,
      screenMode: "alternate-screen",
      exitOnCtrlC: false,
      // Freeze renderer scheduling; wall-clock measurements use performance.now().
      clock: {
        now: () => 0,
        setTimeout: () => ++timerId,
        clearTimeout: () => {},
        setInterval: () => ++timerId,
        clearInterval: () => {},
      },
    },
  );
  const { renderer, mockInput, renderOnce, captureCharFrame } = setup;
  const frame = async (action: () => void | Promise<void>) => {
    const before = renderer.frameId;
    await act(async () => {
      await action();
      // OpenTUI's stdin parser dispatches input on a later event-loop turn.
      await new Promise<void>((resolve) => setImmediate(resolve));
    });
    await act(renderOnce);
    assert.equal(
      renderer.frameId - before,
      1,
      "Only the explicit frame may run",
    );
    return captureCharFrame();
  };

  try {
    await frame(() => {});
    assert(
      counts.transcriptTraversals > 0,
      "Traversal counter must observe mount",
    );
    assert(prompt, "Prompt must mount");
    const input = prompt as PromptInputRef;
    await frame(() => input.focus());
    for (let index = 0; index < 8; index++) {
      await frame(() => mockInput.pressKey("w"));
    }
    await frame(() => input.reset());
    counts.transcriptTraversals = 0;
    counts.messageVisits = 0;
    const cpuStart = process.cpuUsage();
    const rssStart = process.memoryUsage().rss;
    const typingMs: number[] = [];
    const streamMs: number[] = [];
    let text = "LIVE";
    let expected = "";
    for (const [index, character] of [...INPUT].entries()) {
      if (options.streamEvery > 0 && index % options.streamEvery === 0) {
        text += ` delta${index}`;
        const traversalsBefore = counts.transcriptTraversals;
        const start = performance.now();
        const output = await frame(() => publishText(text));
        streamMs.push(performance.now() - start);
        assert(output.includes(`delta${index}`), "Stream tail must be visible");
        assert(
          counts.transcriptTraversals > traversalsBefore,
          "Traversal counter must observe changed messages",
        );
      }
      expected += character;
      const start = performance.now();
      const output = await frame(() => mockInput.pressKey(character));
      typingMs.push(performance.now() - start);
      assert(
        output.includes(expected),
        "Every typed character must be visible",
      );
      assert.equal(input.getValue(), expected);
      assert.equal(observedInput, expected);
    }
    const cpu = process.cpuUsage(cpuStart);
    const work = { ...counts };
    const rssEnd = process.memoryUsage().rss;

    await frame(() => mockInput.pressArrow("left"));
    await frame(() => mockInput.pressKey("X"));
    expected = `${expected.slice(0, -1)}X${expected.slice(-1)}`;
    assert.equal(
      input.getValue(),
      expected,
      "Mid-line editing preserves caret",
    );
    const resized = await frame(() => setup.resize(80, 24));
    assert(resized.includes(expected), "Input survives resize");
    await frame(() => mockInput.pressEnter());
    assert.equal(submitted, expected, "Submission is lossless");
    await frame(() => input.reset());
    const paste = "line one\nline two\nline three\nline four\nline five";
    await frame(() => mockInput.pasteBracketedText(paste));
    await frame(() => mockInput.pressEnter());
    assert.equal(submitted, paste, "Paste placeholders expand on submit");

    const summarize = (samples: number[]) => {
      const sorted = [...samples].sort((a, b) => a - b);
      return {
        samples: samples.length,
        p75: sorted[Math.ceil(sorted.length * 0.75) - 1] ?? null,
        p95: sorted[Math.ceil(sorted.length * 0.95) - 1] ?? null,
        max: sorted.at(-1) ?? null,
      };
    };
    return {
      fixture: "transcript-typing-v1",
      ...options,
      dimensions: { width: WIDTH, height: HEIGHT },
      warmupKeys: 8,
      measuredKeys: INPUT.length,
      work,
      typingToCapturedFrameMs: summarize(typingMs),
      streamToCapturedFrameMs: summarize(streamMs),
      cpuMs: (cpu.user + cpu.system) / 1000,
      rssStartBytes: rssStart,
      rssEndBytes: rssEnd,
      assertions: "input, stream tail, caret, resize, submit, paste",
    };
  } finally {
    await act(() => renderer.destroy());
  }
}

if (import.meta.main) {
  const historySize = Number(process.argv[2]);
  const streamEvery = Number(process.argv[3]);
  assert(Number.isSafeInteger(historySize) && historySize > 0);
  assert(Number.isSafeInteger(streamEvery) && streamEvery >= 0);
  const result = await runTypingJourney({ historySize, streamEvery });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
