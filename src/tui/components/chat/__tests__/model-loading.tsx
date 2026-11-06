import assert from "node:assert/strict";
import { testRender } from "@opentui/react/test-utils";
import { act, type Dispatch, type SetStateAction, useState } from "react";
import { registerBuiltinThemes, ThemeProvider } from "../../../theme";
import type { DisplayMessage } from "../../agent-display";
import { MessageList, type MessageListProps } from "../message-list";

registerBuiltinThemes();
const timers = new Set<ReturnType<typeof setInterval>>();
const nativeSetInterval = globalThis.setInterval;
const nativeClearInterval = globalThis.clearInterval;
globalThis.setInterval = ((...args: Parameters<typeof setInterval>) => {
  const timer = nativeSetInterval(...args);
  timers.add(timer);
  return timer;
}) as typeof setInterval;
globalThis.clearInterval = ((timer: ReturnType<typeof setInterval>) => {
  timers.delete(timer);
  nativeClearInterval(timer);
}) as typeof clearInterval;

try {
  for (const initialMode of ["dark", "light"] as const) {
    for (const width of [32, 100]) {
      let update: Dispatch<SetStateAction<MessageListProps>>;
      function Host() {
        const [props, setProps] = useState<MessageListProps>({
          messages: [],
          variant: "subagent",
        });
        update = setProps;
        return <MessageList {...props} />;
      }
      const setup = await testRender(
        <ThemeProvider initialMode={initialMode}>
          <Host />
        </ThemeProvider>,
        { width, height: 16, useThread: false },
      );
      const render = async (props: MessageListProps) => {
        await act(() => update(props));
        await act(setup.renderOnce);
        return setup.captureCharFrame();
      };
      try {
        const baselineTimers = timers.size;
        const loadingProps: MessageListProps = {
          messages: [],
          variant: "subagent",
          isRunning: true,
          modelLoading:
            "ollama:hf.co/webAI-Official/TwIL-8B:TwIL-8B-Q4_K_M-balanced.gguf",
        };
        const loading = await render(loadingProps);
        assert.match(loading.replace(/\s+/g, " "), /Loading model weights/);
        assert.match(loading, /\[[|/\\-]\]/);
        assert.ok(!loading.includes("Compacting"));
        assert.ok(!loading.includes("No messages"));
        assert.equal(timers.size, baselineTimers + 1);
        await act(async () => {
          await Bun.sleep(140);
        });
        await act(setup.renderOnce);
        assert.notEqual(setup.captureCharFrame(), loading);
        const messages: DisplayMessage[] = [
          { role: "user", content: "Hello", createdAt: new Date() },
        ];
        const ready = await render({
          ...loadingProps,
          modelLoading: null,
          messages,
        });
        assert.ok(!ready.includes("Loading model weights"));
        assert.ok(ready.includes("Thinking"));
        const compacting = await render({
          ...loadingProps,
          modelLoading: null,
          messages: [
            {
              role: "tool",
              content: "",
              toolCallId: "compact",
              toolName: "summarize_conversation",
              status: "pending",
              createdAt: new Date(),
            },
          ],
        });
        assert.ok(compacting.includes("Compacting"));
        assert.ok(!compacting.includes("Loading model weights"));
        await render(loadingProps);
        const stopped = await render({
          ...loadingProps,
          isRunning: false,
          modelLoading: null,
        });
        assert.ok(!stopped.includes("Loading model weights"));
        assert.equal(timers.size, baselineTimers);
        if (process.env.APEX_LOADING_VISUAL_QA)
          console.log(`${initialMode} ${width} columns\n${loading}`);
      } finally {
        await act(() => setup.renderer.destroy());
      }
    }
  }
  assert.equal(timers.size, 0);
} finally {
  globalThis.setInterval = nativeSetInterval;
  globalThis.clearInterval = nativeClearInterval;
}
