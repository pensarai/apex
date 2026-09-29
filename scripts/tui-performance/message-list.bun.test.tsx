import { expect, test } from "bun:test";
import { testRender } from "@opentui/react/test-utils";
import { act, type Dispatch, type SetStateAction, useState } from "react";
import {
  MessageList,
  type MessageListProps,
} from "../../src/tui/components/chat/message-list";
import {
  registerBuiltinThemes,
  ThemeProvider,
  useTheme,
} from "../../src/tui/theme";

test("transcript still responds to message, approval and theme changes", async () => {
  registerBuiltinThemes();
  const initial: MessageListProps = {
    messages: [
      { role: "assistant", content: "Before", createdAt: new Date(0) },
    ],
  };
  let update: Dispatch<SetStateAction<MessageListProps>>;
  let toggleTheme: () => void;
  function Host() {
    const [props, setProps] = useState(initial);
    update = setProps;
    toggleTheme = useTheme().toggleMode;
    return <MessageList {...props} />;
  }
  const setup = await testRender(
    <ThemeProvider>
      <Host />
    </ThemeProvider>,
    {
      width: 80,
      height: 24,
      useThread: false,
    },
  );
  const frame = async (action: () => void) => {
    await act(action);
    await act(setup.renderOnce);
    return setup.captureCharFrame();
  };
  try {
    expect(await frame(() => {})).toContain("Before");
    expect(
      await frame(() =>
        update({
          messages: [{ ...initial.messages[0], content: "After" }],
        }),
      ),
    ).toContain("After");
    expect(
      await frame(() =>
        update((previous) => ({
          ...previous,
          pendingApprovals: [
            {
              id: "approval-fixture",
              toolCallId: "tool-fixture",
              toolName: "execute_command",
              args: {
                command: "pwd",
                toolCallDescription: "Inspect directory",
              },
              tier: 2,
              timestamp: 0,
            },
          ],
        })),
      ),
    ).toContain("approve all");
    expect(
      await frame(() =>
        update((previous) => ({ ...previous, pendingApprovals: [] })),
      ),
    ).not.toContain("approve all");
    const dark = setup.captureSpans();
    expect(await frame(() => toggleTheme())).toContain("After");
    expect(setup.captureSpans()).not.toEqual(dark);
  } finally {
    await act(() => setup.renderer.destroy());
  }
});
