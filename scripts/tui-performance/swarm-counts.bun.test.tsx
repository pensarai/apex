import { expect, test } from "bun:test";
import { testRender } from "@opentui/react/test-utils";
import {
  act,
  type Dispatch,
  type SetStateAction,
  useState,
  useSyncExternalStore,
} from "react";
import {
  createSubagentSessionHelpers,
  createSubagentStore,
  markSubagentsInterrupted,
} from "../../src/tui/components/operator-dashboard/subagent-state";
import { SubagentStatusBar } from "../../src/tui/components/operator-dashboard/subagent-status-bar";
import { registerBuiltinThemes, ThemeProvider } from "../../src/tui/theme";

test("production status bar responds to lifecycle counts, not streamed transcripts", async () => {
  registerBuiltinThemes();
  const store = createSubagentStore();
  const helpers = createSubagentSessionHelpers(store.setState);
  let renders = 0;
  let setMovedOn: Dispatch<SetStateAction<boolean>>;
  const onOpen = () => {};
  function Host() {
    const counts = useSyncExternalStore(
      store.subscribeCounts,
      store.getCountsSnapshot,
    );
    const [movedOn, updateMovedOn] = useState(false);
    setMovedOn = updateMovedOn;
    renders++;
    return (
      <SubagentStatusBar
        counts={counts}
        agentMovedOn={movedOn}
        onOpen={onOpen}
      />
    );
  }
  const setup = await testRender(
    <ThemeProvider>
      <Host />
    </ThemeProvider>,
    {
      width: 120,
      height: 5,
      useThread: false,
    },
  );
  const frame = async (action: () => void) => {
    await act(action);
    await act(setup.renderOnce);
    return setup.captureCharFrame();
  };
  try {
    expect(await frame(() => {})).not.toContain("view agents");
    expect(await frame(() => helpers.spawnSession("a"))).toContain(
      "1 agent  1 running",
    );
    const beforeStream = renders;
    expect(
      await frame(() => {
        helpers.appendText("a", "live text");
        helpers.addStreamingToolCall("a", "tool-a", "execute_command");
        helpers.appendToolCallDelta("a", "tool-a", '{"command":"echo ok"}');
        helpers.addToolCall("a", "tool-a", "execute_command", {
          command: "echo ok",
        });
        helpers.updateToolResult("a", "tool-a", "ok");
      }),
    ).toContain("1 agent  1 running");
    expect(renders).toBe(beforeStream);

    const running = await frame(() => {
      helpers.spawnSession("b");
      helpers.spawnSession("c");
      helpers.spawnSession("d");
      helpers.completeSession("b", "completed");
      helpers.completeSession("c", "failed");
    });
    expect(running).toContain("4 agents  2 running");
    expect(running).toContain("1 complete");
    expect(running).toContain("1 failed");
    expect(running).toContain("Ctrl+A view agents");
    expect(await frame(() => setMovedOn(true))).toContain("2 running");
    expect(
      await frame(() => store.setState(markSubagentsInterrupted)),
    ).not.toContain("view agents");
    const settled = await frame(() => setMovedOn(false));
    expect(settled).toContain("4 agents");
    expect(settled).toContain("2 cancelled");
    expect(settled).not.toContain("running");

    const restored = store.getSnapshot();
    expect(await frame(() => store.setState(new Map()))).not.toContain(
      "view agents",
    );
    expect(await frame(() => store.setState(restored))).toContain(
      "2 cancelled",
    );
  } finally {
    await act(() => setup.renderer.destroy());
  }
});
