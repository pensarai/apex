import assert from "node:assert/strict";
import { testRender } from "@opentui/react/test-utils";
import { act, type Dispatch, type SetStateAction, useState } from "react";
import { registerBuiltinThemes, ThemeProvider } from "../../../theme";
import type { DisplayMessage } from "../../agent-display";
import {
  applyToolCall,
  applyToolResult,
  markInFlightToolsErrored,
  startStreamingToolCall,
} from "../../operator-dashboard/display-state";
import { ToolRenderer } from "../tool-renderer";

registerBuiltinThemes();
let update: Dispatch<SetStateAction<DisplayMessage[]>>;
function Host() {
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  update = setMessages;
  return messages.map((message) => (
    <ToolRenderer key={message.toolCallId} message={message} />
  ));
}

const setup = await testRender(
  <ThemeProvider>
    <Host />
  </ThemeProvider>,
  { width: 100, height: 24, useThread: false },
);
const frame = async (messages: DisplayMessage[]) => {
  await act(() => update(messages));
  await act(setup.renderOnce);
  return setup.captureCharFrame();
};

try {
  for (const toolName of ["provider_tool", "execute_command"]) {
    const label = toolName === "execute_command" ? "$" : toolName;
    const streaming = startStreamingToolCall([], "call-1", toolName);
    assert.ok((await frame(streaming)).includes(label));

    const pending = applyToolCall(streaming, "call-1", toolName, undefined);
    assert.ok((await frame(pending)).includes(label));
    assert.equal(pending[0].args, undefined);

    const errored = markInFlightToolsErrored(pending, "Invalid tool arguments");
    const errorFrame = await frame(errored);
    assert.ok(errorFrame.includes(label));
    assert.ok(errorFrame.includes("Invalid tool arguments"));

    const completed = applyToolResult(pending, "call-1", "Tool finished");
    assert.ok((await frame(completed)).includes("Tool finished"));

    const populated = applyToolCall(streaming, "call-1", toolName, {
      command: "echo probe",
      toolCallDescription: "Run probe",
    });
    const populatedFrame = await frame(populated);
    assert.ok(
      populatedFrame.includes(
        toolName === "execute_command"
          ? "Run probe"
          : "provider_tool echo probe",
      ),
    );
  }
} finally {
  await act(() => setup.renderer.destroy());
}
