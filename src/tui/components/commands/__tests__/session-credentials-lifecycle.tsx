import assert from "node:assert/strict";
import { testRender } from "@opentui/react/test-utils";
import { act, useEffect, useRef } from "react";
import type { AuthCredentials } from "../../../../core/session";
import { DialogProvider, useDialog } from "../../../context/dialog";
import { TerminalDimensionsProvider } from "../../../context/dimensions";
import { registerBuiltinThemes, ThemeProvider } from "../../../theme";
import { SessionCredentialsDialog } from "../session-credentials";

registerBuiltinThemes();
const writes: AuthCredentials[] = [];
function OpenCredentials() {
  const { replace } = useDialog();
  const opened = useRef(false);
  useEffect(() => {
    if (opened.current) return;
    opened.current = true;
    replace(
      <SessionCredentialsDialog
        saved={[{ id: "existing", type: "api-key", role: "Read only" }]}
        onSave={async (value) => {
          writes.push(value);
        }}
      />,
      { bare: true, selfHandlesEscape: true },
    );
  }, [replace]);
  return null;
}
const setup = await testRender(
  <ThemeProvider>
    <TerminalDimensionsProvider>
      <DialogProvider>
        <OpenCredentials />
      </DialogProvider>
    </TerminalDimensionsProvider>
  </ThemeProvider>,
  { width: 80, height: 24, exitOnCtrlC: false },
);
const frame = async () => {
  await act(async () => {});
  await act(setup.renderOnce);
  return setup.captureCharFrame();
};
const press = async (key: string) => {
  await act(async () => setup.mockInput.pressKey(key));
  await frame();
};
try {
  assert.ok((await frame()).includes("Read only"));
  await press("RETURN");
  await press("RETURN");
  assert.ok((await frame()).includes("Enter a credential"));
  const values = [
    "QA admin",
    "https://app.example.test/login",
    "qa@example.test",
    "sample-password",
    "sample-key",
    "",
    "X-API-Key",
    "Use the staging login form.",
  ];
  for (const [index, value] of values.entries()) {
    if (index) await press("TAB");
    if (!value) continue;
    await act(async () => setup.mockInput.pasteBracketedText(value));
    const rendered = await frame();
    if ([3, 4, 5].includes(index)) {
      assert.ok(!rendered.includes(value), rendered);
      assert.ok(rendered.includes("••••••••"), rendered);
    } else assert.ok(rendered.includes(value), rendered);
  }
  await press("RETURN");
  assert.deepEqual(writes, [
    {
      role: values[0],
      loginUrl: values[1],
      username: values[2],
      password: values[3],
      apiKey: values[4],
      tokens: {
        bearerToken: undefined,
        customHeaders: { "X-API-Key": values[4] },
      },
      context: values[7],
    },
  ]);
  assert.ok(!(await frame()).includes("Add session credential"));
} finally {
  await act(async () => setup.renderer.destroy());
}
