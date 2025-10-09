#!/usr/bin/env bun
import { render } from "@opentui/react";
import AnimatedSpritesExample from "./src/components /sprites";

/**
 * Test file for animated terminal sprites
 * Run with: bun run test-animated-sprites.tsx
 */

function App() {
  return (
    <box
      flexDirection="column"
      width="100%"
      height="100%"
      alignItems="center"
      justifyContent="center"
    >
      <AnimatedSpritesExample />
    </box>
  );
}

render(<App />, {
  exitOnCtrlC: true,
});
