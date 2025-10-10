#!/usr/bin/env bun
import { render } from "@opentui/react";
import {
  SpinnerCircle,
  HeartBeat,
  LoadingWave,
  ProgressBar,
  PulsingDot,
  SpinnerBraille,
  SpinnerDots,
  SpinnerLine,
  BlinkingEye,
  TypingIndicator,
  RocketLaunch,
  StatusPulse,
} from "./src/components/sprites";

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
      <SpinnerDots />
      <SpinnerLine />
      <SpinnerCircle />
      <SpinnerBraille />
      <ProgressBar />
      <PulsingDot />
      <LoadingWave />
      <HeartBeat />
      <BlinkingEye />
      <TypingIndicator />
      <RocketLaunch />
      <StatusPulse status="success" />
      <StatusPulse status="warning" />
      <StatusPulse status="error" />
      <StatusPulse status="info" />
    </box>
  );
}

render(<App />, {
  exitOnCtrlC: true,
});
