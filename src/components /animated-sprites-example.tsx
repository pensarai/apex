import { RGBA } from "@opentui/core";
import { useState, useEffect } from "react";

/**
 * Example component demonstrating animated terminal sprite icons using OpenTUI
 * Showcases various animation techniques for terminal UIs
 */
export default function AnimatedSpritesExample() {
  return (
    <box
      flexDirection="column"
      width="100%"
      height="100%"
      padding={2}
      gap={2}
      backgroundColor={RGBA.fromInts(20, 20, 20, 255)}
    >
      <text fg="cyan" content="🎨 Animated Terminal Sprite Icons Demo" bold />

      <box flexDirection="column" gap={1}>
        <text fg="yellow" content="Spinners:" />
        <box flexDirection="row" gap={4}>
          <SpinnerDots />
          <SpinnerLine />
          <SpinnerCircle />
          <SpinnerBraille />
        </box>
      </box>

      <box flexDirection="column" gap={1}>
        <text fg="yellow" content="Progress Indicators:" />
        <box flexDirection="column" gap={1}>
          <ProgressBar />
          <PulsingDot />
          <LoadingWave />
        </box>
      </box>

      <box flexDirection="column" gap={1}>
        <text fg="yellow" content="Animated Icons:" />
        <box flexDirection="row" gap={4}>
          <HeartBeat />
          <BlinkingEye />
          <TypingIndicator />
          <RocketLaunch />
        </box>
      </box>

      <box flexDirection="column" gap={1}>
        <text fg="yellow" content="Status Indicators:" />
        <box flexDirection="row" gap={4}>
          <StatusPulse status="success" />
          <StatusPulse status="warning" />
          <StatusPulse status="error" />
          <StatusPulse status="info" />
        </box>
      </box>
    </box>
  );
}

/** Animated spinner with rotating dots */
function SpinnerDots() {
  const frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((prev) => (prev + 1) % frames.length);
    }, 80);
    return () => clearInterval(interval);
  }, []);

  return <text fg="blue" content={`${frames[frame]} Loading`} />;
}

/** Horizontal line spinner */
function SpinnerLine() {
  const frames = ["-", "\\", "|", "/"];
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((prev) => (prev + 1) % frames.length);
    }, 100);
    return () => clearInterval(interval);
  }, []);

  return <text fg="magenta" content={`[${frames[frame]}] Processing`} />;
}

/** Circle spinner animation */
function SpinnerCircle() {
  const frames = ["◐", "◓", "◑", "◒"];
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((prev) => (prev + 1) % frames.length);
    }, 150);
    return () => clearInterval(interval);
  }, []);

  return <text fg="cyan" content={`${frames[frame]} Working`} />;
}

/** Braille pattern spinner */
export function SpinnerBraille({ label }: { label?: string }) {
  const frames = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"];
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((prev) => (prev + 1) % frames.length);
    }, 80);
    return () => clearInterval(interval);
  }, []);

  return <text fg="green" content={`${frames[frame]} ${label || "Active"}`} />;
}

/** Animated progress bar */
function ProgressBar() {
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setProgress((prev) => (prev >= 100 ? 0 : prev + 2));
    }, 100);
    return () => clearInterval(interval);
  }, []);

  const barWidth = 30;
  const filled = Math.floor((progress / 100) * barWidth);
  const empty = barWidth - filled;
  const bar = "█".repeat(filled) + "░".repeat(empty);

  return <text fg="green" content={`[${bar}] ${progress}%`} />;
}

/** Pulsing dot indicator */
function PulsingDot() {
  const frames = ["⚫", "⚪", "⚫", "⚪"];
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((prev) => (prev + 1) % frames.length);
    }, 300);
    return () => clearInterval(interval);
  }, []);

  return <text fg="blue" content={`${frames[frame]} Syncing`} />;
}

/** Wave loading animation */
function LoadingWave() {
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setOffset((prev) => (prev + 1) % 8);
    }, 100);
    return () => clearInterval(interval);
  }, []);

  const dots = Array.from({ length: 8 }, (_, i) => {
    const height = Math.sin((i + offset) * 0.5) * 2 + 2;
    return height > 2 ? "●" : "○";
  }).join(" ");

  return <text fg="cyan" content={dots} />;
}

/** Beating heart animation */
function HeartBeat() {
  const frames = ["💙", "💚", "💙", "💛"];
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((prev) => (prev + 1) % frames.length);
    }, 400);
    return () => clearInterval(interval);
  }, []);

  return <text content={frames[frame]} />;
}

/** Blinking eye */
function BlinkingEye() {
  const frames = ["👁️", "👁️", "👁️", "👁️", "👁️", "😑"];
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((prev) => (prev + 1) % frames.length);
    }, 300);
    return () => clearInterval(interval);
  }, []);

  return <text content={frames[frame]} />;
}

/** Typing indicator with dots */
function TypingIndicator() {
  const frames = ["   ", ".  ", ".. ", "..."];
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((prev) => (prev + 1) % frames.length);
    }, 300);
    return () => clearInterval(interval);
  }, []);

  return <text fg="gray" content={`typing${frames[frame]}`} />;
}

/** Rocket launch animation */
function RocketLaunch() {
  const frames = ["🚀", "🚀 ", "🚀  ", " 🚀 ", "  🚀", "   🚀"];
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((prev) => (prev + 1) % frames.length);
    }, 200);
    return () => clearInterval(interval);
  }, []);

  return <text content={frames[frame]} />;
}

/** Pulsing status indicator */
function StatusPulse({
  status,
}: {
  status: "success" | "warning" | "error" | "info";
}) {
  const [intensity, setIntensity] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setIntensity((prev) => (prev + 0.1) % (Math.PI * 2));
    }, 50);
    return () => clearInterval(interval);
  }, []);

  const opacity = Math.sin(intensity) * 0.5 + 0.5; // Oscillates between 0 and 1
  const bright = opacity > 0.5;

  const configs = {
    success: { icon: "●", color: "green", label: "Success" },
    warning: { icon: "▲", color: "yellow", label: "Warning" },
    error: { icon: "✖", color: "red", label: "Error" },
    info: { icon: "ℹ", color: "blue", label: "Info" },
  };

  const config = configs[status];
  const displayIcon = bright ? config.icon : "○";

  return <text fg={config.color} content={`${displayIcon} ${config.label}`} />;
}

/**
 * Usage example:
 *
 * import AnimatedSpritesExample from "./components /animated-sprites-example";
 *
 * <AnimatedSpritesExample />
 */
