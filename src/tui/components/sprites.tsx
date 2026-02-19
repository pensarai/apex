import { RGBA } from "@opentui/core";
import { useState, useEffect } from "react";
import { useTheme } from "../theme";

// Global animation tick - shared by all spinners to avoid excessive re-renders
let globalTick = 0;
const globalListeners = new Set<() => void>();
let globalInterval: NodeJS.Timeout | null = null;

function startGlobalTick() {
  if (!globalInterval) {
    globalInterval = setInterval(() => {
      globalTick = (globalTick + 1) % 1000;
      globalListeners.forEach((listener) => listener());
    }, 80);
  }
}

function stopGlobalTick() {
  if (globalInterval && globalListeners.size === 0) {
    clearInterval(globalInterval);
    globalInterval = null;
  }
}

function useGlobalTick() {
  const [, setTick] = useState(0);

  useEffect(() => {
    const listener = () => setTick((t) => t + 1);
    globalListeners.add(listener);
    startGlobalTick();

    return () => {
      globalListeners.delete(listener);
      stopGlobalTick();
    };
  }, []);

  return globalTick;
}

/** Animated spinner with rotating dots */
export function SpinnerDots({
  label,
  fg,
}: {
  label?: string;
  fg?: string | RGBA;
}) {
  const { colors } = useTheme();
  const frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  const tick = useGlobalTick();
  const frame = tick % frames.length;

  return (
    <text
      fg={fg || colors.info}
      content={`${frames[frame]} ${label || "Loading"}`}
    />
  );
}

/** Horizontal line spinner */
export function SpinnerLine() {
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
export function SpinnerCircle() {
  const { colors } = useTheme();
  const frames = ["◐", "◓", "◑", "◒"];
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((prev) => (prev + 1) % frames.length);
    }, 150);
    return () => clearInterval(interval);
  }, []);

  return <text fg={colors.secondary} content={`${frames[frame]} Working`} />;
}

/** Braille pattern spinner */
export function SpinnerBraille({ label }: { label?: string }) {
  const { colors } = useTheme();
  const frames = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"];
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((prev) => (prev + 1) % frames.length);
    }, 80);
    return () => clearInterval(interval);
  }, []);

  return <text fg={colors.primary} content={`${frames[frame]} ${label || "Active"}`} />;
}

/** Animated progress bar */
export function ProgressBar({
  value,
  width,
}: {
  value: number;
  width?: number;
}) {
  const barWidth = width || 15;
  // Clamp value between 0 and 100, handle NaN
  const { colors } = useTheme();
  const safeValue = Math.max(0, Math.min(100, isNaN(value) ? 0 : value));
  const filled = Math.floor((safeValue / 100) * barWidth);
  const empty = barWidth - filled;
  const bar = "█".repeat(filled) + "░".repeat(empty);

  return <text fg={colors.primary} content={`[${bar}] ${safeValue}%`} />;
}

/** Pulsing dot indicator */
export function PulsingDot() {
  const { colors } = useTheme();
  const frames = ["⚫", "⚪", "⚫", "⚪"];
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((prev) => (prev + 1) % frames.length);
    }, 300);
    return () => clearInterval(interval);
  }, []);

  return <text fg={colors.info} content={`${frames[frame]} Syncing`} />;
}

/** Wave loading animation */
export function LoadingWave() {
  const { colors } = useTheme();
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

  return <text fg={colors.secondary} content={dots} />;
}

/** Beating heart animation */
export function HeartBeat() {
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
export function BlinkingEye() {
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
export function TypingIndicator() {
  const frames = ["   ", ".  ", ".. ", "..."];
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((prev) => (prev + 1) % frames.length);
    }, 300);
    return () => clearInterval(interval);
  }, []);

  const { colors } = useTheme();

  return <text fg={colors.textMuted} content={`typing${frames[frame]}`} />;
}

/** Rocket launch animation */
export function RocketLaunch() {
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
export function StatusPulse({
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

  const { colors } = useTheme();
  const opacity = Math.sin(intensity) * 0.5 + 0.5; // Oscillates between 0 and 1
  const bright = opacity > 0.5;

  const configs = {
    success: { icon: "●", color: colors.primary, label: "Success" },
    warning: { icon: "▲", color: colors.warning, label: "Warning" },
    error: { icon: "✖", color: colors.error, label: "Error" },
    info: { icon: "ℹ", color: colors.info, label: "Info" },
  };

  const config = configs[status];
  const displayIcon = bright ? config.icon : "○";

  return <text fg={config.color} content={`${displayIcon} ${config.label}`} />;
}
