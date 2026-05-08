/**
 * Wave Animation Component
 *
 * Smooth gradient wave animation for the home screen.
 * Renders at ~20fps using global tick system.
 */

import { RGBA } from "@opentui/core";
import { useEffect, useMemo, useRef, useState } from "react";
import { useDimensions } from "../../context/dimensions";
import { useTheme } from "../../theme";
import { WaveSimulation } from "./lib/wave-simulation";

// Global tick system for animations (shared across components)
let globalTick = 0;
const globalListeners = new Set<() => void>();
let globalInterval: ReturnType<typeof setInterval> | null = null;

function startGlobalTick() {
  if (!globalInterval) {
    globalInterval = setInterval(() => {
      globalTick = (globalTick + 1) % 1000;
      globalListeners.forEach((listener) => listener());
    }, 50); // ~20fps
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

/**
 * Generate a gradient array of N RGBA steps from a dim version of `base`
 * to a boosted brighter version beyond `base`.
 *
 * The original hardcoded gradient ranged from very dark (0,60,30) to very
 * bright (100,255,130) — well past the base green. This replicates that by
 * going from 0% of base to ~160% (clamped at 255), with a slight warm shift
 * (adding a touch of red) at the bright end for richness.
 */
function generateGradient(base: RGBA, steps: number): RGBA[] {
  const r = base.r * 255;
  const g = base.g * 255;
  const b = base.b * 255;
  return Array.from({ length: steps }, (_, i) => {
    const t = steps === 1 ? 1 : i / (steps - 1);
    // Start at ~35% brightness, ramp beyond 100% to get the original's
    // characteristic bright top end (original peaked at 100,255,130 from a
    // base of ~76,175,80).
    const brightness = 0.35 + t * 1.25;
    return RGBA.fromInts(
      Math.min(255, Math.round(r * brightness + t * 25)),
      Math.min(255, Math.round(g * brightness)),
      Math.min(255, Math.round(b * brightness + t * 10)),
      255,
    );
  });
}

interface PetriAnimationProps {
  /** Height as percentage of terminal (0-1) or fixed rows */
  height?: number | string;
  /** Width as percentage of terminal (0-1) or fixed columns */
  width?: number | string;
}

export function PetriAnimation({
  height = 0.4,
  width = "100%",
}: PetriAnimationProps) {
  const dimensions = useDimensions();
  const tick = useGlobalTick();
  const { colors } = useTheme();
  const simulationRef = useRef<WaveSimulation | null>(null);
  const [frame, setFrame] = useState<string[]>([]);

  // Theme-derived gradient (dim → bright primary)
  const gradientColors = useMemo(
    () => generateGradient(colors.primary, 9),
    [colors.primary],
  );

  // Calculate actual dimensions
  const actualHeight = useMemo(() => {
    if (typeof height === "number" && height <= 1) {
      return Math.floor(dimensions.height * height);
    }
    return typeof height === "number"
      ? height
      : Math.floor(dimensions.height * 0.4);
  }, [height, dimensions.height]);

  const actualWidth = useMemo(() => {
    if (typeof width === "number" && width <= 1) {
      return Math.floor(dimensions.width * width);
    }
    if (width === "100%") {
      return dimensions.width;
    }
    return typeof width === "number" ? width : dimensions.width;
  }, [width, dimensions.width]);

  // Initialize or resize simulation
  useEffect(() => {
    if (actualWidth <= 0 || actualHeight <= 0) return;

    if (!simulationRef.current) {
      simulationRef.current = new WaveSimulation(actualWidth, actualHeight);
    } else if (
      simulationRef.current.width !== actualWidth ||
      simulationRef.current.height !== actualHeight
    ) {
      simulationRef.current.resize(actualWidth, actualHeight);
    }
  }, [actualWidth, actualHeight]);

  // Step simulation on each tick
  useEffect(() => {
    if (simulationRef.current) {
      simulationRef.current.step();
      setFrame(simulationRef.current.render());
    }
  }, [tick]);

  if (frame.length === 0 || actualWidth <= 0 || actualHeight <= 0) {
    return null;
  }

  return (
    <box flexDirection="column" width={actualWidth} height={actualHeight}>
      {frame.map((row, idx) => (
        <text
          key={idx}
          fg={getRowColor(idx, actualHeight, gradientColors)}
          content={row}
        />
      ))}
    </box>
  );
}

/**
 * Get color for a row (gradient from top to bottom)
 */
function getRowColor(
  rowIdx: number,
  totalRows: number,
  gradient: RGBA[],
): RGBA {
  // Create a gradient from top to bottom
  const progress = rowIdx / Math.max(1, totalRows - 1);

  // Map progress to color index
  const colorIdx = Math.floor(progress * (gradient.length - 1));

  return gradient[Math.min(colorIdx, gradient.length - 1)];
}

export default PetriAnimation;
