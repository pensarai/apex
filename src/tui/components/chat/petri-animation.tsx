/**
 * Wave Animation Component
 *
 * Smooth gradient wave animation for the home screen.
 * Renders at ~20fps using global tick system.
 */

import { useState, useEffect, useRef, useMemo } from "react";
import { RGBA } from "@opentui/core";
import { useTerminalDimensions } from "@opentui/react";
import { WaveSimulation } from "./lib/wave-simulation";

// Global tick system for animations (shared across components)
let globalTick = 0;
let globalListeners = new Set<() => void>();
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

// Green color gradient
const greenColors = [
  RGBA.fromInts(0, 60, 30, 255),    // Darkest
  RGBA.fromInts(0, 90, 45, 255),
  RGBA.fromInts(0, 120, 60, 255),
  RGBA.fromInts(0, 150, 75, 255),
  RGBA.fromInts(20, 180, 90, 255),
  RGBA.fromInts(40, 200, 100, 255),
  RGBA.fromInts(60, 220, 110, 255),
  RGBA.fromInts(80, 240, 120, 255),
  RGBA.fromInts(100, 255, 130, 255),  // Brightest
];

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
  const dimensions = useTerminalDimensions();
  const tick = useGlobalTick();
  const simulationRef = useRef<WaveSimulation | null>(null);
  const [frame, setFrame] = useState<string[]>([]);

  // Calculate actual dimensions
  const actualHeight = useMemo(() => {
    if (typeof height === "number" && height <= 1) {
      return Math.floor(dimensions.height * height);
    }
    return typeof height === "number" ? height : Math.floor(dimensions.height * 0.4);
  }, [height, dimensions.height]);

  const actualWidth = useMemo(() => {
    if (typeof width === "number" && width <= 1) {
      return Math.floor(dimensions.width * width);
    }
    if (width === "100%") {
      return dimensions.width - 8; // Account for padding
    }
    return typeof width === "number" ? width : dimensions.width - 8;
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
    <box
      flexDirection="column"
      width={actualWidth}
      height={actualHeight}
    >
      {frame.map((row, idx) => (
        <text
          key={idx}
          fg={getRowColor(idx, actualHeight)}
          content={row}
        />
      ))}
    </box>
  );
}

/**
 * Get color for a row (gradient from top to bottom)
 */
function getRowColor(rowIdx: number, totalRows: number): RGBA {
  // Create a gradient from top to bottom
  const progress = rowIdx / Math.max(1, totalRows - 1);

  // Map progress to color index
  const colorIdx = Math.floor(progress * (greenColors.length - 1));

  return greenColors[Math.min(colorIdx, greenColors.length - 1)];
}

export default PetriAnimation;
