import { type OptimizedBuffer, RGBA } from "@opentui/core";
import { clamp, smoothstep } from "./play-core/num";

const GRADIENT_CHARS = " ·:;+*#░▒▓█";
const GRADIENT_CODES = Array.from(GRADIENT_CHARS, (char) =>
  char.codePointAt(0),
).filter((code): code is number => code !== undefined);
const FRAME_DURATION_MS = 50;
const INITIAL_STEP = 12;
const LOOP_STEPS = 100_000;

const WAVES = Array.from({ length: 4 }, (_, index) => ({
  frequency: 0.05 + index * 0.02,
  amplitude: 0.15 + index * 0.08,
  phase: (index * Math.PI) / 2,
  speed: 0.03 * (1 + index * 0.3),
  yOffset: 0.3 + index * 0.15,
}));

function createGradient(base: RGBA, steps: number): RGBA[] {
  const red = base.r * 255;
  const green = base.g * 255;
  const blue = base.b * 255;

  return Array.from({ length: steps }, (_, index) => {
    const progress = steps === 1 ? 1 : index / (steps - 1);
    const brightness = 0.35 + progress * 1.25;
    return RGBA.fromInts(
      Math.min(255, Math.round(red * brightness + progress * 25)),
      Math.min(255, Math.round(green * brightness)),
      Math.min(255, Math.round(blue * brightness + progress * 10)),
      255,
    );
  });
}

export class WavePainter {
  private background = RGBA.defaultBackground();
  private elapsedSteps = INITIAL_STEP;
  private primary = RGBA.defaultForeground();
  private gradient = createGradient(this.primary, 9);

  setBackground(value: RGBA | undefined): boolean {
    if (!value || this.background.equals(value)) return false;
    this.background = RGBA.clone(value);
    return true;
  }

  setPrimary(value: RGBA | undefined): boolean {
    if (!value || this.primary.equals(value)) return false;
    this.primary = RGBA.clone(value);
    this.gradient = createGradient(this.primary, 9);
    return true;
  }

  render(frameBuffer: OptimizedBuffer, deltaTime = 0): void {
    this.elapsedSteps =
      (this.elapsedSteps + deltaTime / FRAME_DURATION_MS) % LOOP_STEPS;

    const { width, height } = frameBuffer;
    const { char, fg, bg, attributes } = frameBuffer.buffers;
    const background = this.background.buffer;

    for (let y = 0; y < height; y++) {
      const rowProgress = y / Math.max(1, height - 1);
      const colorIndex = Math.floor(rowProgress * (this.gradient.length - 1));
      const color =
        this.gradient[Math.min(colorIndex, this.gradient.length - 1)];

      for (let x = 0; x < width; x++) {
        const cellIndex = y * width + x;
        const colorOffset = cellIndex * 4;
        const intensity = this.getWaveValue(x, y, width, height);
        const characterIndex = Math.floor(
          clamp(intensity, 0, 0.99) * GRADIENT_CODES.length,
        );

        char[cellIndex] = GRADIENT_CODES[characterIndex] ?? 32;
        attributes[cellIndex] = 0;
        fg.set(color.buffer, colorOffset);
        bg.set(background, colorOffset);
      }
    }
  }

  private getWaveValue(
    x: number,
    y: number,
    width: number,
    height: number,
  ): number {
    const normalizedX = x / width;
    const normalizedY = y / height;
    let total = 0;

    for (const wave of WAVES) {
      const waveY =
        wave.yOffset +
        wave.amplitude *
          Math.sin(
            normalizedX * wave.frequency * width +
              this.elapsedSteps * wave.speed +
              wave.phase,
          );
      const intensity = smoothstep(0.3, 0, Math.abs(normalizedY - waveY));
      total += intensity * (1 - wave.yOffset * 0.5);
    }

    const noise = Math.sin(x * 0.5 + y * 0.3 + this.elapsedSteps * 0.1) * 0.05;
    return clamp(total / WAVES.length + noise, 0, 1);
  }
}
