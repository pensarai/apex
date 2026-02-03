/**
 * Gradient Wave Animation
 *
 * A smooth, flowing wave animation using sine waves with varying
 * amplitudes and phases. Creates a calm, professional aesthetic.
 */

import { clamp, smoothstep } from "./play-core/num";

// Wave parameters
const WAVE_COUNT = 4;
const BASE_SPEED = 0.03;

// ASCII gradient characters (dark to bright)
const GRADIENT_CHARS = " ·:;+*#░▒▓█";

export class WaveSimulation {
  width: number;
  height: number;
  time: number;
  private waves: Wave[];

  constructor(width: number, height: number) {
    this.width = width;
    this.height = height;
    this.time = 0;
    this.waves = this.initWaves();
  }

  private initWaves(): Wave[] {
    const waves: Wave[] = [];
    for (let i = 0; i < WAVE_COUNT; i++) {
      waves.push({
        frequency: 0.05 + i * 0.02,
        amplitude: 0.15 + i * 0.08,
        phase: (i * Math.PI) / 2,
        speed: BASE_SPEED * (1 + i * 0.3),
        yOffset: 0.3 + i * 0.15,
      });
    }
    return waves;
  }

  /**
   * Advance time and step simulation
   */
  step() {
    this.time += 1;
  }

  /**
   * Get wave value at position (0-1 range)
   */
  private getWaveValue(x: number, y: number): number {
    const normalizedX = x / this.width;
    const normalizedY = y / this.height;

    let totalValue = 0;
    let maxPossible = 0;

    for (const wave of this.waves) {
      // Calculate wave position
      const waveY = wave.yOffset +
        wave.amplitude * Math.sin(
          normalizedX * wave.frequency * this.width +
          this.time * wave.speed +
          wave.phase
        );

      // Distance from wave center (creates soft gradient)
      const distFromWave = Math.abs(normalizedY - waveY);

      // Soft falloff from wave center
      const intensity = smoothstep(0.3, 0, distFromWave);

      totalValue += intensity * (1 - wave.yOffset * 0.5);
      maxPossible += 1;
    }

    // Add subtle noise/texture
    const noise = Math.sin(x * 0.5 + y * 0.3 + this.time * 0.1) * 0.05;

    return clamp((totalValue / maxPossible) + noise, 0, 1);
  }

  /**
   * Render to ASCII string array
   */
  render(): string[] {
    const rows: string[] = [];

    for (let y = 0; y < this.height; y++) {
      let row = "";
      for (let x = 0; x < this.width; x++) {
        const value = this.getWaveValue(x, y);
        const charIdx = Math.floor(clamp(value, 0, 0.99) * GRADIENT_CHARS.length);
        row += GRADIENT_CHARS[charIdx];
      }
      rows.push(row);
    }

    return rows;
  }

  /**
   * Resize simulation
   */
  resize(width: number, height: number) {
    this.width = width;
    this.height = height;
  }
}

interface Wave {
  frequency: number;
  amplitude: number;
  phase: number;
  speed: number;
  yOffset: number;
}
