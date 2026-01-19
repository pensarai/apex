/**
 * GLSL-style Math Utilities
 *
 * Common math functions for animations.
 * Ported from pensarai play-core utilities.
 */

/** Clamp value to range */
export function clamp(x: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, x));
}

/** Linear interpolation */
export function mix(a: number, b: number, t: number): number {
  return a + (b - a) * t;
}

/** Map value from one range to another */
export function map(
  value: number,
  inMin: number,
  inMax: number,
  outMin: number,
  outMax: number
): number {
  return outMin + ((value - inMin) / (inMax - inMin)) * (outMax - outMin);
}

/** Smoothstep interpolation */
export function smoothstep(edge0: number, edge1: number, x: number): number {
  const t = clamp((x - edge0) / (edge1 - edge0), 0, 1);
  return t * t * (3 - 2 * t);
}

/** Hermite interpolation (like smoothstep but smoother) */
export function smootherstep(edge0: number, edge1: number, x: number): number {
  const t = clamp((x - edge0) / (edge1 - edge0), 0, 1);
  return t * t * t * (t * (t * 6 - 15) + 10);
}

/** Fractional part of number */
export function fract(x: number): number {
  return x - Math.floor(x);
}

/** Step function: 0 if x < edge, 1 otherwise */
export function step(edge: number, x: number): number {
  return x < edge ? 0 : 1;
}

/** Sign of number: -1, 0, or 1 */
export function sign(x: number): number {
  if (x > 0) return 1;
  if (x < 0) return -1;
  return 0;
}

/** Modulo that works correctly for negative numbers */
export function mod(x: number, y: number): number {
  return ((x % y) + y) % y;
}

/** Random number in range [min, max) */
export function random(min: number = 0, max: number = 1): number {
  return min + Math.random() * (max - min);
}

/** Random integer in range [min, max] */
export function randomInt(min: number, max: number): number {
  return Math.floor(random(min, max + 1));
}

/** Simple hash function for pseudo-random based on seed */
export function hash(n: number): number {
  const x = Math.sin(n) * 43758.5453123;
  return x - Math.floor(x);
}

/** 2D hash function */
export function hash2(x: number, y: number): number {
  return hash(x + hash(y) * 1000);
}

/** Exponential decay */
export function expDecay(a: number, b: number, decay: number, dt: number): number {
  return b + (a - b) * Math.exp(-decay * dt);
}

/** Ease in (quadratic) */
export function easeIn(t: number): number {
  return t * t;
}

/** Ease out (quadratic) */
export function easeOut(t: number): number {
  return t * (2 - t);
}

/** Ease in-out (quadratic) */
export function easeInOut(t: number): number {
  return t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
}
