/**
 * 2D Vector Utilities
 *
 * GLSL-style vector math for terminal animations.
 * Ported from pensarai play-core utilities.
 */

export type Vec2 = [number, number];

/** Create a 2D vector */
export function vec2(x: number, y: number): Vec2 {
  return [x, y];
}

/** Add two vectors */
export function add(a: Vec2, b: Vec2): Vec2 {
  return [a[0] + b[0], a[1] + b[1]];
}

/** Subtract two vectors */
export function sub(a: Vec2, b: Vec2): Vec2 {
  return [a[0] - b[0], a[1] - b[1]];
}

/** Multiply vector by scalar */
export function mul(v: Vec2, s: number): Vec2 {
  return [v[0] * s, v[1] * s];
}

/** Divide vector by scalar */
export function div(v: Vec2, s: number): Vec2 {
  return [v[0] / s, v[1] / s];
}

/** Vector length (magnitude) */
export function length(v: Vec2): number {
  return Math.sqrt(v[0] * v[0] + v[1] * v[1]);
}

/** Normalize vector to unit length */
export function norm(v: Vec2): Vec2 {
  const len = length(v);
  if (len === 0) return [0, 0];
  return [v[0] / len, v[1] / len];
}

/** Distance between two points */
export function dist(a: Vec2, b: Vec2): number {
  return length(sub(a, b));
}

/** Dot product */
export function dot(a: Vec2, b: Vec2): number {
  return a[0] * b[0] + a[1] * b[1];
}

/** Rotate vector by angle (radians) */
export function rot(v: Vec2, angle: number): Vec2 {
  const cos = Math.cos(angle);
  const sin = Math.sin(angle);
  return [
    v[0] * cos - v[1] * sin,
    v[0] * sin + v[1] * cos
  ];
}

/** Linear interpolation between two vectors */
export function lerp(a: Vec2, b: Vec2, t: number): Vec2 {
  return [
    a[0] + (b[0] - a[0]) * t,
    a[1] + (b[1] - a[1]) * t
  ];
}

/** Angle from a to b (radians) */
export function angle(a: Vec2, b: Vec2): number {
  return Math.atan2(b[1] - a[1], b[0] - a[0]);
}

/** Create vector from angle and magnitude */
export function fromAngle(angle: number, magnitude: number = 1): Vec2 {
  return [
    Math.cos(angle) * magnitude,
    Math.sin(angle) * magnitude
  ];
}

/** Floor both components */
export function floor(v: Vec2): Vec2 {
  return [Math.floor(v[0]), Math.floor(v[1])];
}

/** Clamp vector components to range */
export function clampVec(v: Vec2, min: Vec2, max: Vec2): Vec2 {
  return [
    Math.max(min[0], Math.min(max[0], v[0])),
    Math.max(min[1], Math.min(max[1], v[1]))
  ];
}
