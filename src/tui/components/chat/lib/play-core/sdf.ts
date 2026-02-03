/**
 * Signed Distance Functions (SDFs)
 *
 * 2D distance functions for collision detection and rendering.
 * Ported from pensarai play-core utilities.
 */

import type { Vec2 } from "./vec2";
import { length, sub, dot } from "./vec2";
import { clamp as clampNum } from "./num";

/** Distance to circle */
export function sdCircle(p: Vec2, center: Vec2, radius: number): number {
  return length(sub(p, center)) - radius;
}

/** Distance to box (axis-aligned) */
export function sdBox(p: Vec2, center: Vec2, halfSize: Vec2): number {
  const d: Vec2 = [
    Math.abs(p[0] - center[0]) - halfSize[0],
    Math.abs(p[1] - center[1]) - halfSize[1]
  ];
  const outside = length([Math.max(d[0], 0), Math.max(d[1], 0)]);
  const inside = Math.min(Math.max(d[0], d[1]), 0);
  return outside + inside;
}

/** Distance to line segment */
export function sdSegment(p: Vec2, a: Vec2, b: Vec2): number {
  const pa = sub(p, a);
  const ba = sub(b, a);
  const h = clampNum(dot(pa, ba) / dot(ba, ba), 0, 1);
  return length(sub(pa, [ba[0] * h, ba[1] * h]));
}

/** Distance to capsule (line with rounded ends) */
export function sdCapsule(p: Vec2, a: Vec2, b: Vec2, radius: number): number {
  return sdSegment(p, a, b) - radius;
}

/** Distance to ring */
export function sdRing(p: Vec2, center: Vec2, innerRadius: number, outerRadius: number): number {
  const d = length(sub(p, center));
  return Math.abs(d - (innerRadius + outerRadius) / 2) - (outerRadius - innerRadius) / 2;
}

/** Union of two SDFs (smooth blend) */
export function opSmoothUnion(d1: number, d2: number, k: number): number {
  const h = clampNum(0.5 + 0.5 * (d2 - d1) / k, 0, 1);
  return d2 * (1 - h) + d1 * h - k * h * (1 - h);
}

/** Intersection of two SDFs */
export function opIntersection(d1: number, d2: number): number {
  return Math.max(d1, d2);
}

/** Subtraction of two SDFs */
export function opSubtraction(d1: number, d2: number): number {
  return Math.max(d1, -d2);
}

/** Repeat SDF in a grid */
export function opRepeat(p: Vec2, spacing: Vec2): Vec2 {
  return [
    ((p[0] % spacing[0]) + spacing[0]) % spacing[0] - spacing[0] / 2,
    ((p[1] % spacing[1]) + spacing[1]) % spacing[1] - spacing[1] / 2
  ];
}
