import { describe, it, expect } from "vitest";

const BLOCK_CHARS = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

function renderGraphLine(
  values: number[],
  minVal: number,
  maxVal: number,
  graphWidth: number,
): string {
  if (values.length === 0) return "";

  const range = maxVal - minVal || 1;

  const interpolated: number[] = [];
  for (let i = 0; i < graphWidth; i++) {
    const t =
      values.length <= 1 ? 0 : (i / (graphWidth - 1)) * (values.length - 1);
    const lo = Math.floor(t);
    const hi = Math.min(lo + 1, values.length - 1);
    const frac = t - lo;
    interpolated.push(values[lo] + (values[hi] - values[lo]) * frac);
  }

  return interpolated
    .map((v) => {
      const normalized = (v - minVal) / range;
      const idx = Math.round(normalized * (BLOCK_CHARS.length - 1));
      return BLOCK_CHARS[Math.max(0, Math.min(idx, BLOCK_CHARS.length - 1))];
    })
    .join("");
}

function buildXAxisWithMid(
  start: string,
  mid: string,
  end: string,
  totalWidth: number,
): string {
  const midPos = Math.floor(totalWidth / 2) - Math.floor(mid.length / 2);
  const afterMid = midPos + mid.length;
  const endPos = totalWidth - end.length;

  if (midPos <= start.length + 1 || afterMid >= endPos - 1) {
    return (
      start +
      " ".repeat(Math.max(0, totalWidth - start.length - end.length)) +
      end
    );
  }

  return (
    start +
    " ".repeat(midPos - start.length) +
    mid +
    " ".repeat(endPos - afterMid) +
    end
  );
}

describe("LineGraph rendering logic", () => {
  describe("renderGraphLine", () => {
    it("returns empty string for empty values", () => {
      expect(renderGraphLine([], 0, 100, 10)).toBe("");
    });

    it("renders a single value as repeated same character", () => {
      const result = renderGraphLine([50], 0, 100, 5);
      expect(result.length).toBe(5);
      const uniqueChars = new Set(result.split(""));
      expect(uniqueChars.size).toBe(1);
    });

    it("renders ascending values with ascending block chars", () => {
      const result = renderGraphLine([0, 50, 100], 0, 100, 3);
      expect(result.length).toBe(3);
      expect(result[0]).toBe(BLOCK_CHARS[0]);
      expect(result[2]).toBe(BLOCK_CHARS[BLOCK_CHARS.length - 1]);
    });

    it("renders all same values as same character", () => {
      const result = renderGraphLine([42, 42, 42], 0, 100, 5);
      const uniqueChars = new Set(result.split(""));
      expect(uniqueChars.size).toBe(1);
    });

    it("renders correct width", () => {
      const result = renderGraphLine([10, 20, 30, 40, 50], 0, 50, 20);
      expect(result.length).toBe(20);
    });

    it("handles min equal to max (range=0)", () => {
      const result = renderGraphLine([5, 5, 5], 5, 5, 5);
      expect(result.length).toBe(5);
    });
  });

  describe("buildXAxisWithMid", () => {
    it("places start and end labels at edges", () => {
      const result = buildXAxisWithMid("Jan", "Jul", "Dec", 40);
      expect(result.startsWith("Jan")).toBe(true);
      expect(result.endsWith("Dec")).toBe(true);
      expect(result.length).toBe(40);
    });

    it("falls back when mid label would overlap", () => {
      const result = buildXAxisWithMid("January", "July", "December", 20);
      expect(result.startsWith("January")).toBe(true);
      expect(result.endsWith("December")).toBe(true);
    });

    it("includes mid label in the middle when space allows", () => {
      const result = buildXAxisWithMid("A", "M", "Z", 30);
      expect(result).toContain("M");
      expect(result.length).toBe(30);
    });
  });
});
