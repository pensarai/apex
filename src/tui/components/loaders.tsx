/**
 * Creative Loaders
 *
 * High-polish animated loading indicators for the TUI.
 */

import { useState, useEffect, useMemo } from "react";
import { RGBA } from "@opentui/core";
import { useTheme } from "../theme";
import { useObfuscation } from "../context/obfuscation";

// ---------------------------------------------------------------------------
// Shared tick system — all loaders share one interval to avoid timer bloat
// ---------------------------------------------------------------------------

let tick = 0;
const listeners = new Set<() => void>();
let interval: ReturnType<typeof setInterval> | null = null;

function ensureTick() {
  if (!interval) {
    interval = setInterval(() => {
      tick = (tick + 1) % 100_000;
      listeners.forEach((fn) => fn());
    }, 50); // 20 fps
  }
}

function releaseTick() {
  if (interval && listeners.size === 0) {
    clearInterval(interval);
    interval = null;
  }
}

function useTick(): number {
  const [, rerender] = useState(0);

  useEffect(() => {
    const fn = () => rerender((n) => n + 1);
    listeners.add(fn);
    ensureTick();
    return () => {
      listeners.delete(fn);
      releaseTick();
    };
  }, []);

  return tick;
}

export function withAlpha(base: RGBA, alpha: number): RGBA {
  return RGBA.fromInts(
    Math.round(base.r * 255),
    Math.round(base.g * 255),
    Math.round(base.b * 255),
    Math.round(Math.max(0, Math.min(1, alpha)) * 255),
  );
}

// ---------------------------------------------------------------------------
// SpinningDots — compact single-line braille-dot spinner with opacity trail
// ---------------------------------------------------------------------------

const SPIN_DOTS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/**
 * Tiny single-character braille spinner.
 * Renders as one line: `⠹ Loading`.
 *
 * The frame is derived from `Date.now()` so the visible glyph always
 * matches real elapsed time, regardless of when the parent re-renders.
 * This keeps the spin rate stable even when the host component is
 * under heavy re-render load (e.g. streaming token updates).
 *
 * @param intervalMs - milliseconds between frames (lower = faster).
 */
export function SpinningDots({
  label,
  fg,
  intervalMs = 60,
}: {
  label?: string;
  fg?: RGBA;
  intervalMs?: number;
}) {
  const { colors } = useTheme();
  const base = fg ?? colors.primary;
  const [, forceRender] = useState(0);

  useEffect(() => {
    const id = setInterval(() => {
      forceRender((n) => (n + 1) % 1_000_000);
    }, intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);

  const frame = Math.floor(Date.now() / intervalMs) % SPIN_DOTS.length;

  return (
    <box flexDirection="row" gap={1}>
      <text fg={base} content={SPIN_DOTS[frame]} />
      {label && <text fg={colors.textMuted}>{label}</text>}
    </box>
  );
}

// ---------------------------------------------------------------------------
// BouncingBox — bouncing block with fading opacity trail
// ---------------------------------------------------------------------------

const BOX_CHAR = "█";
const TRAIL_LENGTH = 5;

/**
 * A solid block that bounces left-to-right across `width` columns,
 * leaving a fading opacity trail behind it.
 */
export function BouncingBox({
  width = 24,
  fg,
  speed = 2,
  label,
}: {
  width?: number;
  fg?: RGBA;
  speed?: number;
  label?: string;
}) {
  const { colors } = useTheme();
  const base = fg ?? colors.primary;
  const t = useTick();

  const cycleLen = (width - 1) * 2;
  const raw = Math.floor(t / speed) % cycleLen;
  const pos = raw < width ? raw : cycleLen - raw;

  const trailColors = useMemo(() => {
    const steps: RGBA[] = [];
    for (let i = 0; i <= TRAIL_LENGTH; i++) {
      const alpha = 1.0 - i * (0.85 / TRAIL_LENGTH);
      steps.push(withAlpha(base, Math.max(0.08, alpha)));
    }
    return steps;
  }, [base]);

  const goingRight = raw < width;

  const cells = useMemo(() => {
    const out: { ch: string; color: RGBA | null }[] = [];
    for (let col = 0; col < width; col++) {
      const dist = goingRight ? pos - col : col - pos;
      if (dist >= 0 && dist <= TRAIL_LENGTH) {
        out.push({ ch: BOX_CHAR, color: trailColors[dist] });
      } else {
        out.push({ ch: " ", color: null });
      }
    }
    return out;
  }, [pos, goingRight, width, trailColors]);

  return (
    <box flexDirection="column">
      <box flexDirection="row">
        {cells.map((cell, i) => (
          <text
            key={i}
            fg={cell.color ?? colors.background}
            content={cell.ch}
          />
        ))}
      </box>
      {label && <text fg={colors.textMuted}>{label}</text>}
    </box>
  );
}

// ---------------------------------------------------------------------------
// BracketBounce — bouncing marker inside a bracketed dashed track
// ---------------------------------------------------------------------------

const MARKER = "■";
const DASH = "─";

/**
 * A marker that bounces left-to-right inside `[──────]` brackets,
 * with a dashed line through the middle and a fading trail.
 *
 * When `active` is false the component still renders the bracketed
 * track (so layout stays stable) but the marker is hidden and the
 * shared tick is not subscribed to — the visual is fully static.
 */
export function BracketBounce({
  width = 24,
  fg,
  speed = 3,
  label,
  trailLen = 4,
  active = true,
}: {
  width?: number;
  fg?: RGBA;
  speed?: number;
  label?: string;
  trailLen?: number;
  active?: boolean;
}) {
  const { colors } = useTheme();
  const base = fg ?? colors.primary;
  const inner = Math.max(1, width - 2);

  const dashColor = withAlpha(colors.textMuted, 0.3);
  const bracketColor = withAlpha(colors.textMuted, 0.6);

  if (!active) {
    return (
      <box flexDirection="column">
        <box flexDirection="row">
          <text fg={bracketColor} content="[" />
          {Array.from({ length: inner }, (_, i) => (
            <text key={i} fg={dashColor} content={DASH} />
          ))}
          <text fg={bracketColor} content="]" />
        </box>
        {label && <text fg={colors.textMuted}>{label}</text>}
      </box>
    );
  }

  return (
    <BracketBounceActive
      inner={inner}
      base={base}
      speed={speed}
      trailLen={trailLen}
      dashColor={dashColor}
      bracketColor={bracketColor}
      label={label}
      mutedColor={colors.textMuted}
    />
  );
}

function BracketBounceActive({
  inner,
  base,
  speed,
  trailLen,
  dashColor,
  bracketColor,
  label,
  mutedColor,
}: {
  inner: number;
  base: RGBA;
  speed: number;
  trailLen: number;
  dashColor: RGBA;
  bracketColor: RGBA;
  label?: string;
  mutedColor: RGBA;
}) {
  const t = useTick();

  const halfCycle = inner - 1;
  const fullCycle = halfCycle * 2;
  const raw = Math.floor(t / speed) % Math.max(1, fullCycle);
  const goingRight = raw < halfCycle;
  const linear = goingRight ? raw / halfCycle : (fullCycle - raw) / halfCycle;
  const eased =
    linear < 0.5
      ? 4 * linear * linear * linear
      : 1 - Math.pow(-2 * linear + 2, 3) / 2;
  const pos = Math.round(eased * (inner - 1));

  const trailColors = useMemo(() => {
    const steps: RGBA[] = [];
    for (let i = 0; i <= trailLen; i++) {
      const alpha = 1.0 - i * (0.85 / trailLen);
      steps.push(withAlpha(base, Math.max(0.12, alpha)));
    }
    return steps;
  }, [base, trailLen]);

  const cells = useMemo(() => {
    const out: { ch: string; color: RGBA }[] = [];
    out.push({ ch: "[", color: bracketColor });
    for (let col = 0; col < inner; col++) {
      const dist = goingRight ? pos - col : col - pos;
      if (dist === 0) {
        out.push({ ch: MARKER, color: trailColors[0] });
      } else if (dist > 0 && dist <= trailLen) {
        out.push({ ch: MARKER, color: trailColors[dist] });
      } else {
        out.push({ ch: DASH, color: dashColor });
      }
    }
    out.push({ ch: "]", color: bracketColor });
    return out;
  }, [pos, goingRight, inner, trailColors, trailLen, dashColor, bracketColor]);

  return (
    <box flexDirection="column">
      <box flexDirection="row">
        {cells.map((cell, i) => (
          <text key={i} fg={cell.color} content={cell.ch} />
        ))}
      </box>
      {label && <text fg={mutedColor}>{label}</text>}
    </box>
  );
}

// ---------------------------------------------------------------------------
// PulseRing — concentric ring that pulses outward
// ---------------------------------------------------------------------------

const RING_FRAMES = ["◉", "◎", "○", "◌", " "];

/**
 * A single character that cycles through concentric ring glyphs,
 * creating a "radar ping" pulse effect.
 */
export function PulseRing({
  label,
  fg,
  speed = 4,
}: {
  label?: string;
  fg?: RGBA;
  speed?: number;
}) {
  const { colors } = useTheme();
  const base = fg ?? colors.info;
  const t = useTick();
  const frame = Math.floor(t / speed) % RING_FRAMES.length;
  const alpha = 1.0 - frame * (0.8 / (RING_FRAMES.length - 1));

  return (
    <box flexDirection="row" gap={1}>
      <text fg={withAlpha(base, alpha)} content={RING_FRAMES[frame]} />
      {label && <text fg={colors.textMuted}>{label}</text>}
    </box>
  );
}

// ---------------------------------------------------------------------------
// WaveBar — horizontal bar with a sine-wave brightness sweep
// ---------------------------------------------------------------------------

/**
 * A row of block characters with a bright spot that sweeps
 * back and forth in a smooth sine wave.
 */
export function WaveBar({
  width = 20,
  fg,
  speed = 1,
  label,
  bounce = false,
}: {
  width?: number;
  fg?: RGBA;
  speed?: number;
  label?: string;
  bounce?: boolean;
}) {
  const { colors } = useTheme();
  const base = fg ?? colors.primary;
  const t = useTick();

  const cells = useMemo(() => {
    const out: { color: RGBA }[] = [];
    if (bounce) {
      const cycleLen = (width - 1) * 2;
      const raw = Math.floor(t * speed * 0.6) % Math.max(1, cycleLen);
      const center = raw < width ? raw : cycleLen - raw;
      for (let i = 0; i < width; i++) {
        const dist = Math.abs(i - center);
        const alpha = Math.max(0.08, 1.0 - dist * (0.9 / (width * 0.3)));
        out.push({ color: withAlpha(base, alpha) });
      }
    } else {
      const phase = t * speed * 0.06;
      for (let i = 0; i < width; i++) {
        const norm = i / (width - 1);
        const wave = Math.sin(phase - norm * Math.PI * 2);
        const alpha = 0.12 + 0.88 * Math.max(0, wave);
        out.push({ color: withAlpha(base, alpha) });
      }
    }
    return out;
  }, [t, width, base, speed, bounce]);

  return (
    <box flexDirection="column">
      <box flexDirection="row">
        {cells.map((cell, i) => (
          <text key={i} fg={cell.color} content="▬" />
        ))}
      </box>
      {label && <text fg={colors.textMuted}>{label}</text>}
    </box>
  );
}

// ---------------------------------------------------------------------------
// BarPulse — multiple bars that pulse in sequence like an equalizer
// ---------------------------------------------------------------------------

const BAR_HEIGHTS = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

/**
 * A row of vertical bars that pulse up and down in a staggered wave,
 * like an audio equalizer visualization.
 */
export function BarPulse({
  bars = 8,
  fg,
  speed = 1,
  label,
}: {
  bars?: number;
  fg?: RGBA;
  speed?: number;
  label?: string;
}) {
  const { colors } = useTheme();
  const base = fg ?? colors.secondary ?? colors.primary;
  const t = useTick();

  const display = useMemo(() => {
    const out: { ch: string; color: RGBA }[] = [];
    for (let i = 0; i < bars; i++) {
      const wave = Math.sin(t * speed * 0.08 - i * 0.7);
      const norm = (wave + 1) / 2;
      const idx = Math.round(norm * (BAR_HEIGHTS.length - 1));
      const alpha = 0.3 + 0.7 * norm;
      out.push({ ch: BAR_HEIGHTS[idx], color: withAlpha(base, alpha) });
    }
    return out;
  }, [t, bars, base, speed]);

  return (
    <box flexDirection="column">
      <box flexDirection="row">
        {display.map((b, i) => (
          <text key={i} fg={b.color} content={b.ch} />
        ))}
      </box>
      {label && <text fg={colors.textMuted}>{label}</text>}
    </box>
  );
}

// ---------------------------------------------------------------------------
// OrbitDots — dots orbiting around a center point on a single line
// ---------------------------------------------------------------------------

const ORBIT_GLYPHS = ["⠁", "⠂", "⠄", "⡀", "⢀", "⠠", "⠐", "⠈"];

/**
 * A set of braille dots that orbit in sequence with fading trails,
 * rendered as a compact inline indicator.
 */
export function OrbitDots({
  label,
  fg,
  speed = 2,
  count = 3,
}: {
  label?: string;
  fg?: RGBA;
  speed?: number;
  count?: number;
}) {
  const { colors } = useTheme();
  const base = fg ?? colors.accent;
  const t = useTick();
  const len = ORBIT_GLYPHS.length;

  const display = useMemo(() => {
    const out: { ch: string; color: RGBA }[] = [];
    for (let i = 0; i < count; i++) {
      const frame = Math.floor(t / speed + i * (len / count)) % len;
      const alpha = 1.0 - i * (0.6 / count);
      out.push({ ch: ORBIT_GLYPHS[frame], color: withAlpha(base, alpha) });
    }
    return out;
  }, [t, count, base, speed]);

  return (
    <box flexDirection="row" gap={1}>
      <box flexDirection="row">
        {display.map((d, i) => (
          <text key={i} fg={d.color} content={d.ch} />
        ))}
      </box>
      {label && <text fg={colors.textMuted}>{label}</text>}
    </box>
  );
}

// ---------------------------------------------------------------------------
// ScanLine — a bright line that sweeps across a dim field
// ---------------------------------------------------------------------------

/**
 * A horizontal field of dim dots with a bright vertical scan line
 * that sweeps left-to-right continuously.
 */
export function ScanLine({
  width = 24,
  fg,
  speed = 2,
  label,
  bounce = false,
}: {
  width?: number;
  fg?: RGBA;
  speed?: number;
  label?: string;
  bounce?: boolean;
}) {
  const { colors } = useTheme();
  const base = fg ?? colors.primary;
  const t = useTick();
  const raw = Math.floor(t / speed);
  const pos = bounce
    ? (() => {
        const cycle = (width - 1) * 2;
        const r = raw % Math.max(1, cycle);
        return r < width ? r : cycle - r;
      })()
    : raw % width;

  const cells = useMemo(() => {
    const out: { ch: string; color: RGBA }[] = [];
    for (let i = 0; i < width; i++) {
      const dist = Math.abs(i - pos);
      if (dist === 0) {
        out.push({ ch: "┃", color: base });
      } else if (dist <= 2) {
        out.push({ ch: "│", color: withAlpha(base, 0.5 - dist * 0.15) });
      } else {
        out.push({ ch: "·", color: withAlpha(colors.textMuted, 0.25) });
      }
    }
    return out;
  }, [pos, width, base, colors.textMuted]);

  return (
    <box flexDirection="column">
      <box flexDirection="row">
        {cells.map((cell, i) => (
          <text key={i} fg={cell.color} content={cell.ch} />
        ))}
      </box>
      {label && <text fg={colors.textMuted}>{label}</text>}
    </box>
  );
}

// ---------------------------------------------------------------------------
// Typewriter — text that types out character by character then resets
// ---------------------------------------------------------------------------

/**
 * Animates `text` appearing one character at a time with a blinking
 * cursor, then pauses and restarts.
 */
export function Typewriter({
  text,
  fg,
  speed = 3,
  pauseTicks = 30,
}: {
  text: string;
  fg?: RGBA;
  speed?: number;
  pauseTicks?: number;
}) {
  const { colors } = useTheme();
  const base = fg ?? colors.text;
  const t = useTick();

  const cycleLen = text.length * speed + pauseTicks;
  const frame = t % cycleLen;
  const charsShown = Math.min(text.length, Math.floor(frame / speed));
  const showCursor = frame < text.length * speed;
  const cursorVisible = t % 10 < 5;

  const visible = text.slice(0, charsShown);
  const cursor = showCursor && cursorVisible ? "▌" : " ";

  return (
    <box flexDirection="row">
      <text fg={base} content={visible} />
      <text fg={withAlpha(base, 0.7)} content={cursor} />
    </box>
  );
}

// ---------------------------------------------------------------------------
// LaserBar — BouncingBox variant with dim filled track and long smooth trail
// ---------------------------------------------------------------------------

const LASER_TRAIL = 12;

/**
 * A dim `▬` bar with a bright head that bounces left-to-right.
 * Built on BouncingBox's proven bounce logic with a longer quadratic
 * opacity trail and a filled dim track underneath.
 */
export function LaserBar({
  width = 30,
  fg,
  speed = 2,
  label,
  trailLen = LASER_TRAIL,
  brackets = false,
  track = true,
}: {
  width?: number;
  fg?: RGBA;
  speed?: number;
  label?: string;
  trailLen?: number;
  brackets?: boolean;
  /** Render a dim filled `▬` track behind the laser head. Default true. */
  track?: boolean;
}) {
  const { colors } = useTheme();
  const base = fg ?? colors.primary;
  const t = useTick();

  const inner = brackets ? Math.max(1, width - 2) : width;

  // Overshoot by trailLen on both sides so the trail fully drains
  // off-screen before the head reverses direction
  const span = inner - 1 + trailLen * 2;
  const cycleLen = span * 2;
  const raw = Math.floor(t * speed * 1.5) % cycleLen;
  const rawPos = raw < span ? raw : cycleLen - raw;
  const pos = rawPos - trailLen;
  const goingRight = raw < span;

  const bracketColor = withAlpha(colors.textMuted, 0.6);

  const cells = useMemo(() => {
    const out: { ch: string; color: RGBA }[] = [];
    if (brackets) out.push({ ch: "[", color: bracketColor });
    for (let col = 0; col < inner; col++) {
      const dist = goingRight ? pos - col : col - pos;
      if (dist >= 0 && dist <= trailLen) {
        const norm = dist / trailLen;
        const alpha = 0.7 - norm * norm * 0.62;
        out.push({ ch: "▬", color: withAlpha(base, Math.max(0.08, alpha)) });
      } else if (track) {
        out.push({ ch: "▬", color: withAlpha(base, 0.08) });
      } else {
        out.push({ ch: " ", color: base });
      }
    }
    if (brackets) out.push({ ch: "]", color: bracketColor });
    return out;
  }, [pos, goingRight, inner, base, trailLen, brackets, bracketColor, track]);

  return (
    <box flexDirection="column">
      <box flexDirection="row">
        {cells.map((cell, i) => (
          <text key={i} fg={cell.color} content={cell.ch} />
        ))}
      </box>
      {label && <text fg={colors.textMuted}>{label}</text>}
    </box>
  );
}

// ---------------------------------------------------------------------------
// ShiningText — text with a bright highlight that sweeps across it
// ---------------------------------------------------------------------------

/**
 * Renders `text` with a bright shimmer that sweeps left-to-right,
 * like light glinting off a surface. Base text stays dim, and a
 * bell-curve bright window slides across continuously.
 */
export function ShiningText({
  text,
  fg,
  speed = 2,
  shimmerWidth = 9,
  baseAlpha = 0.35,
}: {
  text: string;
  fg?: RGBA;
  speed?: number;
  shimmerWidth?: number;
  baseAlpha?: number;
}) {
  const { colors } = useTheme();
  const base = fg ?? colors.text;
  // Subscribe to the shared tick to drive re-renders, but derive the cycle
  // position from absolute wall-clock time so multiple ShiningText instances
  // (with different text lengths) start each shimmer pass in lockstep.
  useTick();

  // Each character gets its own `<text content={ch} />`. The content setter
  // sits on TextRenderable, not TextNodeRenderable, so it bypasses the
  // central obfuscation patch in `tui/obfuscation/patch.ts`. Apply
  // obfuscation here at the component boundary so the per-char split
  // operates on the already-redacted string. Subscribing via
  // `useObfuscation()` also forces a re-render on toggle.
  const { redact } = useObfuscation();
  const displayText = redact(text);

  const len = displayText.length;
  const totalFrames = len + shimmerWidth;
  const periodMs = 1250 / speed;
  const cyclePos = (Date.now() % periodMs) / periodMs;
  // Smoothstep easing per cycle so the highlight glides through the middle
  // and softens near the edges — gives a more natural "shine" sweep.
  const eased = cyclePos * cyclePos * (3 - 2 * cyclePos);
  const head = Math.floor(eased * totalFrames);

  const chars = useMemo(() => {
    const out: { ch: string; color: RGBA }[] = [];
    for (let i = 0; i < len; i++) {
      const dist = head - i;
      if (dist >= 0 && dist < shimmerWidth) {
        const norm = dist / (shimmerWidth - 1);
        const bell = 1.0 - (2 * norm - 1) * (2 * norm - 1);
        const alpha = baseAlpha + (1.0 - baseAlpha) * bell;
        out.push({ ch: displayText[i], color: withAlpha(base, alpha) });
      } else {
        out.push({ ch: displayText[i], color: withAlpha(base, baseAlpha) });
      }
    }
    return out;
  }, [head, displayText, base, shimmerWidth, baseAlpha, len]);

  return (
    <box flexDirection="row">
      {chars.map((c, i) => (
        <text key={i} fg={c.color} content={c.ch} />
      ))}
    </box>
  );
}
