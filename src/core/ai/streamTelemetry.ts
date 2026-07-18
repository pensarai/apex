// Per-stream connection telemetry for diagnosing provider-stream wedges (OFF
// unless PENSAR_STREAM_DEBUG=1); tracks bytes separately from parsed events to
// distinguish a dead stream from a slow-but-alive one.

import { createLogger } from "../logger/structured";
import { scopedLogger } from "../util/lazyLogger";

const log = scopedLogger(() => createLogger("stream-telemetry"));

export const STREAM_DEBUG =
  process.env.PENSAR_STREAM_DEBUG === "1" ||
  process.env.PENSAR_STREAM_DEBUG === "true";

const HEARTBEAT_MS = 10_000;

export type StreamPhase =
  | "connecting"
  | "first-byte"
  | "streaming-text"
  | `streaming-tool-args:${string}`
  | "tool-result"
  | "finish"
  | "wedged";

let seq = 0;

export class StreamTelemetry {
  readonly id: string;
  readonly label: string;
  private readonly startAt: number;
  private lastByteAt: number;
  private lastEventAt: number;
  private bytes = 0;
  private chunks = 0;
  private events = 0;
  private phase: StreamPhase = "connecting";
  private heartbeat: ReturnType<typeof setInterval> | undefined;

  constructor(label: string, nowMs: number) {
    this.id = `s${++seq}`;
    this.label = label;
    this.startAt = nowMs;
    this.lastByteAt = nowMs;
    this.lastEventAt = nowMs;
    if (STREAM_DEBUG) {
      this.log("open");
      this.heartbeat = setInterval(() => this.log("heartbeat"), HEARTBEAT_MS);
      this.heartbeat.unref?.();
    }
  }

  recordByte(byteLength: number, nowMs: number): void {
    this.bytes += byteLength;
    this.chunks++;
    this.lastByteAt = nowMs;
    if (this.phase === "connecting") this.setPhase("first-byte", nowMs);
  }

  recordEvent(nowMs: number): void {
    this.events++;
    this.lastEventAt = nowMs;
  }

  setPhase(phase: StreamPhase, nowMs: number): void {
    if (this.phase === phase) return;
    this.phase = phase;
    if (STREAM_DEBUG) this.log("phase", nowMs);
  }

  wedge(reason: string, nowMs: number): void {
    this.phase = "wedged";
    if (STREAM_DEBUG) this.log(`WEDGE reason=${JSON.stringify(reason)}`, nowMs);
  }

  finish(nowMs: number): void {
    if (this.heartbeat) clearInterval(this.heartbeat);
    if (STREAM_DEBUG) this.log("close", nowMs);
  }

  private log(tag: string, nowMs?: number): void {
    if (!STREAM_DEBUG) return;
    const t = nowMs ?? wallNow();
    log.info(
      `[stream-telem] ${this.id} ${tag} label=${JSON.stringify(this.label)} ` +
        `phase=${this.phase} elapsed=${t - this.startAt}ms ` +
        `bytes=${this.bytes} chunks=${this.chunks} events=${this.events} ` +
        `msSinceLastByte=${t - this.lastByteAt} msSinceLastEvent=${t - this.lastEventAt}`,
    );
  }
}

// Real wall clock is fine here — provider streaming isn't workflow-deterministic code.
export function wallNow(): number {
  return Date.now();
}
