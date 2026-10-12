interface CaptureBuffer {
  // One owned, geometrically grown buffer, hard-capped at maxBytes: no
  // per-chunk allocations and no retained pipe-allocated backing storage.
  buf: Buffer;
  used: number;
  truncated: boolean;
  readonly max: number;
}

export function makeCapture(maxBytes: number): CaptureBuffer {
  return { buf: Buffer.alloc(0), used: 0, truncated: false, max: maxBytes };
}

export function captureChunk(cap: CaptureBuffer, chunk: Buffer): void {
  const room = cap.max - cap.used;
  if (room <= 0) {
    cap.truncated = true;
    return;
  }
  const take = Math.min(chunk.byteLength, room);
  if (take < chunk.byteLength) cap.truncated = true;
  if (cap.buf.byteLength < cap.used + take) {
    let size = cap.buf.byteLength || 64 * 1024;
    while (size < cap.used + take && size < cap.max) size *= 2;
    const next = Buffer.alloc(Math.min(size, cap.max));
    cap.buf.copy(next, 0, 0, cap.used);
    cap.buf = next;
  }
  chunk.copy(cap.buf, cap.used, 0, take);
  cap.used += take;
}

export function captureText(cap: CaptureBuffer): string {
  if (cap.used === 0) return "";
  // Full-UTF8 decode of exactly the captured bytes — no reassembly, so
  // multibyte sequences spanning chunk boundaries survive intact.
  return cap.buf.subarray(0, cap.used).toString("utf8");
}
