import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createLogger, type LogLevel, resolveInitialLevel } from "./structured";

// Capture process.stderr.write into `sink`; returns a restore fn.
function captureStderr(sink: string[]): () => void {
  const original = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: string | Uint8Array): boolean => {
    sink.push(typeof chunk === "string" ? chunk : chunk.toString());
    return true;
  }) as typeof process.stderr.write;
  return () => {
    process.stderr.write = original;
  };
}

function firstRecord(writes: string[]): Record<string, unknown> {
  const raw = writes[0];
  if (raw === undefined) throw new Error("no log line captured");
  return JSON.parse(raw) as Record<string, unknown>;
}

describe("resolveInitialLevel — precedence", () => {
  it("uses PENSAR_LOG_LEVEL over PENSAR_DEBUG and default", () => {
    expect(
      resolveInitialLevel({ PENSAR_LOG_LEVEL: "WARN", PENSAR_DEBUG: "1" }),
    ).toBe("WARN");
  });

  it("is case-insensitive for PENSAR_LOG_LEVEL", () => {
    expect(resolveInitialLevel({ PENSAR_LOG_LEVEL: "error" })).toBe("ERROR");
  });

  it("ignores an invalid PENSAR_LOG_LEVEL and falls through", () => {
    expect(
      resolveInitialLevel({ PENSAR_LOG_LEVEL: "bogus", PENSAR_DEBUG: "true" }),
    ).toBe("DEBUG");
  });

  it("maps PENSAR_DEBUG=1 to debug", () => {
    expect(resolveInitialLevel({ PENSAR_DEBUG: "1" })).toBe("DEBUG");
  });

  it("maps PENSAR_DEBUG=true to debug", () => {
    expect(resolveInitialLevel({ PENSAR_DEBUG: "TRUE" })).toBe("DEBUG");
  });

  it("ignores PENSAR_DEBUG=0 / false", () => {
    expect(resolveInitialLevel({ PENSAR_DEBUG: "0" })).toBe("INFO");
    expect(resolveInitialLevel({ PENSAR_DEBUG: "false" })).toBe("INFO");
  });

  it("defaults to info on empty env", () => {
    expect(resolveInitialLevel({})).toBe("INFO");
  });
});

describe("level gating", () => {
  let writes: string[];
  let restore: () => void;

  beforeEach(() => {
    writes = [];
    // Force JSON output for deterministic, parseable records.
    process.env.PENSAR_LOG_FORMAT = "json";
    restore = captureStderr(writes);
  });

  afterEach(() => {
    restore();
    delete process.env.PENSAR_LOG_FORMAT;
  });

  function methodsThatEmit(level: LogLevel): string[] {
    writes.length = 0;
    const log = createLogger();
    log.setLevel(level);
    log.debug("d");
    log.info("i");
    log.warn("w");
    log.error("e");
    return writes.map((w) => JSON.parse(w).level as string);
  }

  it("emits debug+ at debug threshold", () => {
    expect(methodsThatEmit("DEBUG")).toEqual([
      "DEBUG",
      "INFO",
      "WARN",
      "ERROR",
    ]);
  });

  it("emits info+ at info threshold", () => {
    expect(methodsThatEmit("INFO")).toEqual(["INFO", "WARN", "ERROR"]);
  });

  it("emits warn+ at warn threshold", () => {
    expect(methodsThatEmit("WARN")).toEqual(["WARN", "ERROR"]);
  });

  it("emits only error at error threshold", () => {
    expect(methodsThatEmit("ERROR")).toEqual(["ERROR"]);
  });

  it("emits nothing at silent threshold", () => {
    expect(methodsThatEmit("SILENT")).toEqual([]);
  });
});

describe("JSON record shape", () => {
  let writes: string[];
  let restore: () => void;

  beforeEach(() => {
    writes = [];
    process.env.PENSAR_LOG_FORMAT = "json";
    restore = captureStderr(writes);
  });

  afterEach(() => {
    restore();
    delete process.env.PENSAR_LOG_FORMAT;
  });

  it("writes one-line JSON ending in newline with ts/level/msg", () => {
    const log = createLogger();
    log.setLevel("INFO");
    log.info("hello");

    expect(writes).toHaveLength(1);
    const raw = writes[0] ?? "";
    expect(raw.endsWith("\n")).toBe(true);
    expect(raw.trimEnd().includes("\n")).toBe(false);

    const rec = firstRecord(writes);
    expect(rec.level).toBe("INFO");
    expect(rec.msg).toBe("hello");
    expect(typeof rec.ts).toBe("string");
    expect(rec.scope).toBeUndefined();
  });

  it("includes scope and merged fields", () => {
    const log = createLogger("net").child("http");
    log.setLevel("DEBUG");
    log.debug("req", { status: 200, path: "/x" });

    const rec = firstRecord(writes);
    expect(rec.scope).toBe("net:http");
    expect(rec.status).toBe(200);
    expect(rec.path).toBe("/x");
  });

  it("flattens an Error on error() into error/stack fields", () => {
    const log = createLogger("boom");
    log.setLevel("DEBUG");
    log.error("failed", new Error("kaboom"), { attempt: 2 });

    const rec = firstRecord(writes);
    expect(rec.level).toBe("ERROR");
    expect(rec.msg).toBe("failed");
    expect(rec.error).toBe("kaboom");
    expect(typeof rec.stack).toBe("string");
    expect(rec.attempt).toBe(2);
  });

  it("treats a plain object second arg to error() as fields", () => {
    const log = createLogger();
    log.setLevel("DEBUG");
    log.error("nope", { code: "E_X" });

    const rec = firstRecord(writes);
    expect(rec.code).toBe("E_X");
    expect(rec.error).toBeUndefined();
  });
});
