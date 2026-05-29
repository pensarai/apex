import { describe, expect, it } from "vitest";
import {
  isMessageId,
  isPartId,
  isSessionId,
  newMessageId,
  newPartId,
  newSessionId,
} from "./id";

// ---------------------------------------------------------------------------
// Prefixed-ULID identity: minters, prefixes, uniqueness, and guards.
// ---------------------------------------------------------------------------

const ITERATIONS = 100_000;

describe("id minters", () => {
  it("mint correct prefixes", () => {
    expect(newSessionId()).toMatch(/^ses_/);
    expect(newMessageId()).toMatch(/^msg_/);
    expect(newPartId()).toMatch(/^prt_/);
  });

  it("produce unique session ids over 100k iterations", () => {
    const seen = new Set<string>();
    for (let i = 0; i < ITERATIONS; i++) seen.add(newSessionId());
    expect(seen.size).toBe(ITERATIONS);
  });

  it("produce unique message ids over 100k iterations", () => {
    const seen = new Set<string>();
    for (let i = 0; i < ITERATIONS; i++) seen.add(newMessageId());
    expect(seen.size).toBe(ITERATIONS);
  });

  it("produce unique part ids over 100k iterations", () => {
    const seen = new Set<string>();
    for (let i = 0; i < ITERATIONS; i++) seen.add(newPartId());
    expect(seen.size).toBe(ITERATIONS);
  });
});

describe("id guards", () => {
  it("accept their own kind", () => {
    expect(isSessionId(newSessionId())).toBe(true);
    expect(isMessageId(newMessageId())).toBe(true);
    expect(isPartId(newPartId())).toBe(true);
  });

  it("reject other kinds", () => {
    const ses = newSessionId();
    const msg = newMessageId();
    const prt = newPartId();

    expect(isSessionId(msg)).toBe(false);
    expect(isSessionId(prt)).toBe(false);

    expect(isMessageId(ses)).toBe(false);
    expect(isMessageId(prt)).toBe(false);

    expect(isPartId(ses)).toBe(false);
    expect(isPartId(msg)).toBe(false);
  });

  it("reject arbitrary strings", () => {
    expect(isSessionId("pentest-agent-1")).toBe(false);
    expect(isMessageId("")).toBe(false);
    expect(isPartId("prt")).toBe(false); // no underscore separator
  });
});
