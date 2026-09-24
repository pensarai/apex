import { execSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { winScriptFromEnv } from "./__tests__/sandboxScript";
import { type ReadFileResult, readFile } from "./readFile";
import type { UnifiedSandbox } from "./sandbox";
import type { ToolContext } from "./types";

// Counts every byte the reader pulls off the disk, so bounded-IO tests can
// prove a small window never reads the whole file. afterRead fires after each
// counted read — the deterministic abort test uses it to stop mid-scan.
const readStats = vi.hoisted(() => ({
  totalBytesRead: 0,
  afterRead: undefined as undefined | ((total: number) => void),
}));
vi.mock("node:fs/promises", async (importOriginal) => {
  const real = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...real,
    open: (async (...args: Parameters<typeof real.open>) => {
      const fh = await real.open(...args);
      return new Proxy(fh, {
        get(target, prop, receiver) {
          const value = Reflect.get(target, prop, receiver);
          if (prop === "read" && typeof value === "function") {
            return async (...callArgs: unknown[]) => {
              const res = await (
                value as (...a: unknown[]) => Promise<{
                  bytesRead: number;
                }>
              ).apply(target, callArgs);
              readStats.totalBytesRead += res.bytesRead;
              readStats.afterRead?.(readStats.totalBytesRead);
              return res;
            };
          }
          return value;
        },
      });
    }) as typeof real.open,
  };
});

function makeCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: ["https://example.com"],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: "/tmp/test",
      logsPath: "/tmp/test/logs",
      findingsPath: "/tmp/test/findings",
      scratchpadPath: "/tmp/test/scratchpad",
      pocsPath: "/tmp/test/pocs",
    } as SessionInfo,
    agentCwd: "/tmp/test",
    target: "https://example.com",
    ...overrides,
  };
}

const scratchDirs: string[] = [];
function scratchDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "apex-readfile-test-"));
  scratchDirs.push(dir);
  return dir;
}

type ReadFileCall = Parameters<
  NonNullable<ReturnType<typeof readFile>["execute"]>
>[0];

async function runRead(
  ctx: ToolContext,
  input: ReadFileCall,
): Promise<ReadFileResult> {
  return (await readFile(ctx).execute?.(input, {
    toolCallId: "tc_test",
    messages: [],
    abortSignal: ctx.abortSignal,
  })) as ReadFileResult;
}

beforeEach(() => {
  readStats.totalBytesRead = 0;
  readStats.afterRead = undefined;
});

afterEach(() => {
  for (const dir of scratchDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("readFile healthy paths", () => {
  it("returns the numbered format with split-semantics line counts", async () => {
    const dir = scratchDir();
    const file = join(dir, "notes.txt");
    writeFileSync(file, "alpha\nbeta\ngamma\n");

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "notes.txt",
      toolCallDescription: "read all",
    });

    // Trailing newline contributes the final empty line, as split("\n") does.
    expect(result).toMatchObject({
      success: true,
      error: "",
      totalLines: 4,
      linesReturned: 4,
    });
    expect(result.content).toBe(
      "     1|alpha\n     2|beta\n     3|gamma\n     4|",
    );
    expect(result.truncated).toBeUndefined();
  });

  it("serves a startLine/endLine window without reading the rest", async () => {
    const dir = scratchDir();
    const file = join(dir, "lines.txt");
    writeFileSync(file, "one\ntwo\nthree\nfour\nfive\n");

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "lines.txt",
      startLine: 2,
      endLine: 3,
      toolCallDescription: "window read",
    });

    expect(result.content).toBe("     2|two\n     3|three");
    expect(result.linesReturned).toBe(2);
    // Window satisfied: resume cursor is the first line NOT emitted.
    expect(result.stoppedAtLine).toBe(4);
    expect(result.truncated).toBeUndefined();
    expect(result.totalLines).toBeUndefined();
  });

  it.each([
    "one\ntwo",
    "one\ntwo\n",
    "",
  ])("reports completion when endLine is the last split-line of %j", async (body) => {
    const dir = scratchDir();
    writeFileSync(join(dir, "final-page.txt"), body);
    const lines = body.split("\n");
    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "final-page.txt",
      endLine: lines.length,
      toolCallDescription: "read through the final line",
    });

    expect(result.success).toBe(true);
    expect(result.content).toBe(
      lines.map((line, i) => `${String(i + 1).padStart(6)}|${line}`).join("\n"),
    );
    expect(result.totalLines).toBe(lines.length);
    expect(result.linesReturned).toBe(lines.length);
    expect(result.stoppedAtLine).toBeUndefined();
    expect(result.truncated).toBeUndefined();
  });

  it.each([
    ["valid UTF-8", Buffer.from("alpha"), "alpha"],
    ["invalid UTF-8", Buffer.from([0x61, 0xff, 0x62]), "a\uFFFDb"],
  ])("preserves a leading BOM in line mode with %s", async (_label, body, expected) => {
    const dir = scratchDir();
    writeFileSync(
      join(dir, "bom-lines.txt"),
      Buffer.concat([Buffer.from("\uFEFF"), body]),
    );

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "bom-lines.txt",
      toolCallDescription: "read BOM-prefixed text",
    });

    expect(result).toMatchObject({
      success: true,
      error: "",
      content: `     1|\uFEFF${expected}`,
      totalLines: 1,
      linesReturned: 1,
    });
    expect(result.truncated).toBeUndefined();
  });
});

describe("readFile bounded streaming", () => {
  it("a small page of a huge file never reads the whole file", async () => {
    const dir = scratchDir();
    const file = join(dir, "huge.txt");
    // 40 MiB: line 1-2 short, then a massive remainder.
    writeFileSync(file, "first\nsecond\n");
    const bigLine = `${"x".repeat(1024)}\n`;
    const chunk = bigLine.repeat(1024); // ~1 MiB per write
    for (let i = 0; i < 40; i++) writeFileSync(file, chunk, { flag: "a" });

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "huge.txt",
      startLine: 1,
      endLine: 2,
      toolCallDescription: "page 1-2 of a huge file",
    });

    expect(result.content).toBe("     1|first\n     2|second");
    expect(result.stoppedAtLine).toBe(3);
    // The reader stopped after the chunks that carried lines 1-2 — nowhere
    // near the 40 MiB on disk.
    expect(readStats.totalBytesRead).toBeLessThanOrEqual(256 * 1024);
  }, 20_000);

  it("roundtrip pagination: endLine cursor then startLine continuation", async () => {
    const dir = scratchDir();
    const file = join(dir, "pager.txt");
    writeFileSync(file, "l1\nl2\nl3\nl4\nl5\nl6\n");

    const ctx = makeCtx({ agentCwd: dir });
    const page1 = await runRead(ctx, {
      path: "pager.txt",
      endLine: 4,
      toolCallDescription: "page one",
    });
    expect(page1.stoppedAtLine).toBe(5);

    const page2 = await runRead(ctx, {
      path: "pager.txt",
      startLine: page1.stoppedAtLine,
      toolCallDescription: "page two",
    });

    // Concatenated pages cover every line exactly once — no skips, no dups.
    expect(`${page1.content}\n${page2.content}`).toBe(
      "     1|l1\n     2|l2\n     3|l3\n     4|l4\n     5|l5\n     6|l6\n     7|",
    );
    expect(page2.totalLines).toBe(7);
  });

  it("keeps a continuation when the output budget excludes the final line", async () => {
    const dir = scratchDir();
    writeFileSync(
      join(dir, "budget.txt"),
      Array(50).fill("x".repeat(2_000)).join("\n"),
    );
    const ctx = makeCtx({ agentCwd: dir });
    const page1 = await runRead(ctx, {
      path: "budget.txt",
      endLine: 50,
      toolCallDescription: "read a window exceeding the output budget",
    });

    expect(page1.success).toBe(true);
    expect(page1.linesReturned).toBe(49);
    expect(page1.stoppedAtLine).toBe(50);
    expect(page1.totalLines).toBeUndefined();
    expect(page1.truncated).toBe(true);

    const page2 = await runRead(ctx, {
      path: "budget.txt",
      startLine: page1.stoppedAtLine,
      endLine: 50,
      toolCallDescription: "read the remaining final line",
    });
    expect(page2.content).toBe(`    50|${"x".repeat(2_000)}`);
    expect(page2.totalLines).toBe(50);
    expect(page2.stoppedAtLine).toBeUndefined();
    expect(page2.truncated).toBeUndefined();
  });

  it("stops at endLine immediately instead of parsing the next huge line", async () => {
    const dir = scratchDir();
    const file = join(dir, "slow-next-line.txt");
    // Line 2 is 5 MiB: an eager reader would pull it all to exclude it.
    writeFileSync(file, "line-one\n");
    writeFileSync(file, `${"y".repeat(5 * 1024 * 1024)}\n`, { flag: "a" });

    const started = Date.now();
    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "slow-next-line.txt",
      endLine: 1,
      toolCallDescription: "endLine 1 with a huge second line",
    });

    expect(result.content).toBe("     1|line-one");
    expect(readStats.totalBytesRead).toBeLessThanOrEqual(128 * 1024);
    expect(Date.now() - started).toBeLessThan(2_000);
  }, 10_000);
});

describe("readFile single-line bounds", () => {
  it.each([
    ["at EOF", undefined, "     2|second\n     3|third", 3, undefined],
    ["at endLine", 2, "     2|second", undefined, 3],
  ])("does not flag complete pages %s when a skipped line was capped", async (_label, endLine, content, totalLines, stoppedAtLine) => {
    const dir = scratchDir();
    writeFileSync(
      join(dir, "skipped-long-line.txt"),
      `${"x".repeat(128 * 1024)}\nsecond\nthird`,
    );

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "skipped-long-line.txt",
      startLine: 2,
      endLine,
      toolCallDescription: "read after a long line",
    });

    expect(result.success).toBe(true);
    expect(result.content).toBe(content);
    expect(result.totalLines).toBe(totalLines);
    expect(result.stoppedAtLine).toBe(stoppedAtLine);
    expect(result.truncated).toBeUndefined();
  });

  it.each([
    ["with a trailing newline", `${"A".repeat(20_000)}\n`],
    ["without a trailing newline", "A".repeat(20_000)],
  ])("a 20k-char single line %s is capped consistently and flagged truncated", async (_label, fileBody) => {
    const dir = scratchDir();
    const file = join(dir, "single.txt");
    writeFileSync(file, fileBody);

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "single.txt",
      toolCallDescription: "huge single line",
    });

    expect(result.content).toContain("A".repeat(2_000));
    expect(result.content).toMatch(/\(\+18,?000 chars dropped in this line/);
    // Never silent: the read is marked truncated either way.
    expect(result.truncated).toBe(true);
  });

  it("caps a line that spans chunk boundaries without splicing prefix and tail", async () => {
    const dir = scratchDir();
    const file = join(dir, "chunky.txt");
    // 200k chars on one line — several 64k read chunks, capped at 2k.
    writeFileSync(file, `${"B".repeat(200_000)}\n`);

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "chunky.txt",
      toolCallDescription: "multi-chunk single line",
    });

    const emitted = result.content.split("|")[1] ?? "";
    // The kept prefix is the line's FIRST 2000 chars — not prefix+tail spliced.
    expect(emitted.startsWith("B".repeat(2_000))).toBe(true);
    expect(emitted).not.toContain("…(+0");
    expect(result.truncated).toBe(true);
    expect(result.content).toMatch(/chars dropped in this line/);
  });
});

describe("readFile byte windows", () => {
  const MULTIBYTE = "aé€😀ok\nsecond €line\n";

  it("returns an exact aligned window with byteCaptured", async () => {
    const dir = scratchDir();
    const file = join(dir, "bytes.txt");
    writeFileSync(file, MULTIBYTE);

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "bytes.txt",
      byteOffset: 0,
      byteCount: 4,
      toolCallDescription: "aligned window",
    });

    // 'a' (1 byte) + 'é' (2 bytes) = 3 decoded bytes; the 4th byte starts
    // the '€' sequence and is held back by the streaming decoder.
    expect(result.content).toBe("aé");
    expect(result.byteCaptured).toBe(3);
    expect(result.stoppedAtByte).toBe(3);
    expect(result.truncated).toBe(true);
  });

  it("counts a UTF-8 BOM as bytes, at the start and across a window boundary", async () => {
    const dir = scratchDir();
    const file = join(dir, "bom.txt");
    const bomBody = "\uFEFFalpha";
    writeFileSync(file, bomBody);

    const ctx = makeCtx({ agentCwd: dir });
    // Window 1: the 3 BOM bytes plus 'a' — the BOM must survive decoding so
    // its bytes stay counted and the cursor stays aligned.
    const page1 = await runRead(ctx, {
      path: "bom.txt",
      byteOffset: 0,
      byteCount: 4,
      toolCallDescription: "BOM start window",
    });
    expect(page1.content).toBe("\uFEFFa");
    expect(page1.byteCaptured).toBe(4);
    expect(page1.stoppedAtByte).toBe(4);

    // Window 2 begins inside the body: reconstruction stays exact.
    if (page1.stoppedAtByte === undefined) throw new Error("missing cursor");
    const page2 = await runRead(ctx, {
      path: "bom.txt",
      byteOffset: page1.stoppedAtByte,
      byteCount: 64,
      toolCallDescription: "BOM follow-on window",
    });
    expect(`${page1.content}${page2.content}`).toBe(bomBody);
    expect(page2.truncated).toBeUndefined();
  });

  it("multibyte roundtrip: chained stoppedAtByte pages reconstruct the original", async () => {
    const dir = scratchDir();
    const file = join(dir, "roundtrip.txt");
    writeFileSync(file, MULTIBYTE);

    const ctx = makeCtx({ agentCwd: dir });
    // A deliberately tiny page that lands on a multibyte start gets the
    // too-small error — retry with a size that fits the next codepoint.
    const readPage = async (offset: number, size: number) => {
      let page = await runRead(ctx, {
        path: "roundtrip.txt",
        byteOffset: offset,
        byteCount: size,
        toolCallDescription: "roundtrip page",
      });
      if (!page.success && page.error.includes("too small")) {
        page = await runRead(ctx, {
          path: "roundtrip.txt",
          byteOffset: offset,
          byteCount: 4,
          toolCallDescription: "roundtrip page (widened)",
        });
      }
      return page;
    };

    let offset = 0;
    let reassembled = "";
    for (let i = 0; i < 60; i++) {
      // Page sizes that deliberately split 2/3/4-byte sequences.
      const page = await readPage(offset, (i % 4) + 1);
      expect(page.success).toBe(true);
      reassembled += page.content;
      if (page.stoppedAtByte === undefined) break;
      offset = page.stoppedAtByte;
    }

    expect(reassembled).toBe(MULTIBYTE);
  });

  it("a window too small for the next codepoint fails explicitly, never zero-progress", async () => {
    const dir = scratchDir();
    const file = join(dir, "emdash.txt");
    writeFileSync(file, "— dash");

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "emdash.txt",
      byteOffset: 0,
      byteCount: 2, // inside the 3-byte em dash
      toolCallDescription: "tiny window",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("too small");
    expect(result.content).toBe("");
  });

  it("fails explicitly on invalid UTF-8 inside the window — no lossy fallback", async () => {
    const dir = scratchDir();
    const file = join(dir, "invalid.txt");
    // Valid text, then a lone 0xFF (never valid in UTF-8), then more text.
    writeFileSync(
      file,
      Buffer.concat([
        Buffer.from("ok-"),
        Buffer.from([0xff]),
        Buffer.from("-tail"),
      ]),
    );

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "invalid.txt",
      byteOffset: 0,
      byteCount: 16,
      toolCallDescription: "invalid sequence window",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("invalid UTF-8");
    // Never a successful retrieval with replacement characters.
    expect(result.content).toBe("");
  });

  it("rejects a mid-codepoint leading offset", async () => {
    const dir = scratchDir();
    const file = join(dir, "emdash2.txt");
    writeFileSync(file, "— dash");

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "emdash2.txt",
      byteOffset: 1, // second byte of the em dash
      byteCount: 8,
      toolCallDescription: "misaligned offset",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("codepoint boundary");
  });

  it("a short final page at EOF is completion, not truncation", async () => {
    const dir = scratchDir();
    const file = join(dir, "short.txt");
    writeFileSync(file, "tail");

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "short.txt",
      byteOffset: 1,
      byteCount: 64,
      toolCallDescription: "final page past EOF",
    });

    expect(result.success).toBe(true);
    expect(result.error).toBe("");
    expect(result.truncated).toBeUndefined();
    expect(result.byteCaptured).toBe(3);
  });

  it("validates byteCount-without-byteOffset and line/byte conflicts", async () => {
    const ctx = makeCtx();
    const missingOffset = await runRead(ctx, {
      path: "whatever",
      byteCount: 16,
      toolCallDescription: "byteCount without offset",
    });
    expect(missingOffset.success).toBe(false);
    expect(missingOffset.error).toContain("byteOffset is required");

    const missingCount = await runRead(ctx, {
      path: "whatever",
      byteOffset: 0,
      toolCallDescription: "byteOffset without count",
    });
    expect(missingCount.success).toBe(false);
    expect(missingCount.error).toContain("byteCount is required");

    const dir = scratchDir();
    writeFileSync(join(dir, "f.txt"), "x");
    const conflict = await runRead(makeCtx({ agentCwd: dir }), {
      path: "f.txt",
      byteOffset: 0,
      byteCount: 4,
      startLine: 1,
      toolCallDescription: "conflicting modes",
    });
    expect(conflict.success).toBe(false);
    expect(conflict.error).toContain("cannot be combined");
  });
});

describe("readFile file-kind and abort handling", () => {
  it("rejects directories with the ordinary-file contract", async () => {
    const dir = scratchDir();
    mkdirSync(join(dir, "sub"));

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "sub",
      toolCallDescription: "directory read",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("not an ordinary file");
  });

  it("rejects a named pipe instead of blocking on an unbounded read", async () => {
    const dir = scratchDir();
    const fifo = join(dir, "pipe.fifo");
    execSync(`mkfifo '${fifo}'`);

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "pipe.fifo",
      toolCallDescription: "fifo read",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("not an ordinary file");
  }, 5_000);

  it("returns an aborted result without touching the file when pre-aborted", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "a.txt"), "data");
    const ac = new AbortController();
    ac.abort();

    const result = await runRead(
      makeCtx({ agentCwd: dir, abortSignal: ac.signal }),
      {
        path: "a.txt",
        toolCallDescription: "pre-aborted read",
      },
    );

    expect(result).toMatchObject({
      success: false,
      error: "Read file aborted by user",
      content: "",
    });
    expect(readStats.totalBytesRead).toBe(0);
  });

  it("cancels between bounded reads after exactly one chunk", async () => {
    const dir = scratchDir();
    const file = join(dir, "two-chunks.txt");
    // 128 KiB = exactly two 64 KiB reads; the abort lands after the first.
    writeFileSync(file, `${"z".repeat(1023)}\n`.repeat(128));

    const ac = new AbortController();
    readStats.afterRead = (total) => {
      if (total >= 64 * 1024) ac.abort();
    };
    const result = await runRead(
      makeCtx({ agentCwd: dir, abortSignal: ac.signal }),
      {
        path: "two-chunks.txt",
        toolCallDescription: "abort after the first chunk",
      },
    );

    expect(result.success).toBe(false);
    expect(result.error).toBe("Read file aborted by user");
    expect(result.truncated).toBe(true);
    // Exactly one bounded read happened before the cancellation check fired.
    expect(readStats.totalBytesRead).toBe(64 * 1024);
  }, 10_000);
});

// EOF semantics for byte windows: an incomplete trailing multibyte sequence
// at REAL EOF is invalid UTF-8, not a page split — finalizing the decoder
// must fail it with the binary-tool guidance instead of a continuation
// cursor that asks for more bytes forever.
describe("readFile byte-window EOF semantics", () => {
  // "ok-" (6f 6b 2d) + the first two bytes of a 3-byte sequence (e2 82) that
  // the file never completes.
  const tornTail = Buffer.concat([
    Buffer.from("ok-"),
    Buffer.from([0xe2, 0x82]),
  ]);

  it("fails an incomplete trailing sequence at EOF (read returned 0)", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "torn.txt"), tornTail);

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "torn.txt",
      byteOffset: 0,
      byteCount: 64,
      toolCallDescription: "window past the torn tail",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("invalid UTF-8");
    expect(result.error).toContain("xxd");
    expect(result.stoppedAtByte).toBeUndefined();
  });

  it("detects EOF when the window ends exactly at the file size", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "torn-exact.txt"), tornTail);

    // byteCount == remaining file size: the read loop fills the window and
    // never observes a 0-byte read — a bounded probe must still see EOF.
    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "torn-exact.txt",
      byteOffset: 0,
      byteCount: tornTail.length,
      toolCallDescription: "window exactly the file size",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("invalid UTF-8");
    expect(result.stoppedAtByte).toBeUndefined();
  });

  it("a continuation page at the torn cursor fails instead of looping forever", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "torn-cursor.txt"), tornTail);

    // The torn sequence starts at byte 3; a follow-up page from there must
    // report invalid UTF-8 at EOF, never the "increase byteCount" guidance
    // that can never succeed.
    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "torn-cursor.txt",
      byteOffset: 3,
      byteCount: 524_288,
      toolCallDescription: "continuation at the torn cursor",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("invalid UTF-8");
    expect(result.error).not.toContain("increase byteCount");
  });

  it("a complete multibyte at EOF is not truncated (clean finalization)", async () => {
    const dir = scratchDir();
    const cleanTail = Buffer.from("ok-😀");
    writeFileSync(join(dir, "clean-tail.txt"), cleanTail);

    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "clean-tail.txt",
      byteOffset: 0,
      byteCount: 64,
      toolCallDescription: "window over a clean tail",
    });

    expect(result.success).toBe(true);
    expect(result.content).toBe("ok-😀");
    expect(result.byteCaptured).toBe(cleanTail.length);
    expect(result.truncated).toBeUndefined();
  });

  it("a valid sequence split across pages keeps its cursor (page split, not EOF)", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "split.txt"), "a😀b");

    const ctx = makeCtx({ agentCwd: dir });
    const page1 = await runRead(ctx, {
      path: "split.txt",
      byteOffset: 0,
      byteCount: 2,
      toolCallDescription: "page splitting a multibyte",
    });
    expect(page1.success).toBe(true);
    expect(page1.content).toBe("a");
    expect(page1.stoppedAtByte).toBe(1);
    expect(page1.truncated).toBe(true);

    const page2 = await runRead(ctx, {
      path: "split.txt",
      byteOffset: page1.stoppedAtByte,
      byteCount: 10,
      toolCallDescription: "follow-up page completing the multibyte",
    });
    expect(page2.success).toBe(true);
    expect(`${page1.content}${page2.content}`).toBe("a😀b");
    expect(page2.truncated).toBeUndefined();
  });

  it("a window smaller than a split BOM still asks for a bigger window (page split)", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "bom-split.txt"), "\uFEFFalpha");

    // Only the first 2 of the BOM's 3 bytes fit: this is a page split (the
    // file continues), so the too-small guidance is correct here.
    const result = await runRead(makeCtx({ agentCwd: dir }), {
      path: "bom-split.txt",
      byteOffset: 0,
      byteCount: 2,
      toolCallDescription: "window splitting the BOM",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("increase byteCount");
  });
});

// Sandbox reads run the real transport scripts (bash executes the actual
// pipeline; the resolve round trip runs the real remote helper), so these
// tests exercise the commands that ship, not their expected outputs.
describe("readFile sandbox routing (linux, real execution)", () => {
  it("offers byte paging when a remote line exceeds the bounded window", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "minified.js"), "a".repeat(200_000));
    const result = await runRead(
      makeCtx({ agentCwd: dir, sandbox: realLinuxSandbox() }),
      {
        path: "minified.js",
        toolCallDescription: "inspect a large single line",
      },
    );
    expect(result.success).toBe(false);
    expect(result.truncated).toBe(true);
    expect(result.error).toContain("byteOffset/byteCount");
    expect(result.content).toContain("1|aaa");
    expect(result.content.length).toBeLessThan(5_000);
    expect(result.stoppedAtLine).toBeUndefined();
  });

  function realLinuxSandbox(): UnifiedSandbox {
    return {
      type: "linux",
      execute: async (command, opts) => {
        const res = spawnSync("bash", ["-c", command], {
          encoding: "utf8",
          timeout: 35_000,
          env: { ...process.env, ...opts?.envVars },
        });
        return {
          stdout: res.stdout ?? "",
          stderr: res.stderr ?? "",
          exitCode: res.status ?? 1,
          success: res.status === 0,
        };
      },
    };
  }

  it("line-mode sandbox read matches the local reader exactly", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "notes.txt"), "alpha\nbeta\ngamma\n");

    const local = await runRead(makeCtx({ agentCwd: dir }), {
      path: "notes.txt",
      toolCallDescription: "local baseline",
    });
    const remote = await runRead(
      makeCtx({ agentCwd: dir, sandbox: realLinuxSandbox() }),
      {
        path: "notes.txt",
        toolCallDescription: "sandbox read",
      },
    );

    expect(remote).toEqual(local);
    expect(local.content).toBe(
      "     1|alpha\n     2|beta\n     3|gamma\n     4|",
    );
  });

  it("sandbox window reads carry the local resume cursors", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "lines.txt"), "one\ntwo\nthree\nfour\nfive\n");

    const page = await runRead(
      makeCtx({ agentCwd: dir, sandbox: realLinuxSandbox() }),
      {
        path: "lines.txt",
        startLine: 2,
        endLine: 3,
        toolCallDescription: "sandbox window read",
      },
    );

    expect(page.content).toBe("     2|two\n     3|three");
    expect(page.stoppedAtLine).toBe(4);
    expect(page.totalLines).toBeUndefined();
    expect(page.truncated).toBeUndefined();
  });

  it("sandbox byte windows roundtrip multibyte content via stoppedAtByte", async () => {
    const dir = scratchDir();
    const body = "aé€😀ok\nsecond €line\n";
    writeFileSync(join(dir, "bytes.txt"), body);

    const ctx = makeCtx({
      agentCwd: dir,
      sandbox: realLinuxSandbox(),
    });
    let offset = 0;
    let reassembled = "";
    for (let i = 0; i < 60; i++) {
      const page = await runRead(ctx, {
        path: "bytes.txt",
        byteOffset: offset,
        byteCount: (i % 4) + 1,
        toolCallDescription: "sandbox byte page",
      });
      if (!page.success && page.error.includes("too small")) {
        const widened = await runRead(ctx, {
          path: "bytes.txt",
          byteOffset: offset,
          byteCount: 4,
          toolCallDescription: "sandbox byte page (widened)",
        });
        if (!widened.success) throw new Error(widened.error);
        reassembled += widened.content;
        if (widened.stoppedAtByte === undefined) break;
        offset = widened.stoppedAtByte;
        continue;
      }
      expect(page.success).toBe(true);
      reassembled += page.content;
      if (page.stoppedAtByte === undefined) break;
      offset = page.stoppedAtByte;
    }

    expect(reassembled).toBe(body);
  });

  it("a full-window sandbox read at EOF reports completion, not truncation", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "exact.txt"), "ok-😀");

    const result = await runRead(
      makeCtx({ agentCwd: dir, sandbox: realLinuxSandbox() }),
      {
        path: "exact.txt",
        byteOffset: 0,
        byteCount: 7,
        toolCallDescription: "exact-size sandbox window",
      },
    );

    expect(result.success).toBe(true);
    expect(result.content).toBe("ok-😀");
    expect(result.truncated).toBeUndefined();
    expect(result.stoppedAtByte).toBe(7);
  });

  it.each([
    ["missing file", "absent.txt", /sandbox read failed/],
    ["directory", "sub", /not an ordinary file/],
  ])("sandbox read of a %s fails explicitly", async (_label, target, pattern) => {
    const dir = scratchDir();
    mkdirSync(join(dir, "sub"));

    const result = await runRead(
      makeCtx({ agentCwd: dir, sandbox: realLinuxSandbox() }),
      {
        path: target,
        toolCallDescription: `sandbox ${_label}`,
      },
    );

    expect(result.success).toBe(false);
    expect(result.error).toMatch(pattern);
    expect(result.content).toBe("");
  });

  it("sandbox reads honor fileWorkspaceRoot confinement", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "inside.txt"), "ok\n");

    const ctx = makeCtx({
      agentCwd: dir,
      fileWorkspaceRoot: dir,
      sandbox: realLinuxSandbox(),
    });
    const inside = await runRead(ctx, {
      path: "inside.txt",
      toolCallDescription: "read inside the workspace",
    });
    expect(inside.success).toBe(true);
    expect(inside.content).toBe("     1|ok\n     2|");

    const outside = await runRead(ctx, {
      path: "../outside.txt",
      toolCallDescription: "read outside the workspace",
    });
    expect(outside.success).toBe(false);
    expect(outside.error).toMatch(/escapes/i);
  });

  it("a pre-aborted sandbox read fails before any remote call", async () => {
    const dir = scratchDir();
    writeFileSync(join(dir, "a.txt"), "data");
    const ac = new AbortController();
    ac.abort();
    let calls = 0;
    const sandbox: UnifiedSandbox = {
      type: "linux",
      execute: async () => {
        calls++;
        return { stdout: "", stderr: "", exitCode: 0, success: true };
      },
    };

    const result = await runRead(
      makeCtx({ agentCwd: dir, sandbox, abortSignal: ac.signal }),
      {
        path: "a.txt",
        toolCallDescription: "pre-aborted sandbox read",
      },
    );

    expect(result.error).toBe("Read file aborted by user");
    expect(calls).toBe(0);
  });
});

// Windows sandbox: no local PowerShell exists on this host, so these pin the
// transport SHAPE — static command, env-only data, marker protocol — while the
// real cmd.exe execution is covered by the shared remote-helper suite.
describe("readFile sandbox transport shape (windows)", () => {
  function windowsSandbox(
    onRead: (envVars: Record<string, string>) => string,
  ): {
    sandbox: UnifiedSandbox;
    calls: { command: string; envVars?: Record<string, string> }[];
  } {
    const calls: { command: string; envVars?: Record<string, string> }[] = [];
    return {
      calls,
      sandbox: {
        type: "windows",
        execute: async (command, opts) => {
          calls.push({ command, envVars: opts?.envVars });
          if (opts?.envVars?.APEX_FILE_SCRIPT !== undefined) {
            return {
              stdout: JSON.stringify({ ok: true, path: "C:\\w\\f.txt" }),
              stderr: "",
              exitCode: 0,
              success: true,
            };
          }
          return {
            stdout: onRead(opts?.envVars ?? {}),
            stderr: "",
            exitCode: 0,
            success: true,
          };
        },
      },
    };
  }

  it("byte windows use a static command with env-only data and decode the payload", async () => {
    const { sandbox, calls } = windowsSandbox(() =>
      Buffer.from("hello", "utf8").toString("base64"),
    );

    const result = await runRead(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      path: "f.txt",
      byteOffset: 0,
      byteCount: 16,
      toolCallDescription: "windows byte window",
    });

    const readCall = calls[calls.length - 1];
    const command = readCall.command;
    expect(command).toMatch(
      /^powershell -NoProfile -NonInteractive -EncodedCommand [A-Za-z0-9+/=]+$/,
    );
    // The bootstrap is fixed and short — far under cmd.exe's 8191 limit.
    expect(command.length).toBeLessThan(1000);
    expect(readCall.command).not.toContain("f.txt");
    expect(readCall.envVars?.APEX_READ_PATH).toBe("C:\\w\\f.txt");
    expect(readCall.envVars?.APEX_READ_OFFSET).toBe("0");
    expect(readCall.envVars?.APEX_READ_COUNT).toBe("17");
    const script = winScriptFromEnv(readCall.envVars);
    expect(script).toContain("[Console]::OutputEncoding");
    expect(script).not.toContain("C:\\w\\f.txt");

    expect(result.success).toBe(true);
    expect(result.content).toBe("hello");
    expect(result.truncated).toBeUndefined();
  });

  it("the read command is identical across different windows and paths", async () => {
    const { sandbox, calls } = windowsSandbox(() =>
      Buffer.from("hi", "utf8").toString("base64"),
    );
    const ctx = makeCtx({ agentCwd: "C:\\w", sandbox });
    await runRead(ctx, {
      path: "a.txt",
      byteOffset: 0,
      byteCount: 8,
      toolCallDescription: "first window",
    });
    await runRead(ctx, {
      path: "b.txt",
      byteOffset: 99,
      byteCount: 12,
      toolCallDescription: "second window",
    });

    const readCalls = calls.filter((c) => c.envVars?.APEX_WIN_SCRIPT_COUNT);
    expect(readCalls).toHaveLength(2);
    expect(readCalls[0]?.command).toBe(readCalls[1]?.command);
  });

  it("line reads parse the APEXRL completion marker", async () => {
    const { sandbox } = windowsSandbox(
      () =>
        `${Buffer.from("alpha\nbeta\n", "utf8").toString("base64")}\nAPEXRL total=2`,
    );

    const result = await runRead(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      path: "f.txt",
      toolCallDescription: "windows line read",
    });

    expect(result.success).toBe(true);
    expect(result.content).toBe("     1|alpha\n     2|beta\n     3|");
    expect(result.totalLines).toBe(3);
    expect(result.truncated).toBeUndefined();
  });

  it("line reads parse the APEXRL cut marker as truncation with a cursor", async () => {
    const { sandbox } = windowsSandbox(
      () =>
        `${Buffer.from("alpha\n", "utf8").toString("base64")}\nAPEXRL cut=1`,
    );

    const result = await runRead(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      path: "f.txt",
      toolCallDescription: "windows cut line read",
    });

    expect(result.success).toBe(true);
    expect(result.content).toBe("     1|alpha");
    expect(result.stoppedAtLine).toBe(2);
    expect(result.truncated).toBe(true);
  });

  it("a missing APEXRL marker fails explicitly", async () => {
    const { sandbox } = windowsSandbox(() =>
      Buffer.from("orphan", "utf8").toString("base64"),
    );

    const result = await runRead(makeCtx({ agentCwd: "C:\\w", sandbox }), {
      path: "f.txt",
      toolCallDescription: "windows markerless read",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("APEXRL");
  });
});
