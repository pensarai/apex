import { open, stat } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

// Output stops at this many characters of numbered content — the reader never
// buffers the whole file to serve a small window.
const OUTPUT_BUDGET_CHARS = 100_000;
// Any returned line longer than this is capped with an explicit marker and the
// read is marked truncated — never a silent 2k evidence loss. The bound is
// independent of chunk/newline boundaries.
const MAX_LINE_CHARS = 2_000;
const READ_CHUNK_BYTES = 64 * 1024;
const MAX_BYTE_WINDOW = 512 * 1024;

const readFileInputSchema = z.object({
  path: z
    .string()
    .describe(
      "Absolute or relative path to the file to read. Must be a file, not a directory.",
    ),
  startLine: z
    .number()
    .optional()
    .describe("1-based line number to start reading from (inclusive)"),
  endLine: z
    .number()
    .optional()
    .describe("1-based line number to stop reading at (inclusive)"),
  byteOffset: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe(
      "Read a raw byte window starting at this 0-based UTF-8 codepoint-aligned offset instead of lines. Use for minified single-line files where line paging cannot split the content.",
    ),
  byteCount: z
    .number()
    .int()
    .min(1)
    .max(MAX_BYTE_WINDOW)
    .optional()
    .describe(
      `Bytes to read from byteOffset (max ${MAX_BYTE_WINDOW}). Requires byteOffset.`,
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Reading nginx config file')",
    ),
});

type ReadFileInput = z.infer<typeof readFileInputSchema>;

export type ReadFileResult = {
  success: boolean;
  error: string;
  content: string;
  path: string;
  totalLines?: number;
  linesReturned?: number;
  /**
   * True when the read did not deliver everything it scanned: the output
   * budget stopped it, or a returned line exceeded MAX_LINE_CHARS and was capped.
   * totalLines is only reported when the scan reached EOF.
   */
  truncated?: boolean;
  /** Line mode: first line NOT emitted — resume at this startLine. */
  stoppedAtLine?: number;
  /** Byte mode: resume cursor — first byte after the last complete codepoint. */
  stoppedAtByte?: number;
  /** Byte mode: bytes actually returned (window may end early at EOF). */
  byteCaptured?: number;
};

export function readFile(ctx: ToolContext) {
  return tool({
    description: `Read the contents of a file from the filesystem. This tool only works on files, NOT directories. To list directory contents, use the list_files tool instead.

You can read the entire file or specify a line range using startLine / endLine
(both 1-based, inclusive). If only startLine is given, reads from that line to
the end. If only endLine is given, reads from the beginning to that line.

Output lines are prefixed with their line number for easy reference. Reads are
bounded: a huge file returns a window plus truncation metadata instead of
buffering the whole file, and lines longer than ${MAX_LINE_CHARS} characters
are capped with an explicit marker (the read is marked truncated — use
byteOffset / byteCount for the dropped bytes). Byte windows must start on a
UTF-8 codepoint boundary and never split one: stoppedAtByte is the exact
resume cursor.`,
    inputSchema: readFileInputSchema,
    execute: async ({
      path,
      startLine,
      endLine,
      byteOffset,
      byteCount,
    }): Promise<ReadFileResult> => {
      const resolved = isAbsolute(path) ? path : resolve(ctx.agentCwd, path);
      if (ctx.abortSignal?.aborted) {
        return {
          success: false,
          error: "Read file aborted by user",
          content: "",
          path,
        };
      }
      const usesBytes = byteOffset !== undefined || byteCount !== undefined;
      if (byteOffset === undefined && byteCount !== undefined) {
        return {
          success: false,
          error: "byteOffset is required with byteCount",
          content: "",
          path,
        };
      }
      if (byteOffset !== undefined && byteCount === undefined) {
        return {
          success: false,
          error: "byteCount is required with byteOffset",
          content: "",
          path,
        };
      }
      if (usesBytes && (startLine !== undefined || endLine !== undefined)) {
        return {
          success: false,
          error:
            "byteOffset/byteCount cannot be combined with startLine/endLine",
          content: "",
          path,
        };
      }
      try {
        // Ordinary-file contract before any read: a FIFO or device would turn
        // the bounded reader back into an unbounded blocking read.
        const stats = await stat(resolved);
        if (!stats.isFile()) {
          return {
            success: false,
            error: `not an ordinary file (directory, FIFO, or device): ${path} — read_file only pages regular files`,
            content: "",
            path,
          };
        }
        if (byteOffset !== undefined && byteCount !== undefined) {
          return await readLocalByteWindow(
            resolved,
            path,
            byteOffset,
            byteCount,
            ctx.abortSignal,
          );
        }
        return await readLocalLines(
          resolved,
          path,
          startLine,
          endLine,
          ctx.abortSignal,
        );
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          content: "",
          path,
        };
      }
    },
  });
}

/**
 * Streams the file in chunks and stops at endLine or the output budget, so a
 * small window of a huge file never buffers the whole file first. One line
 * per \n plus a final (possibly empty) line at EOF — the same count
 * String.split("\n") produces; trailing \r is kept as-is.
 */
async function readLocalLines(
  resolved: string,
  path: string,
  startLine?: number,
  endLine?: number,
  abortSignal?: AbortSignal,
): Promise<ReadFileResult> {
  const start = startLine ? Math.max(1, Math.floor(startLine)) : 1;
  const end = endLine ? Math.floor(endLine) : Number.POSITIVE_INFINITY;

  const handle = await open(resolved, "r");
  try {
    const decoder = new TextDecoder("utf-8", { ignoreBOM: true });
    const numbered: string[] = [];
    let outputChars = 0;
    let lineNo = 0;
    let newlines = 0;
    // Line-assembly state: once a line passes MAX_LINE_CHARS its remainder is
    // discarded (counted), independent of chunk boundaries.
    let lineBuf = "";
    let lineDropped = 0;
    let capping = false;
    let cappedAnyLine = false;
    let stoppedAtLine: number | undefined;
    let hitBudget = false;
    let reachedEof = false;

    const handleLine = (line: string) => {
      lineNo++;
      if (lineNo < start) return "skip" as const;
      if (lineNo > end) {
        stoppedAtLine = lineNo;
        return "stop" as const;
      }
      const numberedLine = `${String(lineNo).padStart(6)}|${line}`;
      if (outputChars + numberedLine.length > OUTPUT_BUDGET_CHARS) {
        hitBudget = true;
        stoppedAtLine = lineNo;
        return "stop" as const;
      }
      numbered.push(numberedLine);
      cappedAnyLine ||= lineDropped > 0;
      outputChars += numberedLine.length + 1;
      if (lineNo === end) {
        // Window satisfied — stop reading immediately instead of parsing the
        // next (possibly huge) line just to discover it is excluded.
        stoppedAtLine = lineNo + 1;
        return "stop" as const;
      }
      return "keep" as const;
    };

    const emitLine = () => {
      const display =
        lineDropped > 0
          ? `${lineBuf}… (+${lineDropped} chars dropped in this line — use byteOffset/byteCount)`
          : lineBuf;
      const outcome = handleLine(display);
      newlines++;
      lineBuf = "";
      lineDropped = 0;
      capping = false;
      return outcome;
    };

    const consume = (text: string): "keep" | "skip" | "stop" => {
      let rest = text;
      while (rest.length > 0) {
        const nl = rest.indexOf("\n");
        const segment = nl === -1 ? rest : rest.slice(0, nl);
        if (!capping && lineBuf.length + segment.length > MAX_LINE_CHARS) {
          const take = MAX_LINE_CHARS - lineBuf.length;
          lineBuf += segment.slice(0, take);
          lineDropped += segment.length - take;
          capping = true;
        } else if (!capping) {
          lineBuf += segment;
        } else {
          lineDropped += segment.length;
        }
        if (nl === -1) return "keep";
        rest = rest.slice(nl + 1);
        if (emitLine() === "stop") return "stop";
      }
      return "keep";
    };

    const buffer = Buffer.allocUnsafe(READ_CHUNK_BYTES);
    let running = true;
    let abortedMidRead = false;
    while (running) {
      if (abortSignal?.aborted) {
        abortedMidRead = true;
        break;
      }
      const { bytesRead } = await handle.read(buffer, 0, READ_CHUNK_BYTES);
      if (bytesRead === 0) break;
      if (
        consume(
          decoder.decode(buffer.subarray(0, bytesRead), { stream: true }),
        ) === "stop"
      ) {
        running = false;
      }
    }
    if (running && !abortedMidRead) {
      const tail = decoder.decode();
      if (tail && consume(tail) === "stop") running = false;
    }
    if (running && !abortedMidRead) {
      // EOF: the final (possibly empty) line, so the count matches
      // split("\n") semantics. A capped fragment is emitted with its marker —
      // same bound as a newline-terminated line.
      const outcome = handleLine(
        lineDropped > 0
          ? `${lineBuf}… (+${lineDropped} chars dropped in this line — use byteOffset/byteCount)`
          : lineBuf,
      );
      // Reaching endLine here also completes the file, unless the output
      // budget prevented this final line from being included.
      reachedEof = outcome !== "stop" || (lineNo === end && !hitBudget);
    }

    const content = numbered.join("\n");
    const result: ReadFileResult = {
      success: !abortedMidRead,
      error: abortedMidRead ? "Read file aborted by user" : "",
      content:
        hitBudget && numbered.length > 0
          ? `${content}\n\n(truncated — use startLine/endLine or byteOffset/byteCount to continue)`
          : content,
      path,
      linesReturned: numbered.length,
    };
    // totalLines is exact only when the scan reached EOF.
    if (reachedEof) {
      result.totalLines = newlines + 1;
    } else {
      result.stoppedAtLine = stoppedAtLine;
    }
    if (hitBudget || cappedAnyLine || abortedMidRead) {
      result.truncated = true;
    }
    return result;
  } finally {
    await handle.close();
  }
}

/**
 * True when the byte is a UTF-8 continuation byte (0b10xxxxxx) — a window
 * starting on one begins mid-codepoint.
 */
function isContinuationByte(byte: number): boolean {
  return (byte & 0xc0) === 0x80;
}

async function readLocalByteWindow(
  resolved: string,
  path: string,
  byteOffset: number,
  byteCount: number,
  abortSignal?: AbortSignal,
): Promise<ReadFileResult> {
  const handle = await open(resolved, "r");
  try {
    if (abortSignal?.aborted) {
      return {
        success: false,
        error: "Read file aborted by user",
        content: "",
        path,
      };
    }
    // Validate the leading boundary before reading — never decode a window
    // that starts mid-codepoint into replacement characters.
    const probe = Buffer.alloc(Math.min(4, byteCount));
    const probeRead = await handle.read(probe, 0, probe.length, byteOffset);
    if (
      probeRead.bytesRead > 0 &&
      isContinuationByte(probe[0]) &&
      byteOffset > 0
    ) {
      return {
        success: false,
        error:
          "byteOffset starts inside a UTF-8 sequence — align it to a codepoint boundary (use a previous page's stoppedAtByte)",
        content: "",
        path,
      };
    }

    const out = Buffer.alloc(byteCount);
    let got = 0;
    while (got < byteCount) {
      if (abortSignal?.aborted) {
        return {
          success: false,
          error: "Read file aborted by user",
          content: "",
          path,
        };
      }
      const { bytesRead } = await handle.read(
        out,
        got,
        byteCount - got,
        byteOffset + got,
      );
      if (bytesRead === 0) break;
      got += bytesRead;
    }

    // A window that filled exactly needs a one-byte probe to distinguish a
    // page split from the file's actual end (a short read already proves EOF).
    let atEof = got < byteCount;
    if (!atEof) {
      const probeBuf = Buffer.alloc(1);
      const probe = await handle.read(probeBuf, 0, 1, byteOffset + got);
      atEof = probe.bytesRead === 0;
    }

    // Streaming decode retains incomplete sequences only at page boundaries;
    // at real EOF the decoder is finalized, so a torn tail fails as invalid
    // UTF-8. BOM bytes stay counted so the cursor stays aligned.
    const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
    let content: string;
    try {
      content = decoder.decode(out.subarray(0, got), { stream: !atEof });
    } catch {
      // Invalid bytes inside the window (not a boundary split): fail
      // explicitly — replacement characters would silently corrupt the
      // evidence while advertising a successful byte retrieval.
      return {
        success: false,
        error:
          "window contains invalid UTF-8 — read_file pages text; use execute_command with a byte-oriented tool (e.g. xxd) for binary ranges",
        content: "",
        path,
      };
    }

    const consumed = Buffer.byteLength(content, "utf-8");
    if (consumed === 0 && got > 0) {
      // The window is too small to hold the next codepoint — say so instead
      // of succeeding with zero progress.
      return {
        success: false,
        error: `byte window of ${got} byte(s) is too small for the next UTF-8 sequence — increase byteCount`,
        content: "",
        path,
      };
    }

    const partial = got - consumed;
    // Every page with progress carries a continuation cursor — including a
    // fully-served aligned window, whose next page starts where this one
    // ended. Only a zero-progress page at EOF has nothing to continue.
    return {
      success: true,
      error: "",
      content,
      path,
      byteCaptured: consumed,
      ...(consumed > 0 ? { stoppedAtByte: byteOffset + consumed } : {}),
      ...(partial > 0 ? { truncated: true } : {}),
    };
  } finally {
    await handle.close();
  }
}
