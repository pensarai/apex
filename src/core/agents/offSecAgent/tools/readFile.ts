import { open, stat } from "node:fs/promises";
import { tool } from "ai";
import { z } from "zod";
import { resolveFilePath } from "./fileWorkspace";
import type { SandboxExecutionResult, UnifiedSandbox } from "./sandbox";
import {
  SANDBOX_OP_TIMEOUT_SECONDS,
  sandboxOpError,
  WIN_SCRIPT_COMMAND,
  WIN_SCRIPT_PRELUDE,
  winScriptEnv,
} from "./sandboxScript";
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
    .nullish()
    .describe(
      "1-based start line (inclusive). Omit or set null for byte mode or the beginning of the file.",
    ),
  endLine: z
    .number()
    .nullish()
    .describe(
      "1-based end line (inclusive). Omit or set null for byte mode or the end of the file.",
    ),
  byteOffset: z
    .number()
    .int()
    .min(0)
    .nullish()
    .describe(
      "0-based UTF-8 codepoint-aligned byte offset, paired with byteCount. Omit or set null for line reads. Use byte mode for minified single-line files; startLine and endLine must be omitted or null.",
    ),
  byteCount: z
    .number()
    .int()
    .min(1)
    .max(MAX_BYTE_WINDOW)
    .nullish()
    .describe(
      `Bytes to read from byteOffset (max ${MAX_BYTE_WINDOW}). Requires byteOffset. Omit or set null for line reads.`,
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
Choose one paging mode: omit or set byteOffset and byteCount to null for line
reads; omit or set startLine and endLine to null for byte reads. Never fill
inactive fields with placeholder numbers. Omit or set all four to null to
read from the beginning using the default bounded line reader.

Output lines are prefixed with their line number for easy reference. Reads are
bounded: a huge file returns a window plus truncation metadata instead of
buffering the whole file, and lines longer than ${MAX_LINE_CHARS} characters
are capped with an explicit marker (the read is marked truncated — use
byteOffset / byteCount for the dropped bytes). Byte windows must start on a
UTF-8 codepoint boundary and never split one: stoppedAtByte is the exact
resume cursor.`,
    inputSchema: readFileInputSchema,
    execute: async (input): Promise<ReadFileResult> => {
      const { path } = input;
      // Strict providers require every field; null represents an unused bound.
      const startLine = input.startLine ?? undefined;
      const endLine = input.endLine ?? undefined;
      const byteOffset = input.byteOffset ?? undefined;
      const byteCount = input.byteCount ?? undefined;
      if (ctx.abortSignal?.aborted) {
        return {
          success: false,
          error: "Read file aborted by user",
          content: "",
          path,
        };
      }
      let resolved: string;
      try {
        resolved = await resolveFilePath(ctx, path);
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
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
            "byteOffset/byteCount cannot be combined with startLine/endLine. For line reads, omit byteOffset and byteCount or set both to null. For byte reads, omit startLine and endLine or set both to null.",
          content: "",
          path,
        };
      }
      try {
        // Sandbox agents' files live inside the sandbox: fetch bounded bytes
        // remotely instead of touching the host filesystem.
        if (ctx.sandbox) {
          return await readSandboxFile(ctx, resolved, {
            path,
            startLine,
            endLine,
            byteOffset,
            byteCount,
          });
        }
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

/**
 * Decodes a fetched byte window (local read or sandbox fetch) into a result:
 * boundary alignment, fatal decode, exact byte cursors. `raw` may carry one
 * probe byte past byteCount (sandbox EOF detection) — it is trimmed here.
 */
function decodeByteWindow(
  raw: Buffer,
  byteOffset: number,
  byteCount: number,
  path: string,
  atEof: boolean,
): ReadFileResult {
  // Never decode a window that starts mid-codepoint into replacement chars.
  if (raw.length > 0 && isContinuationByte(raw[0]) && byteOffset > 0) {
    return {
      success: false,
      error:
        "byteOffset starts inside a UTF-8 sequence — align it to a codepoint boundary (use a previous page's stoppedAtByte)",
      content: "",
      path,
    };
  }
  const got = Math.min(raw.length, byteCount);

  // Streaming decode retains incomplete sequences only at page boundaries;
  // at real EOF the decoder is finalized, so a torn tail fails as invalid
  // UTF-8. BOM bytes stay counted so the cursor stays aligned.
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  let content: string;
  try {
    content = decoder.decode(raw.subarray(0, got), { stream: !atEof });
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

    return decodeByteWindow(
      out.subarray(0, got),
      byteOffset,
      byteCount,
      path,
      atEof,
    );
  } finally {
    await handle.close();
  }
}

// --- Sandbox reads ---------------------------------------------------------
//
// A sandboxed agent's files live inside the sandbox, so reads route through
// sandbox.execute and never touch the host filesystem. Raw bytes travel as
// base64 so the adapter's text-only stdout cannot mangle them, then the same
// decoders as local reads produce identical results and cursors.
//
// Transport follows the remote file-operation conventions: the fixed helper
// script arrives via the APEX_WIN_SCRIPT env var (base64 UTF-8) behind a
// short static powershell command — never an oversized EncodedCommand — and
// paths/parameters travel in env vars, never interpolated into the command.

function sandboxReadError(result: SandboxExecutionResult): string {
  return sandboxOpError("read", result);
}

function abortedReadResult(path: string): ReadFileResult {
  return {
    success: false,
    error: "Read file aborted by user",
    content: "",
    path,
  };
}

// Windows byte-window helper: emits the window as base64. The container
// check mirrors the local ordinary-file contract; file symlinks resolve.
const WIN_BYTE_READ_SCRIPT = [
  WIN_SCRIPT_PRELUDE,
  "try{",
  "$p=[Environment]::GetEnvironmentVariable('APEX_READ_PATH')",
  "$item=Get-Item -LiteralPath $p -Force",
  "if($item.PSIsContainer){throw 'Not an ordinary file'}",
  "$off=[int64][Environment]::GetEnvironmentVariable('APEX_READ_OFFSET')",
  "$cnt=[int64][Environment]::GetEnvironmentVariable('APEX_READ_COUNT')",
  "$fs=[IO.File]::OpenRead($p)",
  "try{",
  "$null=$fs.Seek($off,[IO.SeekOrigin]::Begin)",
  "$buf=New-Object byte[] $cnt",
  "$got=0",
  "while($got -lt $cnt){$n=$fs.Read($buf,$got,$cnt-$got);if($n -le 0){break};$got+=$n}",
  "[Console]::Out.Write([Convert]::ToBase64String($buf,0,$got))",
  "}finally{$fs.Dispose()}",
  "}catch{",
  "[Console]::Error.WriteLine($_.Exception.Message)",
  "exit 2",
  "}",
].join("\n");

type SandboxByteFetch =
  | { ok: true; bytes: Buffer; atEof: boolean }
  | { ok: false; error: string };

/**
 * Fetches byteOffset..byteOffset+byteCount plus one probe byte — the probe
 * distinguishes a full page from EOF without a second round trip.
 */
async function fetchSandboxByteWindow(
  sandbox: UnifiedSandbox,
  filePath: string,
  byteOffset: number,
  byteCount: number,
): Promise<SandboxByteFetch> {
  const probeCount = byteCount + 1;
  const result =
    sandbox.type === "windows"
      ? await sandbox.execute(WIN_SCRIPT_COMMAND, {
          timeout: SANDBOX_OP_TIMEOUT_SECONDS,
          retries: 0,
          envVars: {
            ...winScriptEnv(WIN_BYTE_READ_SCRIPT),
            APEX_READ_PATH: filePath,
            APEX_READ_OFFSET: String(byteOffset),
            APEX_READ_COUNT: String(probeCount),
          },
        })
      : await sandbox.execute(
          [
            '[ -f "$APEX_READ_PATH" ] || { echo "not an ordinary file (directory, FIFO, or device): $APEX_READ_PATH" >&2; exit 3; }',
            `tail -c +${byteOffset + 1} "$APEX_READ_PATH" | head -c ${probeCount} | base64`,
          ].join("; "),
          {
            timeout: SANDBOX_OP_TIMEOUT_SECONDS,
            retries: 0,
            envVars: { APEX_READ_PATH: filePath },
          },
        );
  if (!result.success || result.exitCode !== 0) {
    return { ok: false, error: sandboxReadError(result) };
  }
  const parsed = parseSandboxBase64(result.stdout);
  if (!parsed.ok) return parsed;
  const bytes = parsed.bytes;
  return { ok: true, bytes, atEof: bytes.length <= byteCount };
}

async function readSandboxFile(
  ctx: ToolContext,
  resolved: string,
  input: {
    path: string;
    startLine?: number;
    endLine?: number;
    byteOffset?: number;
    byteCount?: number;
  },
): Promise<ReadFileResult> {
  if (!ctx.sandbox) throw new Error("readSandboxFile requires a sandbox");
  if (ctx.abortSignal?.aborted) return abortedReadResult(input.path);
  if (input.byteOffset !== undefined && input.byteCount !== undefined) {
    const fetch = await fetchSandboxByteWindow(
      ctx.sandbox,
      resolved,
      input.byteOffset,
      input.byteCount,
    );
    if (ctx.abortSignal?.aborted) return abortedReadResult(input.path);
    if (!fetch.ok) {
      return {
        success: false,
        error: fetch.error,
        content: "",
        path: input.path,
      };
    }
    return decodeByteWindow(
      fetch.bytes,
      input.byteOffset,
      input.byteCount,
      input.path,
      fetch.atEof,
    );
  }
  return readSandboxLines(
    ctx,
    ctx.sandbox,
    resolved,
    input.path,
    input.startLine,
    input.endLine,
  );
}

// Line windows fetch bounded RAW bytes (terminators intact) and are numbered,
// capped, and budgeted locally, so sandbox reads return exactly the shape and
// cursors local reads do.
const LINE_FETCH_CAP_BYTES = 128 * 1024;

type SandboxLineFetch =
  | { ok: false; error: string }
  | { ok: true; bytes: Buffer; cut: true }
  | { ok: true; bytes: Buffer; cut: false; totalNewlines: number };

function parseSandboxBase64(
  stdout: string,
): { ok: true; bytes: Buffer } | { ok: false; error: string } {
  const b64 = stdout.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/=]*$/.test(b64) || b64.length % 4 !== 0) {
    return {
      ok: false,
      error: `sandbox read returned non-base64 output: ${stdout.slice(0, 200)}`,
    };
  }
  return { ok: true, bytes: Buffer.from(b64, "base64") };
}

async function fetchSandboxLinesLinux(
  sandbox: UnifiedSandbox,
  filePath: string,
  start: number,
  end: number,
): Promise<SandboxLineFetch> {
  const notOrdinary =
    '[ -f "$APEX_READ_PATH" ] || { echo "not an ordinary file (directory, FIFO, or device): $APEX_READ_PATH" >&2; exit 3; }';
  // One probe byte past the cap distinguishes a complete window from a cut.
  const window =
    end === Number.POSITIVE_INFINITY
      ? `tail -n +${start} "$APEX_READ_PATH" | head -c ${LINE_FETCH_CAP_BYTES + 1}`
      : `tail -n +${start} "$APEX_READ_PATH" | head -n ${Math.max(0, end - start + 1)} | head -c ${LINE_FETCH_CAP_BYTES + 1}`;
  const fetch = await sandbox.execute(
    `${notOrdinary}; ( ${window} ) | base64`,
    {
      timeout: SANDBOX_OP_TIMEOUT_SECONDS,
      retries: 0,
      envVars: { APEX_READ_PATH: filePath },
    },
  );
  if (!fetch.success || fetch.exitCode !== 0) {
    return { ok: false, error: sandboxReadError(fetch) };
  }
  const parsed = parseSandboxBase64(fetch.stdout);
  if (!parsed.ok) return parsed;
  if (parsed.bytes.length > LINE_FETCH_CAP_BYTES) {
    return { ok: true, bytes: parsed.bytes, cut: true };
  }
  // A complete window still needs the whole-file line count to report
  // totalLines and decide EOF exactly like the local scanner would.
  const wc = await sandbox.execute('wc -l < "$APEX_READ_PATH"', {
    timeout: SANDBOX_OP_TIMEOUT_SECONDS,
    retries: 0,
    envVars: { APEX_READ_PATH: filePath },
  });
  if (!wc.success || wc.exitCode !== 0) {
    return { ok: false, error: sandboxReadError(wc) };
  }
  const totalNewlines = Number.parseInt(wc.stdout.trim(), 10);
  if (!Number.isInteger(totalNewlines) || totalNewlines < 0) {
    return {
      ok: false,
      error: `sandbox wc -l returned non-numeric output: ${wc.stdout.slice(0, 200)}`,
    };
  }
  return { ok: true, bytes: parsed.bytes, cut: false, totalNewlines };
}

// Windows single-pass scanner: streams raw bytes, counts every newline, and
// emits only the in-window lines' bytes (capped) as base64 plus a trailing
// APEXRL marker carrying the newline count (or the cut flag). Data travels in
// env vars; APEX_READ_END is empty for "no endLine".
const WIN_LINE_READ_SCRIPT = [
  WIN_SCRIPT_PRELUDE,
  "try{",
  "$p=[Environment]::GetEnvironmentVariable('APEX_READ_PATH')",
  "$item=Get-Item -LiteralPath $p -Force",
  "if($item.PSIsContainer){throw 'Not an ordinary file'}",
  "$start=[int64][Environment]::GetEnvironmentVariable('APEX_READ_START')",
  "$endS=[Environment]::GetEnvironmentVariable('APEX_READ_END')",
  "$cap=[int64][Environment]::GetEnvironmentVariable('APEX_READ_CAP')",
  "$hasEnd=($endS -ne '')",
  "$end=[int64]0",
  "if($hasEnd){$end=[int64]$endS}",
  "$fs=[IO.File]::OpenRead($p)",
  "try{",
  "$buf=New-Object byte[] 65536",
  "$ms=New-Object IO.MemoryStream",
  "$nl=[int64]0",
  "$cut=$false",
  "while(-not $cut){",
  "$n=$fs.Read($buf,0,65536)",
  "if($n -le 0){break}",
  "$i=0",
  "while($i -lt $n){",
  "$cur=$nl+1",
  "$win=($cur -ge $start) -and ((-not $hasEnd) -or ($cur -le $end))",
  "if(-not $win){",
  "$j=[Array]::IndexOf($buf,[byte]10,$i,$n-$i)",
  "if($j -lt 0){$i=$n}else{$nl++;$i=$j+1}",
  "continue",
  "}",
  "$j=[Array]::IndexOf($buf,[byte]10,$i,$n-$i)",
  "if($j -lt 0){",
  "$fit=($cap+1)-$ms.Length",
  "if(($n-$i) -le $fit){$ms.Write($buf,$i,($n-$i));$i=$n}else{if($fit -gt 0){$ms.Write($buf,$i,$fit)};$cut=$true}",
  "}else{",
  "$len=$j-$i+1",
  "$fit=($cap+1)-$ms.Length",
  "if($len -le $fit){$ms.Write($buf,$i,$len);$nl++;$i=$j+1}else{if($fit -gt 0){$ms.Write($buf,$i,$fit)};$cut=$true}",
  "}",
  "if($cut){break}",
  "}",
  "}",
  "[Console]::Out.Write([Convert]::ToBase64String($ms.ToArray()))",
  'if($cut){[Console]::Out.Write("`nAPEXRL cut=1")}else{[Console]::Out.Write("`nAPEXRL total=$nl")}',
  "exit 0",
  "}finally{$fs.Dispose()}",
  "}catch{",
  "[Console]::Error.WriteLine($_.Exception.Message)",
  "exit 2",
  "}",
].join("\n");
async function fetchSandboxLinesWindows(
  sandbox: UnifiedSandbox,
  filePath: string,
  start: number,
  end: number,
): Promise<SandboxLineFetch> {
  const result = await sandbox.execute(WIN_SCRIPT_COMMAND, {
    timeout: SANDBOX_OP_TIMEOUT_SECONDS,
    retries: 0,
    envVars: {
      ...winScriptEnv(WIN_LINE_READ_SCRIPT),
      APEX_READ_PATH: filePath,
      APEX_READ_START: String(start),
      APEX_READ_END: end === Number.POSITIVE_INFINITY ? "" : String(end),
      APEX_READ_CAP: String(LINE_FETCH_CAP_BYTES),
    },
  });
  if (!result.success || result.exitCode !== 0) {
    return { ok: false, error: sandboxReadError(result) };
  }
  const markerIdx = result.stdout.lastIndexOf("\nAPEXRL ");
  if (markerIdx === -1) {
    return {
      ok: false,
      error: `sandbox line read missing APEXRL marker: ${result.stdout.slice(0, 200)}`,
    };
  }
  const marker = result.stdout.slice(markerIdx + "\nAPEXRL ".length);
  const parsed = parseSandboxBase64(result.stdout.slice(0, markerIdx));
  if (!parsed.ok) return parsed;
  if (marker === "cut=1") {
    return { ok: true, bytes: parsed.bytes, cut: true };
  }
  const totalMatch = marker.match(/^total=(\d+)$/);
  if (!totalMatch) {
    return {
      ok: false,
      error: `sandbox line read returned a malformed APEXRL marker: ${marker.slice(0, 200)}`,
    };
  }
  return {
    ok: true,
    bytes: parsed.bytes,
    cut: false,
    totalNewlines: Number.parseInt(totalMatch[1], 10),
  };
}

/**
 * Turns a fetched line window into the same result the local streaming reader
 * produces: identical numbering, per-line cap markers, output budget, and
 * resume cursors. Semantics mirror readLocalLines.
 */
function processSandboxLines(
  raw: Buffer,
  opts: {
    path: string;
    start: number;
    end: number;
    cut: boolean;
    totalNewlines?: number;
  },
): ReadFileResult {
  // Non-fatal decode matches local line mode: invalid bytes surface as
  // U+FFFD. A cut window keeps its trailing partial sequence out (stream
  // mode never finalizes); a complete window finalizes at EOF.
  const decoder = new TextDecoder("utf-8", { ignoreBOM: true });
  let text = decoder.decode(raw, { stream: opts.cut });
  if (!opts.cut) text += decoder.decode();

  const totalLines =
    opts.totalNewlines !== undefined ? opts.totalNewlines + 1 : undefined;
  // EOF was reached when the window covers the file's last split-line or
  // starts past it — the same conditions the local scanner uses.
  const eof =
    totalLines !== undefined &&
    (opts.end === Number.POSITIVE_INFINITY ||
      opts.end >= totalLines ||
      opts.start > totalLines);

  let segments = text.split("\n");
  if (opts.cut || !eof) {
    // The segment after the last fetched newline is not a delivered line:
    // for a cut it is a partial line, for a line-boundary window end it is
    // an artifact of split("\n").
    segments.pop();
  } else if (text === "" && opts.start > totalLines) {
    // Window entirely past EOF: no lines exist there, not one empty line.
    segments = [];
  }

  if (opts.cut && segments.length === 0) {
    return {
      success: false,
      error:
        "The requested line exceeds the bounded read window; use byteOffset/byteCount to page its contents",
      content: `${String(opts.start).padStart(6)}|${text.slice(0, MAX_LINE_CHARS)}…`,
      path: opts.path,
      linesReturned: 0,
      truncated: true,
    };
  }
  const numbered: string[] = [];
  let outputChars = 0;
  let cappedAny = false;
  let budgetStopLine: number | undefined;
  for (let i = 0; i < segments.length; i++) {
    const line = segments[i];
    const lineNo = opts.start + i;
    const display =
      line.length > MAX_LINE_CHARS
        ? `${line.slice(0, MAX_LINE_CHARS)}… (+${line.length - MAX_LINE_CHARS} chars dropped in this line — use byteOffset/byteCount)`
        : line;
    cappedAny ||= display !== line;
    const numberedLine = `${String(lineNo).padStart(6)}|${display}`;
    if (outputChars + numberedLine.length > OUTPUT_BUDGET_CHARS) {
      budgetStopLine = lineNo;
      break;
    }
    numbered.push(numberedLine);
    outputChars += numberedLine.length + 1;
  }

  const hitBudget = budgetStopLine !== undefined;
  const content = numbered.join("\n");
  const result: ReadFileResult = {
    success: true,
    error: "",
    content:
      hitBudget && numbered.length > 0
        ? `${content}\n\n(truncated — use startLine/endLine or byteOffset/byteCount to continue)`
        : content,
    path: opts.path,
    linesReturned: numbered.length,
  };
  if (hitBudget) {
    result.stoppedAtLine = budgetStopLine;
  } else if (eof && totalLines !== undefined) {
    result.totalLines = totalLines;
  } else if (opts.cut) {
    result.stoppedAtLine = opts.start + segments.length;
  } else {
    result.stoppedAtLine = opts.end >= opts.start ? opts.end + 1 : opts.start;
  }
  if (hitBudget || cappedAny || opts.cut) {
    result.truncated = true;
  }
  return result;
}

async function readSandboxLines(
  ctx: ToolContext,
  sandbox: UnifiedSandbox,
  resolved: string,
  path: string,
  startLine?: number,
  endLine?: number,
): Promise<ReadFileResult> {
  const start = startLine ? Math.max(1, Math.floor(startLine)) : 1;
  const end = endLine ? Math.floor(endLine) : Number.POSITIVE_INFINITY;
  if (ctx.abortSignal?.aborted) return abortedReadResult(path);
  const fetch =
    sandbox.type === "windows"
      ? await fetchSandboxLinesWindows(sandbox, resolved, start, end)
      : await fetchSandboxLinesLinux(sandbox, resolved, start, end);
  if (ctx.abortSignal?.aborted) return abortedReadResult(path);
  if (!fetch.ok) {
    return { success: false, error: fetch.error, content: "", path };
  }
  return processSandboxLines(fetch.bytes, {
    path,
    start,
    end,
    cut: fetch.cut,
    ...(fetch.cut ? {} : { totalNewlines: fetch.totalNewlines }),
  });
}
