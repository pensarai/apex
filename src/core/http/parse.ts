/**
 * Parser for header inputs across every surface (CLI flags, config file
 * imports, slash commands, dialog forms).
 *
 * Contract: `parseHeaderLine` is total — every input string returns
 * either a valid `HeaderEntry` or a typed `ParseError`. No throws, no
 * silent acceptance. This is INV-parser-total and INV-validated-at-
 * boundary in the headers plan.
 */

import type { HeaderRecord } from "./types";

export type HeaderEntry = {
  readonly name: string;
  readonly value: string;
};

export type ParseError =
  | { kind: "missing-colon"; input: string }
  | { kind: "empty-name"; input: string }
  | { kind: "name-has-whitespace"; input: string }
  | { kind: "invalid-name-char"; input: string; position: number; char: string }
  | { kind: "control-char-in-value"; input: string; position: number }
  | { kind: "crlf-in-value"; input: string; position: number }
  | {
      kind: "duplicate-key-in-bulk";
      key: string;
      firstAt: number;
      secondAt: number;
    }
  | { kind: "invalid-json"; input: string; message: string }
  | { kind: "file-read-failed"; path: string; message: string };

export type Result<T, E> = { ok: true; value: T } | { ok: false; error: E };

/**
 * RFC 7230 token chars allowed in header names. Excludes whitespace,
 * delimiters, and control chars. Case is preserved for display but
 * compared lowercase elsewhere.
 */
const NAME_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const NAME_CHAR = /[!#$%&'*+\-.^_`|~0-9A-Za-z]/;

/**
 * Strip a leading `-H`, `-H=`, or `--header` prefix so curl-paste
 * inputs `parseHeaderLine("-H 'X-API-Key: abc'")` work without the
 * user pre-trimming.
 */
function stripCurlPrefix(input: string): string {
  let s = input.trim();
  if (s.startsWith("-H=")) s = s.slice(3);
  else if (s.startsWith("--header=")) s = s.slice(9);
  else if (s.startsWith("-H ")) s = s.slice(3);
  else if (s.startsWith("--header ")) s = s.slice(9);
  s = s.trim();
  if (
    (s.startsWith('"') && s.endsWith('"')) ||
    (s.startsWith("'") && s.endsWith("'"))
  ) {
    s = s.slice(1, -1);
  }
  return s;
}

/**
 * Parse a single header line. Accepts every documented format —
 * `K:V`, `K: V`, curl `-H "K: V"`, with surrounding quotes — and
 * returns either a branded `HeaderEntry` or a typed `ParseError`.
 *
 * Empty values are RFC-legal and accepted. CRLF in the value is
 * rejected (header injection). Whitespace in the name is rejected.
 */
export function parseHeaderLine(
  input: string,
): Result<HeaderEntry, ParseError> {
  const raw = stripCurlPrefix(input);

  const colonIdx = raw.indexOf(":");
  if (colonIdx === -1) {
    return { ok: false, error: { kind: "missing-colon", input } };
  }

  const rawName = raw.slice(0, colonIdx);
  const rawValue = raw.slice(colonIdx + 1);

  const name = rawName.trim();
  if (name.length === 0) {
    return { ok: false, error: { kind: "empty-name", input } };
  }
  if (/\s/.test(name)) {
    return { ok: false, error: { kind: "name-has-whitespace", input } };
  }
  if (!NAME_TOKEN.test(name)) {
    for (let i = 0; i < name.length; i++) {
      if (!NAME_CHAR.test(name[i]!)) {
        return {
          ok: false,
          error: {
            kind: "invalid-name-char",
            input,
            position: i,
            char: name[i]!,
          },
        };
      }
    }
  }

  // Trim leading whitespace from value per RFC 7230 — preserve trailing
  // whitespace? RFC says optional whitespace is trimmable from both ends.
  // Tolerate but normalize.
  const value = rawValue.replace(/^\s+/, "").replace(/\s+$/, "");

  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code === 0x0d || code === 0x0a) {
      return {
        ok: false,
        error: { kind: "crlf-in-value", input, position: i },
      };
    }
    // RFC 7230 allows printable ASCII + HTAB; reject everything else
    // below 0x20 except tab.
    if (code < 0x20 && code !== 0x09) {
      return {
        ok: false,
        error: { kind: "control-char-in-value", input, position: i },
      };
    }
  }

  return {
    ok: true,
    value: { name, value },
  };
}

/**
 * Parse newline-separated or single-string bulk input (e.g. a multi-
 * line paste, or the contents of a non-JSON `--headers-from` file).
 * Returns all errors with line numbers — no partial application.
 */
function parseHeaderList(input: string): Result<HeaderEntry[], ParseError[]> {
  const lines = input.split(/\r?\n/);
  const entries: HeaderEntry[] = [];
  const errors: ParseError[] = [];
  const seenKeys = new Map<string, number>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith("#")) continue;

    const parsed = parseHeaderLine(line);
    if (!parsed.ok) {
      errors.push(parsed.error);
      continue;
    }
    const canonical = parsed.value.name.toLowerCase();
    const firstAt = seenKeys.get(canonical);
    if (firstAt !== undefined) {
      errors.push({
        kind: "duplicate-key-in-bulk",
        key: parsed.value.name,
        firstAt,
        secondAt: i,
      });
      continue;
    }
    seenKeys.set(canonical, i);
    entries.push(parsed.value);
  }

  if (errors.length > 0) {
    return { ok: false, error: errors };
  }
  return { ok: true, value: entries };
}

/**
 * Parse a `Record<string, string>` (e.g. JSON object) into branded
 * entries. Used by `parseHeadersFromFile` (JSON branch) and by the
 * global-config loader.
 */
function parseHeaderRecord(
  record: HeaderRecord,
): Result<HeaderEntry[], ParseError[]> {
  const lines = Object.entries(record).map(([k, v]) => `${k}: ${v}`);
  return parseHeaderList(lines.join("\n"));
}

/**
 * Parse the contents of a `--headers-from <file>` argument.
 *
 * Format auto-detection: first non-whitespace `{` → JSON object;
 * otherwise newline-separated `Name: Value` with `#` comments.
 */
export async function parseHeadersFromFile(
  filePath: string,
): Promise<Result<HeaderEntry[], ParseError[]>> {
  const fs = await import("fs/promises");
  let raw: string;
  try {
    raw = await fs.readFile(filePath, "utf-8");
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      ok: false,
      error: [{ kind: "file-read-failed", path: filePath, message: msg }],
    };
  }

  const firstNonWs = raw.match(/\S/);
  if (firstNonWs && firstNonWs[0] === "{") {
    try {
      const obj = JSON.parse(raw);
      if (
        typeof obj !== "object" ||
        obj === null ||
        Array.isArray(obj) ||
        Object.values(obj).some((v) => typeof v !== "string")
      ) {
        return {
          ok: false,
          error: [
            {
              kind: "invalid-json",
              input: raw,
              message: "expected a flat object of string values",
            },
          ],
        };
      }
      return parseHeaderRecord(obj as HeaderRecord);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        ok: false,
        error: [{ kind: "invalid-json", input: raw, message: msg }],
      };
    }
  }

  return parseHeaderList(raw);
}

/**
 * Produce a one-line, actionable hint for a `ParseError`. Best-effort —
 * an empty string is returned when no useful suggestion is available.
 */
function hintFor(error: ParseError): string {
  switch (error.kind) {
    case "missing-colon":
      return "header name and value must be separated by a colon (Name: Value)";
    case "empty-name":
      return "header name cannot be empty — got a bare colon";
    case "name-has-whitespace":
      return "header names cannot contain whitespace — did you mean to use a hyphen?";
    case "invalid-name-char":
      return `'${error.char}' is not allowed in header names (use letters, digits, hyphens, or any of !#$%&'*+-.^_\`|~)`;
    case "control-char-in-value":
      return "header values cannot contain control characters (CR, LF, NUL, etc.)";
    case "crlf-in-value":
      return "header values cannot contain CR/LF (HTTP header injection risk)";
    case "duplicate-key-in-bulk":
      return `'${error.key}' was set twice in this batch — keep only one (later value would win)`;
    case "invalid-json":
      return 'expected a JSON object like {"X-API-Key": "abc"} with string values only';
    case "file-read-failed":
      return `could not read ${error.path}`;
  }
}

/**
 * Format a `ParseError` for display in stderr / timeline / dialog form
 * helpers. Always emits a short reason on the first line and a hint on
 * the second; never includes the raw header value (which may be
 * sensitive).
 */
export function formatParseError(error: ParseError): string {
  const hint = hintFor(error);
  switch (error.kind) {
    case "missing-colon":
    case "empty-name":
    case "name-has-whitespace":
      return `reason: ${error.kind}\nhint:   ${hint}`;
    case "invalid-name-char":
      return `reason: ${error.kind} at position ${error.position} ('${error.char}')\nhint:   ${hint}`;
    case "control-char-in-value":
    case "crlf-in-value":
      return `reason: ${error.kind} at position ${error.position}\nhint:   ${hint}`;
    case "duplicate-key-in-bulk":
      return `reason: duplicate key '${error.key}' (lines ${error.firstAt + 1} and ${error.secondAt + 1})\nhint:   ${hint}`;
    case "invalid-json":
      return `reason: ${error.kind}: ${error.message}\nhint:   ${hint}`;
    case "file-read-failed":
      return `reason: file-read-failed: ${error.message}\nhint:   ${hint}`;
  }
}
