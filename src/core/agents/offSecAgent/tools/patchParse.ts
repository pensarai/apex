// Strict unified-diff parser — pure, no filesystem/ToolContext. Hunk bodies
// are consumed count-driven, so a "--- " inside a body is a deletion line,
// not a file header; mismatched counts and ambiguous input fail loudly.
// Apply-time exact context matching is the backstop for the residual
// count-driven-eating ambiguity (same tradeoff GNU patch makes).

export type PatchLineTag = "context" | "delete" | "add";

export type PatchLine = {
  tag: PatchLineTag;
  text: string;
};

export type ParsedHunk = {
  oldStart: number;
  oldCount: number;
  newStart: number;
  newCount: number;
  lines: PatchLine[];
  /** The hunk's final old-side line has no trailing newline in the source. */
  oldEndsWithoutNewline: boolean;
  /** The hunk's final new-side line has no trailing newline in the result. */
  newEndsWithoutNewline: boolean;
};

export type ParsedFileDiff = {
  oldPath: string;
  newPath: string;
  hunks: ParsedHunk[];
  isNew: boolean;
  isDelete: boolean;
};

const NO_NEWLINE_MARKER = "\\ No newline at end of file";
const HUNK_HEADER_RE = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;
const RENAME_OR_COPY_RE = /^(rename from|rename to|copy from|copy to) /;
const GIT_NOISE_RE =
  /^(index |new file mode |deleted file mode |similarity index |dissimilarity index )/;
const MODE_CHANGE_RE = /^(old mode|new mode) /;

function fail(lineNo: number, message: string): never {
  throw new Error(`Patch line ${lineNo}: ${message}`);
}

function preview(line: string): string {
  return line.length > 80 ? `${line.slice(0, 77)}...` : line;
}

// Trailing \r on a body line may be content (git diff of a CRLF file) or
// transport (an LF patch saved with CRLF endings) — indistinguishable here,
// so body text keeps it verbatim and the apply layer adapts per file.
function splitPatchLines(patch: string): string[] {
  const split = patch.split("\n");
  if (split.length > 1 && split[split.length - 1] === "") split.pop();
  return split;
}

function stripTransportCr(line: string): string {
  return line.endsWith("\r") ? line.slice(0, -1) : line;
}

function parseHeaderPath(
  raw: string,
  lineNo: number,
  side: "old" | "new",
): string {
  const path = raw.split("\t")[0].trim();
  if (path === "") {
    fail(lineNo, `empty ${side} path in file header`);
  }
  // Git quotes a path exactly when it needs C-style/octal escaping, so any
  // quoted path is not literal — decoding it wrong would patch the wrong file.
  if (path.startsWith('"')) {
    fail(
      lineNo,
      `quoted ${side} path with C-style escapes is not supported: ${preview(path)}`,
    );
  }
  return path;
}

function stripPrefix(path: string): string {
  if (path.startsWith("a/") || path.startsWith("b/")) return path.slice(2);
  return path;
}

function parseSafeCount(
  digits: string | undefined,
  lineNo: number,
  side: "old" | "new",
  fallback: number,
): number {
  if (digits === undefined) return fallback;
  const value = Number(digits);
  if (!Number.isSafeInteger(value)) {
    fail(lineNo, `hunk ${side} count is not a safe integer: ${digits}`);
  }
  return value;
}

export function parseUnifiedDiff(patch: string): ParsedFileDiff[] {
  const lines = splitPatchLines(patch);
  const files: ParsedFileDiff[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line === "" || line === "\r") {
      i++;
      continue;
    }
    if (
      stripTransportCr(line) === "GIT binary patch" ||
      stripTransportCr(line).startsWith("Binary files ")
    ) {
      fail(i + 1, "binary patches are not supported");
    }
    if (RENAME_OR_COPY_RE.test(line)) {
      fail(
        i + 1,
        "renames and copies are not supported; expand them into full content diffs",
      );
    }
    if (MODE_CHANGE_RE.test(line)) {
      fail(i + 1, "file mode changes are not supported");
    }
    if (line.startsWith("diff --git ") || GIT_NOISE_RE.test(line)) {
      i++;
      continue;
    }
    if (!line.startsWith("--- ")) {
      if (files.length === 0) {
        throw new Error(
          `Patch contained no file diffs (line ${i + 1} is not a file header: ${preview(line)})`,
        );
      }
      fail(i + 1, `expected "--- " file header, got: ${preview(line)}`);
    }

    const headerLineNo = i + 1;
    const oldRaw = parseHeaderPath(line.slice(4), headerLineNo, "old");
    i++;
    if (i >= lines.length || !lines[i].startsWith("+++ ")) {
      fail(i + 1, 'expected "+++" file header after "---"');
    }
    const newRaw = parseHeaderPath(lines[i].slice(4), i + 1, "new");
    i++;

    if (
      i < lines.length &&
      (lines[i] === "GIT binary patch" || lines[i].startsWith("Binary files "))
    ) {
      fail(i + 1, "binary patches are not supported");
    }

    if (oldRaw === "/dev/null" && newRaw === "/dev/null") {
      fail(headerLineNo, "both file header sides are /dev/null");
    }
    const isNew = oldRaw === "/dev/null";
    const isDelete = newRaw === "/dev/null";
    const oldPath = isNew ? "" : stripPrefix(oldRaw);
    const newPath = isDelete ? "" : stripPrefix(newRaw);
    if (!isNew && oldPath === "") {
      fail(headerLineNo, "old path is empty");
    }
    if (!isDelete && newPath === "") {
      fail(headerLineNo, "new path is empty");
    }

    const hunks: ParsedHunk[] = [];
    while (i < lines.length && lines[i].startsWith("@@ ")) {
      const parsed = parseHunk(lines, i, {
        isDelete,
        isNew,
        path: newPath || oldPath,
      });
      hunks.push(parsed.hunk);
      i = parsed.next;
    }

    if (hunks.length === 0 && !isNew && !isDelete) {
      fail(headerLineNo, `no hunks for file ${newPath}`);
    }

    files.push({ oldPath, newPath, hunks, isNew, isDelete });
  }

  if (files.length === 0) {
    throw new Error("Patch contained no file diffs");
  }
  return files;
}

function parseHunk(
  lines: string[],
  start: number,
  file: { isDelete: boolean; isNew: boolean; path: string },
): { hunk: ParsedHunk; next: number } {
  const header = lines[start];
  const match = HUNK_HEADER_RE.exec(header);
  if (!match) {
    fail(start + 1, `malformed hunk header: ${preview(header)}`);
  }
  const headerLineNo = start + 1;
  const oldStartRaw = Number(match[1]);
  const newStartRaw = Number(match[3]);
  if (
    !Number.isSafeInteger(oldStartRaw) ||
    !Number.isSafeInteger(newStartRaw)
  ) {
    fail(headerLineNo, "hunk line position is not a safe integer");
  }
  const oldCount = parseSafeCount(match[2], headerLineNo, "old", 1);
  const newCount = parseSafeCount(match[4], headerLineNo, "new", 1);

  if (oldCount > 0 && oldStartRaw === 0) {
    fail(start + 1, "hunk old start must be >= 1 when old count > 0");
  }
  if (newCount > 0 && newStartRaw === 0) {
    fail(start + 1, "hunk new start must be >= 1 when new count > 0");
  }
  if (oldCount === 0 && newCount === 0) {
    fail(start + 1, "empty hunk");
  }
  if (file.isNew && oldCount !== 0) {
    fail(start + 1, `hunk for new file ${file.path} must not remove lines`);
  }
  if (file.isDelete && newCount !== 0) {
    fail(start + 1, `hunk for deleted file ${file.path} must not add lines`);
  }

  const body: PatchLine[] = [];
  let oldRemaining = oldCount;
  let newRemaining = newCount;
  let oldSeen = 0;
  let newSeen = 0;
  let oldMarkerAt = -1;
  let newMarkerAt = -1;

  const annotate = (lineNo: number): void => {
    const last = body[body.length - 1];
    if (!last) {
      fail(lineNo, "no-newline marker must follow the hunk line it annotates");
    }
    if (last.tag === "delete") {
      if (oldMarkerAt !== -1) {
        fail(lineNo, "duplicate no-newline marker for the old side");
      }
      oldMarkerAt = oldSeen;
    } else if (last.tag === "add") {
      if (newMarkerAt !== -1) {
        fail(lineNo, "duplicate no-newline marker for the new side");
      }
      newMarkerAt = newSeen;
    } else {
      // A context line matches only when its newline status matches on both
      // sides, so its marker covers both.
      if (oldMarkerAt !== -1 || newMarkerAt !== -1) {
        fail(lineNo, "duplicate no-newline marker");
      }
      oldMarkerAt = oldSeen;
      newMarkerAt = newSeen;
    }
  };

  let i = start + 1;
  while (oldRemaining > 0 || newRemaining > 0) {
    if (i >= lines.length) {
      fail(
        start + 1,
        `truncated hunk: expected ${oldCount} old and ${newCount} new lines`,
      );
    }
    const line = lines[i];
    if (stripTransportCr(line) === NO_NEWLINE_MARKER) {
      annotate(i);
      i++;
      continue;
    }
    const tag = line[0];
    if (tag === " ") {
      if (oldRemaining === 0 || newRemaining === 0) {
        fail(
          i + 1,
          "hunk body has more context lines than the header declares",
        );
      }
      body.push({ tag: "context", text: line.slice(1) });
      oldRemaining--;
      newRemaining--;
      oldSeen++;
      newSeen++;
    } else if (tag === "-") {
      if (oldRemaining === 0) {
        fail(
          i + 1,
          "hunk body has more deleted lines than the header declares",
        );
      }
      body.push({ tag: "delete", text: line.slice(1) });
      oldRemaining--;
      oldSeen++;
    } else if (tag === "+") {
      if (newRemaining === 0) {
        fail(i + 1, "hunk body has more added lines than the header declares");
      }
      body.push({ tag: "add", text: line.slice(1) });
      newRemaining--;
      newSeen++;
    } else {
      fail(i + 1, `unexpected line in hunk body: ${preview(line)}`);
    }
    i++;
  }

  while (i < lines.length && stripTransportCr(lines[i]) === NO_NEWLINE_MARKER) {
    annotate(i);
    i++;
  }

  // The marker is only valid on the final line of the side it annotates.
  if (oldMarkerAt !== -1 && oldMarkerAt !== oldSeen) {
    fail(start + 1, "no-newline marker annotates a non-final old-side line");
  }
  if (newMarkerAt !== -1 && newMarkerAt !== newSeen) {
    fail(start + 1, "no-newline marker annotates a non-final new-side line");
  }

  return {
    hunk: {
      oldStart: oldStartRaw,
      oldCount,
      newStart: newStartRaw,
      newCount,
      lines: body,
      oldEndsWithoutNewline: oldMarkerAt !== -1,
      newEndsWithoutNewline: newMarkerAt !== -1,
    },
    next: i,
  };
}
