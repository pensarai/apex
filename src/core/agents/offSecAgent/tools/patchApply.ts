// Pure patch application on in-memory content — no filesystem, no locks.
// Formatting invariants: per-line EOLs (CRLF \r survives in matched text),
// the file BOM, and the final newline all survive unless the patch itself
// changes them; a hunk whose old span reaches EOF sets the result's final
// newline to its new-side marker state.

import type { ParsedFileDiff, ParsedHunk, PatchLine } from "./patchParse";

const BOM = "﻿";

export type EolAdaptation =
  | "none"
  | "added-cr"
  | "stripped-cr"
  | "matched-lines";

export type AppliedHunkOutcome = {
  /** Old-side line the hunk actually matched at (1-based, original file). */
  matchedAt: number;
  /** Line drift from the declared oldStart (negative = earlier). */
  offset: number;
};

export class PatchApplyError extends Error {
  constructor(
    message: string,
    readonly hunkIndex: number,
  ) {
    super(message);
    this.name = "PatchApplyError";
  }
}

type ContentShape = {
  bom: string;
  lines: string[];
  endsWithNewline: boolean;
};

// The BOM is metadata to preserve, never patch content: it is stripped for
// matching and re-added on render. Git-generated diffs of BOM'd files embed
// the BOM in the first body line — planBom tolerates that form.
function analyzeContent(content: string): ContentShape {
  const bom = content.startsWith(BOM) ? BOM : "";
  const body = bom ? content.slice(bom.length) : content;
  if (body === "") return { bom, lines: [], endsWithNewline: false };
  return {
    bom,
    lines: body.endsWith("\n")
      ? body.slice(0, -1).split("\n")
      : body.split("\n"),
    endsWithNewline: body.endsWith("\n"),
  };
}

function renderContent(shape: ContentShape): string {
  if (shape.lines.length === 0) {
    return shape.bom && shape.endsWithNewline ? `${shape.bom}\n` : "";
  }
  const body = shape.lines.join("\n");
  return shape.endsWithNewline
    ? `${shape.bom}${body}\n`
    : `${shape.bom}${body}`;
}

function hunkOldLines(hunk: ParsedHunk): string[] {
  const lines: string[] = [];
  for (const line of hunk.lines) {
    if (line.tag === "context" || line.tag === "delete") lines.push(line.text);
  }
  return lines;
}

function matchesAt(
  lines: string[],
  start: number,
  expected: string[],
): boolean {
  if (start < 0 || start + expected.length > lines.length) return false;
  for (let i = 0; i < expected.length; i++) {
    if (lines[start + i] !== expected[i]) return false;
  }
  return true;
}

/**
 * Find where the hunk's old-side lines match: a globally unique exact-context
 * search across the (already size-bounded) file. Multiple candidates are a
 * rejection, not a guess — the declared line number is never a tiebreaker.
 */
function locateHunk(
  lines: string[],
  hunk: ParsedHunk,
  hunkIndex: number,
): { start: number } {
  const expected = hunkOldLines(hunk);
  if (expected.length === 0) {
    // Pure insertion (@@ -N,0 +M,k @@): insert after old line N.
    if (hunk.oldStart > lines.length) {
      throw new PatchApplyError(
        `Insertion point ${hunk.oldStart} is past end of file (${lines.length} lines)`,
        hunkIndex,
      );
    }
    return { start: hunk.oldStart };
  }

  let first = -1;
  for (let start = 0; start + expected.length <= lines.length; start++) {
    if (!matchesAt(lines, start, expected)) continue;
    if (first === -1) {
      first = start;
    } else {
      throw new PatchApplyError(
        `Context matches at multiple positions (line ${first + 1} and line ${start + 1}); add context lines to disambiguate`,
        hunkIndex,
      );
    }
  }
  if (first === -1) {
    throw new PatchApplyError(
      `Context does not match anywhere in the file (hunk declared line ${hunk.oldStart})`,
      hunkIndex,
    );
  }
  return { start: first };
}

/**
 * Apply a file diff's hunks to content. Hunks are located against the
 * original content (overlaps and same-point insertions rejected), then
 * spliced bottom-up so earlier hunks' line numbers stay valid. Returns the
 * new content plus per-hunk match positions for receipts.
 */
export function applyFileDiff(
  content: string,
  file: ParsedFileDiff,
): {
  content: string;
  outcomes: AppliedHunkOutcome[];
  eolAdaptation: EolAdaptation;
} {
  if (file.isNew && content !== "") {
    throw new PatchApplyError("Target already exists; cannot create", -1);
  }

  const shape = analyzeContent(content);
  const bomPlans = file.hunks.map((hunk) => planBom(hunk, shape.bom !== ""));

  // Raw context takes precedence over line-ending adaptation.
  const adapted = firstAdaptationThatFits(shape, file, bomPlans);
  const located = adapted.located;

  const outcomes: AppliedHunkOutcome[] = new Array(file.hunks.length);

  for (const { hunk, index, start } of [...located].sort(
    (a, b) => b.start - a.start,
  )) {
    const expected = hunkOldLines(hunk);
    const reachesEof = start + expected.length === shape.lines.length;
    if (
      (hunk.oldEndsWithoutNewline || hunk.newEndsWithoutNewline) &&
      !reachesEof
    ) {
      throw new PatchApplyError(
        "No-newline marker on a hunk that does not reach end of file",
        index,
      );
    }

    const replacement: string[] = [];
    let oldEnd = start;
    for (const line of adapted.lines[index]) {
      if (line.tag === "add") {
        replacement.push(line.text);
      } else {
        if (line.tag === "context") replacement.push(line.text);
        oldEnd++;
      }
    }
    shape.lines.splice(start, oldEnd - start, ...replacement);

    if (bomPlans[index].dropFileBom) shape.bom = "";
    if (reachesEof) {
      shape.endsWithNewline = !hunk.newEndsWithoutNewline;
    }
    outcomes[index] = {
      matchedAt: start + 1,
      offset: start - (hunk.oldStart - 1),
    };
  }

  if (file.isDelete && shape.lines.length > 0) {
    throw new PatchApplyError(
      "Delete patch does not cover the entire file",
      -1,
    );
  }

  return {
    content: renderContent(shape),
    outcomes,
    eolAdaptation: adapted.mode,
  };
}

type LocatedHunk = {
  hunk: ParsedHunk;
  index: number;
  start: number;
};

type AdaptedFile = {
  mode: EolAdaptation;
  lines: PatchLine[][];
  located: LocatedHunk[];
};

type BomPlan = {
  /** Body index of the old side's line 1, or -1 when the hunk has none. */
  oldFirstIndex: number;
  stripOldBom: boolean;
  /** Body index of the new side's line 1, or -1 when the new side is empty. */
  newFirstIndex: number;
  stripNewBom: boolean;
  /** Git-style diff whose new line 1 drops the BOM the old line 1 carried. */
  dropFileBom: boolean;
};

// Git treats a leading BOM as part of line 1's text, so a git-generated diff
// of a BOM'd file embeds it in the first body line. Tolerate that form: strip
// the BOM for matching/splicing (render re-adds it), and let a git-style diff
// whose new line 1 lacks the BOM remove it. Hand-authored patches without a
// BOM leave the file's BOM untouched.
function planBom(hunk: ParsedHunk, fileHasBom: boolean): BomPlan {
  const plan: BomPlan = {
    oldFirstIndex: -1,
    stripOldBom: false,
    newFirstIndex: hunk.lines.findIndex((line) => line.tag !== "delete"),
    stripNewBom: false,
    dropFileBom: false,
  };
  if (!fileHasBom) return plan;
  if (hunk.oldStart !== 1 || hunk.oldCount === 0) return plan;
  const oldFirst = hunk.lines.findIndex((line) => line.tag !== "add");
  if (oldFirst === -1) return plan;
  const oldHadBom = hunk.lines[oldFirst].text.startsWith(BOM);
  const newIsLine1 = hunk.newStart === 1 && plan.newFirstIndex !== -1;
  const newHadBom =
    newIsLine1 && hunk.lines[plan.newFirstIndex].text.startsWith(BOM);
  plan.oldFirstIndex = oldFirst;
  plan.stripOldBom = oldHadBom;
  plan.stripNewBom = newHadBom;
  plan.dropFileBom = oldHadBom && newIsLine1 && !newHadBom;
  return plan;
}

function adaptLineText(
  text: string,
  mode: EolAdaptation,
  index: number,
  bom: BomPlan,
): string {
  let adapted = text;
  if (mode === "added-cr" && !adapted.endsWith("\r")) adapted += "\r";
  else if (mode === "stripped-cr" && adapted.endsWith("\r"))
    adapted = adapted.slice(0, -1);
  const stripBom =
    (index === bom.oldFirstIndex && bom.stripOldBom) ||
    (index === bom.newFirstIndex && bom.stripNewBom);
  if (stripBom && adapted.startsWith(BOM)) adapted = adapted.slice(1);
  return adapted;
}

function firstAdaptationThatFits(
  shape: ContentShape,
  file: ParsedFileDiff,
  bomPlans: BomPlan[],
): AdaptedFile {
  const fileLines = shape.lines;
  const modes: EolAdaptation[] = ["none", "stripped-cr"];
  const attempts: { mode: EolAdaptation; error: PatchApplyError }[] = [];

  for (const mode of modes) {
    if (
      file.hunks.some((hunk) => hunk.oldCount === 0) &&
      fileLines.some((line) => line.endsWith("\r"))
    )
      continue;
    const adaptedLines = file.hunks.map((hunk, h) =>
      hunk.lines.map((line, i) => ({
        tag: line.tag,
        text: adaptLineText(line.text, mode, i, bomPlans[h]),
      })),
    );
    const adaptedHunks: ParsedHunk[] = file.hunks.map((hunk, i) => ({
      ...hunk,
      lines: adaptedLines[i],
    }));

    try {
      const located = locateAllHunks(fileLines, adaptedHunks);
      return { mode, lines: adaptedLines, located };
    } catch (err) {
      if (!(err instanceof PatchApplyError)) throw err;
      attempts.push({ mode, error: err });
    }
  }

  // LF-authored patches can span mixed endings or an unterminated last
  // line; restore each matched line's ending rather than adding CR globally.
  try {
    const hunks = file.hunks.map((hunk, h) => ({
      ...hunk,
      lines: hunk.lines.map((line, i) => ({
        ...line,
        text: adaptLineText(line.text, "stripped-cr", i, bomPlans[h]),
      })),
    }));
    const located = locateAllHunks(
      fileLines.map((line) => line.replace(/\r$/, "")),
      hunks,
    );
    const fallbackCr = fileLines.some((line) => line.endsWith("\r"));
    const endingAt = (index: number): boolean => {
      if (
        index >= fileLines.length ||
        (index === fileLines.length - 1 && !shape.endsWithNewline)
      ) {
        return index > 0
          ? (fileLines[index - 1]?.endsWith("\r") ?? fallbackCr)
          : fallbackCr;
      }
      return fileLines[index].endsWith("\r");
    };
    const lines = located.map(({ hunk, start }) => {
      let cursor = start;
      let removed: boolean[] = [];
      let replacementIndex = 0;
      const lastNew = hunk.lines.findLastIndex((line) => line.tag !== "delete");
      return hunk.lines.map((line, index) => {
        if (line.tag === "add") {
          const cr = removed[replacementIndex++] ?? endingAt(cursor);
          const unterminated = index === lastNew && hunk.newEndsWithoutNewline;
          return {
            ...line,
            text: line.text + (cr && !unterminated ? "\r" : ""),
          };
        }
        const text = fileLines[cursor];
        if (line.tag === "delete") removed.push(endingAt(cursor));
        else {
          removed = [];
          replacementIndex = 0;
        }
        cursor++;
        return { ...line, text };
      });
    });
    const mixed = fileLines.some(
      (line, i) =>
        !line.endsWith("\r") &&
        (i < fileLines.length - 1 || shape.endsWithNewline),
    );
    return { mode: mixed ? "matched-lines" : "added-cr", lines, located };
  } catch (err) {
    if (!(err instanceof PatchApplyError)) throw err;
  }
  const none = attempts.find((a) => a.mode === "none");
  throw none?.error ?? new PatchApplyError("Patch does not fit the file", -1);
}

function locateAllHunks(
  fileLines: string[],
  hunks: ParsedHunk[],
): LocatedHunk[] {
  const located: LocatedHunk[] = hunks.map((hunk, index) => ({
    hunk,
    index,
    ...locateHunk(fileLines, hunk, index),
  }));

  const byPosition = [...located].sort((a, b) => a.start - b.start);
  for (let i = 1; i < byPosition.length; i++) {
    const prev = byPosition[i - 1];
    const cur = byPosition[i];
    const prevEnd = prev.start + hunkOldLines(prev.hunk).length;
    if (cur.start < prevEnd) {
      throw new PatchApplyError(
        `Hunk ${cur.index + 1} overlaps hunk ${prev.index + 1}`,
        cur.index,
      );
    }
    if (cur.start === prev.start && cur.start === prevEnd) {
      throw new PatchApplyError(
        `Hunks ${prev.index + 1} and ${cur.index + 1} insert at the same point; order is ambiguous`,
        cur.index,
      );
    }
  }
  return located;
}
