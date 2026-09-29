import { describe, expect, it } from "vitest";
import { applyFileDiff, PatchApplyError } from "./patchApply";
import { parseUnifiedDiff } from "./patchParse";

function apply(patch: string, content: string) {
  const files = parseUnifiedDiff(patch);
  return applyFileDiff(content, files[0]);
}

function expectApplyError(patch: string, content: string, message: RegExp) {
  expect(() => apply(patch, content)).toThrow(message);
}

describe("applyFileDiff — matching", () => {
  it("applies a simple replacement", () => {
    const result = apply(
      `--- a/f
+++ b/f
@@ -1,3 +1,3 @@
 line1
-old
+new
 line3
`,
      "line1\nold\nline3\n",
    );
    expect(result.content).toBe("line1\nnew\nline3\n");
    expect(result.outcomes).toEqual([{ matchedAt: 1, offset: 0 }]);
  });

  it("applies multiple hunks bottom-up", () => {
    const result = apply(
      `--- a/f
+++ b/f
@@ -1,2 +1,2 @@
-a
+A
 b
@@ -5,2 +5,2 @@
 e
-f
+F
`,
      "a\nb\nc\nd\ne\nf\n",
    );
    expect(result.content).toBe("A\nb\nc\nd\ne\nF\n");
    expect(result.outcomes).toEqual([
      { matchedAt: 1, offset: 0 },
      { matchedAt: 5, offset: 0 },
    ]);
  });

  it("locates unique context anywhere in the file when line numbers drift", () => {
    const result = apply(
      `--- a/f
+++ b/f
@@ -2,3 +2,3 @@
 b
-c
+C
 d
`,
      "x\ny\nz\nb\nc\nd\n",
    );
    expect(result.content).toBe("x\ny\nz\nb\nC\nd\n");
    expect(result.outcomes).toEqual([{ matchedAt: 4, offset: 2 }]);
  });

  it("matches a unique position far beyond any fixed drift window", () => {
    const filler = Array.from({ length: 80 }, (_, i) => `filler ${i + 1}`);
    const content = `${[...filler, "unique-old", "tail"].join("\n")}\n`;
    const result = apply(
      `--- a/f
+++ b/f
@@ -2,2 +2,2 @@
-unique-old
+unique-new
 tail
`,
      content,
    );
    expect(result.content).toBe(
      `${[...filler, "unique-new", "tail"].join("\n")}\n`,
    );
    expect(result.outcomes).toEqual([{ matchedAt: 81, offset: 79 }]);
  });

  it("rejects ambiguity even when the declared position is one of the matches", () => {
    expectApplyError(
      `--- a/f
+++ b/f
@@ -1 +1 @@
-same
+diff
`,
      "same\nsame\n",
      /matches at multiple positions/,
    );
  });

  it("rejects ambiguous matches instead of guessing", () => {
    expectApplyError(
      `--- a/f
+++ b/f
@@ -1,2 +1,2 @@
 X
-a
+A
`,
      "q\nX\na\nz\nX\na\n",
      /matches at multiple positions/,
    );
  });

  it("rejects context that matches nowhere in the file", () => {
    expectApplyError(
      `--- a/f
+++ b/f
@@ -1,1 +1,1 @@
-nope
+yep
`,
      "entirely\ndifferent\n",
      /does not match anywhere/,
    );
  });

  it("rejects overlapping hunks", () => {
    expectApplyError(
      `--- a/f
+++ b/f
@@ -1,3 +1,3 @@
 a
-b
+B
 c
@@ -2,2 +2,2 @@
 b
-c
+C
`,
      "a\nb\nc\nd\n",
      /overlaps hunk 1/,
    );
  });

  it("rejects two insertions at the same point", () => {
    expectApplyError(
      `--- a/f
+++ b/f
@@ -1,0 +2,1 @@
+one
@@ -1,0 +2,1 @@
+two
`,
      "a\nb\n",
      /insert at the same point/,
    );
  });

  it.each([
    false,
    true,
  ])("inserts before an adjacent edit regardless of hunk order (reversed: %s)", (reversed) => {
    const hunks = ["@@ -1,0 +2 @@\n+inserted\n", "@@ -2 +3 @@\n-b\n+B\n"];
    if (reversed) hunks.reverse();
    expect(
      apply(`--- a/f\n+++ b/f\n${hunks.join("")}`, "a\nb\nc\n").content,
    ).toBe("a\ninserted\nB\nc\n");
  });

  it("inserts mid-file at the declared anchor", () => {
    const result = apply(
      `--- a/f
+++ b/f
@@ -1,0 +2,1 @@
+X
`,
      "a\nb\n",
    );
    expect(result.content).toBe("a\nX\nb\n");
  });

  it("rejects insertion past end of file", () => {
    expectApplyError(
      `--- a/f
+++ b/f
@@ -9,0 +10,1 @@
+X
`,
      "a\nb\n",
      /past end of file/,
    );
  });
});

describe("applyFileDiff — formatting invariants", () => {
  it.each([
    false,
    true,
  ])("validates old EOF before an append and preserves the appended newline state (%s)", (unterminated) => {
    const marker = unterminated ? "\\ No newline at end of file\n" : "";
    const result = apply(
      `--- a/f\n+++ b/f\n@@ -2 +2 @@\n-b\n\\ No newline at end of file\n+B\n@@ -2,0 +3 @@\n+tail\n${marker}`,
      "a\nb",
    );
    expect(result.content).toBe(`a\nB\ntail${unterminated ? "" : "\n"}`);
  });

  it("rejects a new-side no-newline marker before appended content", () => {
    expectApplyError(
      "--- a/f\n+++ b/f\n@@ -2 +2 @@\n-b\n+B\n\\ No newline at end of file\n@@ -2,0 +3 @@\n+tail\n",
      "a\nb\n",
      /does not reach end of file/,
    );
  });

  it("rejects an old-side no-newline marker before a deleted tail", () => {
    expectApplyError(
      "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+A\n@@ -2 +1,0 @@\n-b\n",
      "a\nb\n",
      /does not reach end of file/,
    );
  });

  it("accepts a new-side no-newline marker when a later hunk deletes the tail", () => {
    const result = apply(
      "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+A\n\\ No newline at end of file\n@@ -2 +1,0 @@\n-b\n",
      "a\nb\n",
    );
    expect(result.content).toBe("A");
  });

  it("preserves a final newline when the hunk does not touch EOF", () => {
    const result = apply(
      `--- a/f
+++ b/f
@@ -1 +1 @@
-a
+A
`,
      "a\nb\n",
    );
    expect(result.content).toBe("A\nb\n");
  });

  it("removes the final newline when both sides carry the marker", () => {
    const result = apply(
      `--- a/f
+++ b/f
@@ -2 +2 @@
-b
\\ No newline at end of file
+B
\\ No newline at end of file
`,
      "a\nb\n",
    );
    expect(result.content).toBe("a\nB");
  });

  it("adds a final newline when only the old side carried the marker", () => {
    const result = apply(
      `--- a/f
+++ b/f
@@ -2 +2 @@
-b
\\ No newline at end of file
+B
`,
      "a\nb",
    );
    expect(result.content).toBe("a\nB\n");
  });

  it("removes a final newline when only the new side carries the marker", () => {
    const result = apply(
      `--- a/f
+++ b/f
@@ -2 +2 @@
-b
+B
\\ No newline at end of file
`,
      "a\nb\n",
    );
    expect(result.content).toBe("a\nB");
  });

  it("matches a CRLF-content patch (body carries CR) against a CRLF file", () => {
    const result = apply(
      "--- a/f\r\n+++ b/f\r\n@@ -1,3 +1,3 @@\r\n one\r\n-two\r\n+TWO\r\n three\r\n",
      "one\r\ntwo\r\nthree\r\n",
    );
    expect(result.content).toBe("one\r\nTWO\r\nthree\r\n");
    expect(result.eolAdaptation).toBe("none");
  });

  it("adapts an LF patch to a CRLF file, adding CR to inserted lines", () => {
    const result = apply(
      `--- a/f
+++ b/f
@@ -1,3 +1,4 @@
 one
-two
+TWO
+EXTRA
 three
`,
      "one\r\ntwo\r\nthree\r\n",
    );
    expect(result.content).toBe("one\r\nTWO\r\nEXTRA\r\nthree\r\n");
    expect(result.eolAdaptation).toBe("added-cr");
  });

  it("strips transport CR from a CRLF-carried patch applied to an LF file", () => {
    const result = apply(
      "--- a/f\r\n+++ b/f\r\n@@ -1,3 +1,3 @@\r\n one\r\n-two\r\n+TWO\r\n three\r\n",
      "one\ntwo\nthree\n",
    );
    expect(result.content).toBe("one\nTWO\nthree\n");
    expect(result.eolAdaptation).toBe("stripped-cr");
  });

  it.each([
    ["before the first line", 0, "inserted\none\ntwo\n"],
    ["between lines", 1, "one\ninserted\ntwo\n"],
    ["at EOF", 2, "one\ntwo\ninserted\n"],
  ])("strips transport CR from a pure insertion %s", (_label, start, expected) => {
    const patch = `--- a/f\r\n+++ b/f\r\n@@ -${start},0 +${Number(start) + 1},1 @@\r\n+inserted\r\n`;
    const result = apply(patch, "one\ntwo\n");
    expect(result.content).toBe(expected);
    expect(result.eolAdaptation).toBe("stripped-cr");
  });

  it("strips transport CR from an insertion beside an unchanged LF hunk", () => {
    const patch =
      "--- a/f\r\n+++ b/f\r\n@@ -1,1 +1,1 @@\r\n one\n@@ -1,0 +2,1 @@\r\n+inserted\r\n";
    expect(apply(patch, "one\ntwo\n").content).toBe("one\ninserted\ntwo\n");
  });

  it("preserves mixed line endings across an LF-authored patch", () => {
    const result = apply(
      `--- a/f
+++ b/f
@@ -1,2 +1,2 @@
 crlf
-lf
+LF
`,
      "crlf\r\nlf\nmixed\r\n",
    );
    expect(result.content).toBe("crlf\r\nLF\nmixed\r\n");
    expect(result.eolAdaptation).toBe("matched-lines");
  });

  it("preserves the BOM across a hand-authored edit", () => {
    const result = apply(
      `--- a/f
+++ b/f
@@ -1 +1 @@
-first
+FIRST
`,
      "﻿first\nsecond\n",
    );
    expect(result.content).toBe("﻿FIRST\nsecond\n");
  });

  it("matches a git-generated BOM first-line diff and keeps the BOM", () => {
    const result = apply(
      `--- a/f
+++ b/f
@@ -1 +1 @@
-﻿first
+﻿FIRST
`,
      "﻿first\nsecond\n",
    );
    expect(result.content).toBe("﻿FIRST\nsecond\n");
  });

  it("removes the BOM when a git-style diff drops it from line 1", () => {
    const result = apply(
      `--- a/f
+++ b/f
@@ -1 +1 @@
-﻿first
+FIRST
`,
      "﻿first\nsecond\n",
    );
    expect(result.content).toBe("FIRST\nsecond\n");
  });

  it.each([
    "\n",
    "\r\n",
  ])("preserves the file BOM when a BOM-dropping hunk relocates (%j)", (eol) => {
    const result = apply(
      "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-\uFEFFold\n+new\n",
      `\uFEFFunchanged${eol}old${eol}`,
    );
    expect(result.content).toBe(`\uFEFFunchanged${eol}new${eol}`);
    expect(result.outcomes).toEqual([{ matchedAt: 2, offset: 1 }]);
  });

  it("adds a BOM when a git-style diff introduces it on line 1", () => {
    const result = apply(
      `--- a/f
+++ b/f
@@ -1 +1 @@
-first
+﻿FIRST
`,
      "first\nsecond\n",
    );
    expect(result.content).toBe("﻿FIRST\nsecond\n");
  });

  it("rejects a no-newline marker on a hunk that stops short of EOF", () => {
    expectApplyError(
      `--- a/f
+++ b/f
@@ -1 +1 @@
-a
\\ No newline at end of file
+A
`,
      "a\nb\n",
      /does not reach end of file/,
    );
  });
});

describe("applyFileDiff — create and delete", () => {
  it("creates a file from pure additions with an implicit final newline", () => {
    const result = apply(
      `--- /dev/null
+++ b/new.ts
@@ -0,0 +1,2 @@
+one
+two
`,
      "",
    );
    expect(result.content).toBe("one\ntwo\n");
  });

  it("creates a file without final newline when the marker says so", () => {
    const result = apply(
      `--- /dev/null
+++ b/new.ts
@@ -0,0 +1,1 @@
+only
\\ No newline at end of file
`,
      "",
    );
    expect(result.content).toBe("only");
  });

  it("refuses to create when content already exists", () => {
    expect(() =>
      apply(
        `--- /dev/null
+++ b/new.ts
@@ -0,0 +1,1 @@
+one
`,
        "existing\n",
      ),
    ).toThrow(PatchApplyError);
  });

  it("applies a whole-file delete to empty", () => {
    const result = apply(
      `--- a/gone.ts
+++ /dev/null
@@ -1,2 +0,0 @@
-a
-b
`,
      "a\nb\n",
    );
    expect(result.content).toBe("");
  });

  it("rejects a delete patch that does not cover the whole file", () => {
    expectApplyError(
      `--- a/gone.ts
+++ /dev/null
@@ -1,1 +0,0 @@
-a
`,
      "a\nb\n",
      /does not cover the entire file/,
    );
  });
});

it("adapts a hunk spanning CRLF and an unterminated final line", () => {
  const patch =
    "--- a/file\n+++ b/file\n@@ -1,2 +1,2 @@\n first\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n";
  expect(apply(patch, "first\r\nold").content).toBe("first\r\nnew");
});

it("preserves each line ending in a mixed LF/CRLF replacement", () => {
  const patch =
    "--- a/file\n+++ b/file\n@@ -1,3 +1,3 @@\n first\n-old\n-last\n+new\n+end\n";
  expect(apply(patch, "first\r\nold\nlast\r\n").content).toBe(
    "first\r\nnew\nend\r\n",
  );
});

it("uses surrounding CRLF for a pure insertion", () => {
  expect(
    apply("--- a/f\n+++ b/f\n@@ -1,0 +2,1 @@\n+inserted\n", "one\r\ntwo\r\n")
      .content,
  ).toBe("one\r\ninserted\r\ntwo\r\n");
});

it("retains exact mixed-ending context when another hunk is an insertion", () => {
  const patch =
    "--- a/f\n+++ b/f\n@@ -1,1 +1,1 @@\n-same\r\n+changed\r\n@@ -3,0 +4,1 @@\n+inserted\n";
  expect(apply(patch, "same\r\nsame\nend\r\n").content).toBe(
    "changed\r\nsame\nend\r\ninserted\r\n",
  );
});

it("reports ambiguous context when a patch also contains a pure insertion", () => {
  const patch =
    "--- a/f\n+++ b/f\n@@ -1,1 +1,1 @@\n-same\r\n+changed\r\n@@ -3,0 +4,1 @@\n+inserted\n";
  expect(() => apply(patch, "same\r\nsame\r\nend\r\n")).toThrow(
    /multiple positions/,
  );
});
