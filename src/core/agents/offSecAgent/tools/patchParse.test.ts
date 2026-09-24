import { describe, expect, it } from "vitest";
import { parseUnifiedDiff } from "./patchParse";

describe("parseUnifiedDiff", () => {
  it("parses a single-file hunk with a/ b/ prefixes stripped", () => {
    const patch = `--- a/src/a.ts
+++ b/src/a.ts
@@ -1,3 +1,3 @@
 line1
-old
+new
 line3
`;
    const files = parseUnifiedDiff(patch);
    expect(files).toHaveLength(1);
    expect(files[0].oldPath).toBe("src/a.ts");
    expect(files[0].newPath).toBe("src/a.ts");
    expect(files[0].hunks).toHaveLength(1);
    expect(files[0].hunks[0].lines).toEqual([
      { tag: "context", text: "line1" },
      { tag: "delete", text: "old" },
      { tag: "add", text: "new" },
      { tag: "context", text: "line3" },
    ]);
  });

  it("parses multiple files and skips git noise headers", () => {
    const patch = `diff --git a/one.ts b/one.ts
index 111..222 100644
--- a/one.ts
+++ b/one.ts
@@ -1 +1 @@
-a
+b
diff --git a/two.ts b/two.ts
--- a/two.ts
+++ b/two.ts
@@ -1 +1 @@
-c
+d
`;
    const files = parseUnifiedDiff(patch);
    expect(files).toHaveLength(2);
    expect(files[1].oldPath).toBe("two.ts");
  });

  it("defaults omitted hunk counts to 1", () => {
    const patch = `--- a/f
+++ b/f
@@ -2 +2 @@
-x
+y
`;
    const hunk = parseUnifiedDiff(patch)[0].hunks[0];
    expect(hunk.oldCount).toBe(1);
    expect(hunk.newCount).toBe(1);
  });

  it("treats a '--- ' line inside a hunk body as a deletion, not a header", () => {
    const patch = `--- a/f
+++ b/f
@@ -1,3 +1,3 @@
 keep
--- looks like a header
 more
+joined
`;
    const files = parseUnifiedDiff(patch);
    expect(files).toHaveLength(1);
    expect(files[0].hunks[0].lines[1]).toEqual({
      tag: "delete",
      text: "-- looks like a header",
    });
  });

  it("rejects fewer body lines than the header declares", () => {
    const patch = `--- a/f
+++ b/f
@@ -1,3 +1,3 @@
 line1
-old
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(/truncated hunk/i);
  });

  it("rejects a context line when the old side is already satisfied", () => {
    const patch = `--- a/f
+++ b/f
@@ -1,2 +1,2 @@
 a
-b
 c
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(
      /more context lines than the header declares/,
    );
  });

  it("rejects body lines dangling past a satisfied hunk", () => {
    const patch = `--- a/f
+++ b/f
@@ -1,1 +1,1 @@
 line1
-extra
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(
      /expected "--- " file header/,
    );
  });

  it("rejects a blank line where a body line is expected", () => {
    const patch = `--- a/f
+++ b/f
@@ -1,2 +1,2 @@
 line1

 line2
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(
      /unexpected line in hunk body/,
    );
  });

  it("rejects renames instead of treating them as adds", () => {
    const patch = `diff --git a/old.ts b/new.ts
similarity index 100%
rename from old.ts
rename to new.ts
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(/renames and copies/i);
  });

  it("rejects binary patches", () => {
    const patch = `--- a/logo.png
+++ b/logo.png
GIT binary patch
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(/binary patches/i);
  });

  it("rejects junk before the first file header, naming the line", () => {
    expect(() => parseUnifiedDiff("Here is your patch:\n--- a/f\n")).toThrow(
      /no file diffs.*line 1/,
    );
  });

  it("rejects file mode changes instead of skipping them", () => {
    const patch = `diff --git a/run.sh b/run.sh
old mode 100644
new mode 100755
--- a/run.sh
+++ b/run.sh
@@ -1 +1 @@
-a
+b
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(
      /file mode changes are not supported/,
    );
  });

  it("still skips new-file/deleted-file mode noise on create/delete diffs", () => {
    const create = `diff --git a/new.ts b/new.ts
new file mode 100644
--- /dev/null
+++ b/new.ts
@@ -0,0 +1 @@
+one
`;
    expect(parseUnifiedDiff(create)[0].isNew).toBe(true);
  });

  it("rejects quoted paths with C-style escapes", () => {
    const patch = `--- "a/ta\\303\\251ble.ts"
+++ "b/ta\\303\\251ble.ts"
@@ -1 +1 @@
-a
+b
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(
      /quoted old path with C-style escapes/,
    );
  });

  it("rejects hunk counts beyond safe integers", () => {
    const patch = `--- a/f
+++ b/f
@@ -1,9007199254740993 +1,1 @@
-a
+b
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(/not a safe integer/);
  });

  it("rejects junk between file sections after a valid file", () => {
    const patch = `--- a/f
+++ b/f
@@ -1 +1 @@
-a
+b
oops
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(
      /expected "--- " file header/,
    );
  });

  it("throws when the patch has no file diffs", () => {
    expect(() => parseUnifiedDiff("not a patch")).toThrow(/no file diffs/i);
  });

  it("requires +++ after ---", () => {
    const patch = `--- a/f
@@ -1 +1 @@
-a
+b
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(
      /expected "\+\+\+" file header/,
    );
  });

  it("parses a new file via /dev/null with pure additions", () => {
    const patch = `--- /dev/null
+++ b/new.ts
@@ -0,0 +1,2 @@
+one
+two
`;
    const files = parseUnifiedDiff(patch);
    expect(files[0].isNew).toBe(true);
    expect(files[0].oldPath).toBe("");
    expect(files[0].newPath).toBe("new.ts");
  });

  it("rejects a new-file hunk that removes lines", () => {
    const patch = `--- /dev/null
+++ b/new.ts
@@ -1,1 +1,1 @@
-x
+y
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(
      /new file new\.ts must not remove lines/,
    );
  });

  it("parses a file deletion via /dev/null", () => {
    const patch = `--- a/gone.ts
+++ /dev/null
@@ -1,1 +0,0 @@
-only
`;
    const files = parseUnifiedDiff(patch);
    expect(files[0].isDelete).toBe(true);
    expect(files[0].newPath).toBe("");
  });

  it("keeps a body-line trailing CR as content (CRLF-file diffs)", () => {
    const patch = "--- a/f\r\n+++ b/f\r\n@@ -1 +1 @@\r\n-a\r\n+b\r\n";
    const hunk = parseUnifiedDiff(patch)[0].hunks[0];
    expect(hunk.lines).toEqual([
      { tag: "delete", text: "a\r" },
      { tag: "add", text: "b\r" },
    ]);
  });

  it("recognizes the no-newline marker on a CRLF-carried patch", () => {
    const patch =
      "--- a/f\r\n+++ b/f\r\n@@ -1 +1 @@\r\n-a\r\n\\ No newline at end of file\r\n+b\r\n";
    const hunk = parseUnifiedDiff(patch)[0].hunks[0];
    expect(hunk.oldEndsWithoutNewline).toBe(true);
    expect(hunk.newEndsWithoutNewline).toBe(false);
  });
});

describe("no-newline markers", () => {
  it("flags old and new sides independently for a -/+ pair", () => {
    const patch = `--- a/f
+++ b/f
@@ -1 +1 @@
-old
\\ No newline at end of file
+new
\\ No newline at end of file
`;
    const hunk = parseUnifiedDiff(patch)[0].hunks[0];
    expect(hunk.oldEndsWithoutNewline).toBe(true);
    expect(hunk.newEndsWithoutNewline).toBe(true);
  });

  it("flags both sides for a context line carrying the marker", () => {
    const patch = `--- a/f
+++ b/f
@@ -1 +1 @@
 last
\\ No newline at end of file
`;
    const hunk = parseUnifiedDiff(patch)[0].hunks[0];
    expect(hunk.oldEndsWithoutNewline).toBe(true);
    expect(hunk.newEndsWithoutNewline).toBe(true);
  });

  it("allows an old-side marker mid-hunk while new-side lines continue", () => {
    const patch = `--- a/f
+++ b/f
@@ -1,2 +1,3 @@
 first
-last
\\ No newline at end of file
+keep
+added
`;
    const hunk = parseUnifiedDiff(patch)[0].hunks[0];
    expect(hunk.oldEndsWithoutNewline).toBe(true);
    expect(hunk.newEndsWithoutNewline).toBe(false);
  });

  it("rejects a marker that annotates a non-final line", () => {
    const patch = `--- a/f
+++ b/f
@@ -1,3 +1,3 @@
 first
-mid
\\ No newline at end of file
-last
+joined
+extra
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(
      /marker annotates a non-final old-side line/,
    );
  });

  it("rejects a marker with no preceding hunk line", () => {
    const patch = `--- a/f
+++ b/f
@@ -1 +1 @@
\\ No newline at end of file
-a
+b
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(
      /marker must follow the hunk line/,
    );
  });

  it("rejects duplicate markers on the same side", () => {
    const patch = `--- a/f
+++ b/f
@@ -1 +1 @@
-old
\\ No newline at end of file
\\ No newline at end of file
+new
`;
    expect(() => parseUnifiedDiff(patch)).toThrow(
      /duplicate no-newline marker/,
    );
  });
});
