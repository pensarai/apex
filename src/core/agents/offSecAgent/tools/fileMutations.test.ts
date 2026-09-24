import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { createFile } from "./createFile";
import type { ToolContext } from "./types";
import { updateFile } from "./updateFile";

const roots: string[] = [];
const options = { toolCallId: "mutation-contract", messages: [] };
const toolCallDescription = "Verify exact file mutation";
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

async function fixture(content: string) {
  const root = await mkdtemp(join(tmpdir(), "apex-mutation-"));
  roots.push(root);
  const path = join(root, "helper.txt");
  await writeFile(path, content);
  const ctx = { agentCwd: root } as ToolContext;
  return { path, ctx };
}

it.each([
  {
    name: "ambiguous text",
    original: "old old",
    oldContent: "old",
    newContent: "new",
  },
  {
    name: "overlapping matches",
    original: "aaa",
    oldContent: "aa",
    newContent: "new",
  },
  { name: "empty search", original: "old", oldContent: "", newContent: "new" },
  {
    name: "missing text",
    original: "old",
    oldContent: "absent",
    newContent: "new",
  },
])("rejects $name without modifying bytes", async ({
  original,
  oldContent,
  newContent,
}) => {
  const { ctx, path } = await fixture(original);
  const result = await updateFile(ctx).execute?.(
    { path, oldContent, newContent, toolCallDescription },
    options,
  );
  expect(result).toMatchObject({ success: false, replacements: 0 });
  expect(await readFile(path, "utf8")).toBe(original);
});

it.each([
  {
    name: "literal replacement",
    original: "old",
    oldContent: "old",
    newContent: "$&$1",
    expected: "$&$1",
  },
  {
    name: "CRLF and BOM",
    original: "\uFEFFfirst\r\nold\r\nlast\r\n",
    oldContent: "first\nold",
    newContent: "first\nnew",
    expected: "\uFEFFfirst\r\nnew\r\nlast\r\n",
  },
  {
    name: "mixed endings",
    original: "first\r\nold\nlast\r\n",
    oldContent: "old",
    newContent: "new",
    expected: "first\r\nnew\nlast\r\n",
  },
  {
    name: "missing final newline",
    original: "old",
    oldContent: "old",
    newContent: "new",
    expected: "new",
  },
])("preserves $name", async ({
  original,
  oldContent,
  newContent,
  expected,
}) => {
  const { ctx, path } = await fixture(original);
  const result = await updateFile(ctx).execute?.(
    { path, oldContent, newContent, toolCallDescription },
    options,
  );
  expect(result).toMatchObject({ success: true, replacements: 1 });
  expect(await readFile(path, "utf8")).toBe(expected);
});

it("requires explicit replaceAll for repeated text", async () => {
  const { ctx, path } = await fixture("old old old");
  const result = await updateFile(ctx).execute?.(
    {
      path,
      oldContent: "old",
      newContent: "$&",
      replaceAll: true,
      toolCallDescription,
    },
    options,
  );
  expect(result).toMatchObject({ success: true, replacements: 3 });
  expect(await readFile(path, "utf8")).toBe("$& $& $&");
});

it("reports no-op edits and preserves the original file", async () => {
  const { ctx, path } = await fixture("old");
  const result = await updateFile(ctx).execute?.(
    { path, oldContent: "old", newContent: "old", toolCallDescription },
    options,
  );
  expect(result).toMatchObject({ success: true, replacements: 0 });
  expect(await readFile(path, "utf8")).toBe("old");
});

it("requires explicit overwrite and admits one concurrent exclusive creator", async () => {
  const { ctx, path } = await fixture("original");
  expect(
    await createFile(ctx).execute?.(
      { path, content: "clobber", toolCallDescription },
      options,
    ),
  ).toMatchObject({ success: false });
  expect(await readFile(path, "utf8")).toBe("original");
  expect(
    await createFile(ctx).execute?.(
      { path, content: "intentional", overwrite: true, toolCallDescription },
      options,
    ),
  ).toMatchObject({ success: true });
  expect(await readFile(path, "utf8")).toBe("intentional");
  const target = join(ctx.agentCwd, "new.txt");
  const results = await Promise.all(
    ["first", "second"].map((content) =>
      createFile(ctx).execute?.(
        { path: target, content, toolCallDescription },
        options,
      ),
    ),
  );
  expect(
    results.filter((result) => result && "success" in result && result.success),
  ).toHaveLength(1);
  expect(["first", "second"]).toContain(await readFile(target, "utf8"));
});
