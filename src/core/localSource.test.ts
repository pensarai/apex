import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { LocalSourceProvider } from "./localSource";

describe("local source access", () => {
  let directory: string;
  let root: string;
  let provider: LocalSourceProvider;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "apex-source-"));
    root = join(directory, "repo");
    await mkdir(root);
    provider = new LocalSourceProvider(root);
  });
  afterEach(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it("pages source and detects edits between pages", async () => {
    await writeFile(join(root, "route.ts"), "first\nsecond\nthird");
    const first = await provider.readFile({
      path: "route.ts",
      offset: 0,
      limit: 6,
    });
    if (first.nextOffset === null) throw new Error("Expected another page");
    const second = await provider.readFile({
      path: "route.ts",
      offset: first.nextOffset,
      limit: 100,
      version: first.version,
    });
    expect(first.content).toBe("first\n");
    expect(second).toMatchObject({
      content: "second\nthird",
      firstLine: 2,
      nextOffset: null,
    });
    await writeFile(join(root, "route.ts"), "changed");
    await expect(
      provider.readFile({
        path: "route.ts",
        offset: 0,
        limit: 6,
        version: first.version,
      }),
    ).rejects.toThrow("changed");
    expect(await provider.describe()).toMatchObject({
      name: "repo",
      kind: "local",
    });
  });

  it("rejects absolute paths, parent traversal, and symlink escapes", async () => {
    const outside = join(directory, "secret.txt");
    await writeFile(outside, "outside");
    await symlink(outside, join(root, "link.txt"));
    await symlink(directory, join(root, "linked-dir"));
    for (const path of [
      outside,
      "../secret.txt",
      "link.txt",
      "linked-dir/secret.txt",
    ]) {
      await expect(
        provider.readFile({ path, offset: 0, limit: 100 }),
      ).rejects.toThrow(/repository/);
    }
    await expect(
      provider.search({ path: "linked-dir", query: "outside", limit: 10 }),
    ).rejects.toThrow("outside");
  });

  it("paginates tree entries and omits symbolic links", async () => {
    await writeFile(join(root, "a.ts"), "");
    await mkdir(join(root, "b"));
    await symlink(join(root, "a.ts"), join(root, "link"));
    expect(await provider.listTree({ path: ".", offset: 0, limit: 1 })).toEqual(
      { entries: [{ path: "a.ts", kind: "file" }], nextOffset: 1 },
    );
    expect(await provider.listTree({ path: ".", offset: 1, limit: 1 })).toEqual(
      { entries: [{ path: "b", kind: "directory" }], nextOffset: null },
    );
  });

  it("searches literally with line numbers and explicit truncation", async () => {
    await writeFile(join(root, "a.ts"), "call(x)\ncall(y)\ncall(x)");
    const result = await provider.search({
      path: ".",
      query: "call(x)",
      limit: 1,
    });
    expect(result).toEqual({
      matches: [{ path: "a.ts", line: 1, text: "call(x)" }],
      truncated: true,
      skippedFiles: 0,
    });
    expect(
      (await provider.search({ path: ".", query: "CALL", limit: 1 })).matches,
    ).toEqual([]);
  });

  it("reports files omitted by encoding or size limits", async () => {
    await writeFile(join(root, "binary"), Buffer.from([0, 1]));
    await writeFile(join(root, "large"), "a".repeat(2 * 1024 * 1024 + 1));
    const result = await provider.search({ path: ".", query: "a", limit: 10 });
    expect(result.skippedFiles).toBe(2);
    await expect(
      provider.readFile({ path: "large", offset: 0, limit: 10 }),
    ).rejects.toThrow("2 MiB");
  });

  it("honors cancellation before filesystem work", async () => {
    const controller = new AbortController();
    controller.abort(new Error("cancelled"));
    await expect(
      provider.search(
        { path: ".", query: "x", limit: 1 },
        { signal: controller.signal },
      ),
    ).rejects.toThrow("cancelled");
  });
});
