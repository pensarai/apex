import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs/promises";
import path from "path";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";

import { addMemory, getMemory, listMemories } from "./index";

let tmpDir: string;

function memoriesDir() {
  return path.join(tmpDir, "memories");
}

describe("memory system", () => {
  beforeEach(() => {
    tmpDir = mkdtempSync(path.join(tmpdir(), "memory-test-"));
    process.env.PENSAR_DATA_DIR = tmpDir;
  });

  afterEach(() => {
    delete process.env.PENSAR_DATA_DIR;
    rmSync(tmpDir, { recursive: true, force: true });
  });

  // -------------------------------------------------------------------------
  // addMemory
  // -------------------------------------------------------------------------

  describe("addMemory", () => {
    it("creates a memory and returns it with an id", async () => {
      const mem = await addMemory({
        title: "SQL Injection Cheatsheet",
        content: "Use UNION SELECT to extract data",
        tags: ["sqli", "cheatsheet"],
      });

      expect(mem.id).toMatch(/^sql-injection-cheatsheet-/);
      expect(mem.category).toBe("general");
      expect(mem.title).toBe("SQL Injection Cheatsheet");
      expect(mem.content).toBe("Use UNION SELECT to extract data");
      expect(mem.tags).toEqual(["sqli", "cheatsheet"]);
      expect(mem.createdAt).toBeTruthy();
      expect(mem.updatedAt).toBeTruthy();
    });

    it("defaults category to general when omitted", async () => {
      const mem = await addMemory({ title: "Catch all", content: "data" });
      expect(mem.category).toBe("general");

      const onDisk = path.join(memoriesDir(), "general", `${mem.id}.json`);
      const raw = await fs.readFile(onDisk, "utf-8");
      expect(JSON.parse(raw).category).toBe("general");
    });

    it("stores app memories under the app subdirectory", async () => {
      const mem = await addMemory({
        title: "App note",
        content: "some note",
        category: "app",
      });
      expect(mem.category).toBe("app");

      const onDisk = path.join(memoriesDir(), "app", `${mem.id}.json`);
      const raw = await fs.readFile(onDisk, "utf-8");
      expect(JSON.parse(raw).category).toBe("app");
    });

    it("stores framework memories under the framework subdirectory", async () => {
      const mem = await addMemory({
        title: "Rails trick",
        content: "mass assignment",
        category: "framework",
      });
      expect(mem.category).toBe("framework");

      const onDisk = path.join(memoriesDir(), "framework", `${mem.id}.json`);
      const raw = await fs.readFile(onDisk, "utf-8");
      expect(JSON.parse(raw).category).toBe("framework");
    });

    it("defaults tags to an empty array", async () => {
      const mem = await addMemory({ title: "No tags", content: "content" });
      expect(mem.tags).toEqual([]);
    });

    it("generates unique ids for duplicate titles", async () => {
      const mem1 = await addMemory({ title: "Dup", content: "a" });
      await new Promise((r) => setTimeout(r, 10));
      const mem2 = await addMemory({ title: "Dup", content: "b" });
      expect(mem1.id).not.toBe(mem2.id);
    });
  });

  // -------------------------------------------------------------------------
  // getMemory
  // -------------------------------------------------------------------------

  describe("getMemory", () => {
    it("retrieves a stored memory by category and id", async () => {
      const created = await addMemory({
        title: "XSS Patterns",
        content: "<script>alert(1)</script>",
        category: "app",
        tags: ["xss"],
      });

      const fetched = await getMemory("app", created.id);
      expect(fetched).not.toBeNull();
      expect(fetched!.id).toBe(created.id);
      expect(fetched!.category).toBe("app");
      expect(fetched!.content).toBe("<script>alert(1)</script>");
      expect(fetched!.tags).toEqual(["xss"]);
    });

    it("returns null for a non-existent id", async () => {
      const result = await getMemory("general", "does-not-exist-abc123");
      expect(result).toBeNull();
    });

    it("returns null when category does not match", async () => {
      const created = await addMemory({
        title: "Stored in app",
        content: "data",
        category: "app",
      });
      const result = await getMemory("framework", created.id);
      expect(result).toBeNull();
    });

    it("rejects ids with path traversal sequences", async () => {
      await expect(getMemory("general", "../../config")).rejects.toThrow(
        "Invalid memory id: contains path traversal characters",
      );
      await expect(getMemory("general", "foo/bar")).rejects.toThrow(
        "Invalid memory id: contains path traversal characters",
      );
      await expect(getMemory("general", "foo\\bar")).rejects.toThrow(
        "Invalid memory id: contains path traversal characters",
      );
      await expect(getMemory("general", "..")).rejects.toThrow(
        "Invalid memory id: contains path traversal characters",
      );
    });
  });

  // -------------------------------------------------------------------------
  // listMemories
  // -------------------------------------------------------------------------

  describe("listMemories", () => {
    it("returns an empty array when no memories exist", async () => {
      const result = await listMemories();
      expect(result).toEqual([]);
    });

    it("lists all memories across categories", async () => {
      await addMemory({
        title: "App mem",
        content: "c1",
        category: "app",
      });
      await addMemory({
        title: "Framework mem",
        content: "c2",
        category: "framework",
      });
      await addMemory({ title: "General mem", content: "c3" });

      const list = await listMemories();
      expect(list).toHaveLength(3);
      const categories = list.map((m) => m.category).sort();
      expect(categories).toEqual(["app", "framework", "general"]);
    });

    it("filters by category", async () => {
      await addMemory({
        title: "App1",
        content: "c1",
        category: "app",
      });
      await addMemory({
        title: "Framework1",
        content: "c2",
        category: "framework",
      });
      await addMemory({ title: "General1", content: "c3" });

      const appOnly = await listMemories({ category: "app" });
      expect(appOnly).toHaveLength(1);
      expect(appOnly[0]!.category).toBe("app");

      const fwOnly = await listMemories({ category: "framework" });
      expect(fwOnly).toHaveLength(1);
      expect(fwOnly[0]!.category).toBe("framework");
    });

    it("filters by tag", async () => {
      await addMemory({
        title: "Tagged",
        content: "c1",
        tags: ["important"],
      });
      await addMemory({ title: "Other", content: "c2", tags: ["misc"] });

      const filtered = await listMemories({ tag: "important" });
      expect(filtered).toHaveLength(1);
      expect(filtered[0]!.title).toBe("Tagged");
    });

    it("combines category and tag filters", async () => {
      await addMemory({
        title: "App tagged",
        content: "c1",
        category: "app",
        tags: ["vuln"],
      });
      await addMemory({
        title: "App other",
        content: "c2",
        category: "app",
        tags: ["misc"],
      });
      await addMemory({
        title: "General tagged",
        content: "c3",
        tags: ["vuln"],
      });

      const result = await listMemories({ category: "app", tag: "vuln" });
      expect(result).toHaveLength(1);
      expect(result[0]!.title).toBe("App tagged");
    });

    it("includes category in summaries", async () => {
      await addMemory({
        title: "Test",
        content: "c",
        category: "framework",
      });

      const list = await listMemories();
      expect(list[0]!.category).toBe("framework");
      expect(list[0]).not.toHaveProperty("content");
    });

    it("returns results sorted most recent first", async () => {
      await addMemory({ title: "Older", content: "c1" });
      await new Promise((r) => setTimeout(r, 10));
      await addMemory({ title: "Newer", content: "c2" });

      const list = await listMemories();
      expect(list).toHaveLength(2);
      expect(list[0]!.title).toBe("Newer");
      expect(list[1]!.title).toBe("Older");
    });
  });
});
