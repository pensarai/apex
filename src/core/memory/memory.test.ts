import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs/promises";
import path from "path";
import os from "os";

import { addMemory, getMemory, listMemories } from "./index";

const memoriesDir = path.join(os.homedir(), ".pensar", "memories");

async function cleanMemories() {
  try {
    await fs.rm(memoriesDir, { recursive: true, force: true });
  } catch {
    // noop — dir may not exist yet
  }
}

describe("memory system", () => {
  beforeEach(async () => {
    await cleanMemories();
  });

  afterEach(async () => {
    await cleanMemories();
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
      expect(mem.title).toBe("SQL Injection Cheatsheet");
      expect(mem.content).toBe("Use UNION SELECT to extract data");
      expect(mem.tags).toEqual(["sqli", "cheatsheet"]);
      expect(mem.createdAt).toBeTruthy();
      expect(mem.updatedAt).toBeTruthy();
    });

    it("persists memory to disk as JSON", async () => {
      const mem = await addMemory({
        title: "Test persist",
        content: "Some content",
      });

      const filePath = path.join(memoriesDir, `${mem.id}.json`);
      const raw = await fs.readFile(filePath, "utf-8");
      const parsed = JSON.parse(raw);
      expect(parsed.title).toBe("Test persist");
      expect(parsed.content).toBe("Some content");
    });

    it("defaults tags to an empty array", async () => {
      const mem = await addMemory({
        title: "No tags",
        content: "content",
      });
      expect(mem.tags).toEqual([]);
    });

    it("generates unique ids for duplicate titles", async () => {
      const mem1 = await addMemory({ title: "Dup", content: "a" });
      // small delay to ensure different timestamp
      await new Promise((r) => setTimeout(r, 10));
      const mem2 = await addMemory({ title: "Dup", content: "b" });
      expect(mem1.id).not.toBe(mem2.id);
    });
  });

  // -------------------------------------------------------------------------
  // getMemory
  // -------------------------------------------------------------------------

  describe("getMemory", () => {
    it("retrieves a stored memory by id", async () => {
      const created = await addMemory({
        title: "XSS Patterns",
        content: "<script>alert(1)</script>",
        tags: ["xss"],
      });

      const fetched = await getMemory(created.id);
      expect(fetched).not.toBeNull();
      expect(fetched!.id).toBe(created.id);
      expect(fetched!.content).toBe("<script>alert(1)</script>");
      expect(fetched!.tags).toEqual(["xss"]);
    });

    it("returns null for a non-existent id", async () => {
      const result = await getMemory("does-not-exist-abc123");
      expect(result).toBeNull();
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

    it("lists all memories with summaries", async () => {
      await addMemory({ title: "First", content: "c1", tags: ["a"] });
      await addMemory({ title: "Second", content: "c2", tags: ["b"] });

      const list = await listMemories();
      expect(list).toHaveLength(2);
      for (const item of list) {
        expect(item).toHaveProperty("id");
        expect(item).toHaveProperty("title");
        expect(item).toHaveProperty("tags");
        expect(item).toHaveProperty("createdAt");
        expect(item).not.toHaveProperty("content");
      }
    });

    it("filters by tag", async () => {
      await addMemory({
        title: "Tagged",
        content: "c1",
        tags: ["important"],
      });
      await addMemory({ title: "Other", content: "c2", tags: ["misc"] });

      const filtered = await listMemories("important");
      expect(filtered).toHaveLength(1);
      expect(filtered[0]!.title).toBe("Tagged");
    });

    it("returns results sorted most recent first", async () => {
      const m1 = await addMemory({ title: "Older", content: "c1" });
      await new Promise((r) => setTimeout(r, 10));
      const m2 = await addMemory({ title: "Newer", content: "c2" });

      const list = await listMemories();
      expect(list).toHaveLength(2);
      expect(list[0]!.title).toBe("Newer");
      expect(list[1]!.title).toBe("Older");
    });
  });
});
