import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import os from "node:os";
import { join, relative } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { MAX_ATTACHMENT_BYTES } from "./attachments";
import { attachFilesToPrompt, decodeAttachments } from "./attachments-host";

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(os.tmpdir(), "apex-attachments-"));
});
afterEach(async () => rm(root, { recursive: true, force: true }));

it("retains binary bytes and separate copies for duplicate filenames", async () => {
  const bytes = Buffer.from([0, 255, 1, 128]);
  const files = decodeAttachments([
    { name: "report.pdf", base64: bytes.toString("base64") },
    { name: "report.pdf", base64: Buffer.from("second").toString("base64") },
    { name: "empty.txt", base64: "" },
  ]);
  const prompt = await attachFilesToPrompt(root, "Compare these", files);
  const [directory] = await readdir(root);
  expect(prompt).toContain("Compare these");
  const first = join(root, directory, "1-report.pdf");
  expect(prompt).toContain(JSON.stringify(first));
  expect(await readFile(first)).toEqual(bytes);
  expect(await readFile(join(root, directory, "2-report.pdf"), "utf8")).toBe(
    "second",
  );
  expect((await readFile(join(root, directory, "3-empty.txt"))).length).toBe(0);
});

it("keeps untrusted filenames inside the session and quotes their prompt references", async () => {
  const name = "../../file\nname\\report.txt";
  const prompt = await attachFilesToPrompt(
    root,
    "",
    decodeAttachments([{ name, base64: "" }]),
  );
  expect(prompt).toContain("Please analyze the attached files.");
  expect(prompt).toContain(JSON.stringify(name));
  const [directory] = await readdir(root);
  const [filename] = await readdir(join(root, directory));
  const path = join(root, directory, filename);
  expect(relative(root, path).startsWith("..")).toBe(false);
  expect(prompt).toContain(JSON.stringify(path));
  expect(filename).not.toMatch(/[/\\\n]/);
});

it("rejects invalid and oversized batches before writing files", async () => {
  expect(() =>
    decodeAttachments([{ name: "file", base64: "not base64!" }]),
  ).toThrow("encoding");
  expect(() =>
    decodeAttachments(
      Array.from({ length: 11 }, () => ({ name: "file", base64: "" })),
    ),
  ).toThrow("10 files");
  const data = Buffer.alloc(MAX_ATTACHMENT_BYTES / 2 + 1).toString("base64");
  expect(() =>
    decodeAttachments([
      { name: "a", base64: data },
      { name: "b", base64: data },
    ]),
  ).toThrow("20 MB");
  expect(await readdir(root)).toEqual([]);
});

it("leaves ordinary messages and the session directory untouched", async () => {
  expect(await attachFilesToPrompt(root, "Hello", [])).toBe("Hello");
  expect(await readdir(root)).toEqual([]);
});
