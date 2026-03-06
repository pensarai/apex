import os from "os";
import path from "path";
import fs from "fs/promises";
import { readdir } from "fs/promises";

import z from "zod";
import { NamedError } from "../../util/errors";
import * as Lock from "../../util/lock";

export const NotFoundError = NamedError.create(
  "NotFoundError",
  z.object({
    message: z.string(),
  }),
);

function getBaseDir(): string {
  return process.env.PENSAR_DATA_DIR ?? path.join(os.homedir(), ".pensar");
}

export async function remove(key: string[]) {
  const dir = getBaseDir();
  const target = path.join(dir, ...key) + ".json";
  return withErrorHandling(async () => {
    await fs.unlink(target).catch(() => {});
  });
}

export async function locate(key: string[], ext?: string) {
  const dir = getBaseDir();
  const target = path.join(dir, ...key) + (ext ? ext : ".json");
  return target;
}

export async function write<T>(key: string[], content: T, ext?: string) {
  const dir = getBaseDir();
  const target = path.join(dir, ...key) + (ext ? ext : ".json");
  return withErrorHandling(async () => {
    using _ = await Lock.write(target);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, JSON.stringify(content, null, 2), "utf-8");
  });
}

export async function createDir(key: string[]) {
  const dir = getBaseDir();
  const target = path.join(dir, ...key);
  return withErrorHandling(async () => {
    using _ = await Lock.write(target);
    await fs.mkdir(target, { recursive: true });
  });
}

/**
 * Write raw content (non-JSON) to a file within the .pensar directory
 */
export async function writeRaw(key: string[], content: string) {
  const dir = getBaseDir();
  const target = path.join(dir, ...key);
  return withErrorHandling(async () => {
    using _ = await Lock.write(target);
    const parentDir = path.dirname(target);
    await fs.mkdir(parentDir, { recursive: true });
    await fs.writeFile(target, content, "utf-8");
  });
}

/**
 * Append raw content to a file within the .pensar directory
 */
export async function appendRaw(key: string[], content: string) {
  const dir = getBaseDir();
  const target = path.join(dir, ...key);
  return withErrorHandling(async () => {
    using _ = await Lock.write(target);
    const parentDir = path.dirname(target);
    await fs.mkdir(parentDir, { recursive: true });
    await fs.appendFile(target, content);
  });
}

export async function read<T>(key: string[], ext?: string) {
  const dir = getBaseDir();
  const target = path.join(dir, ...key) + (ext ? ext : ".json");
  return withErrorHandling(async () => {
    using _ = await Lock.read(target);
    const text = await fs.readFile(target, "utf-8");
    const result = ext ? text : JSON.parse(text);
    return result as T;
  });
}

export async function update<T>(
  key: string[],
  fn: (draft: T) => void,
  ext?: string,
) {
  const dir = getBaseDir();
  const target = path.join(dir, ...key) + (ext ? ext : ".json");
  return withErrorHandling(async () => {
    using _ = await Lock.write(target);
    const text = await fs.readFile(target, "utf-8");
    const content = ext ? text : JSON.parse(text);
    fn(content);
    await fs.writeFile(target, JSON.stringify(content, null, 2), "utf-8");
    return content as T;
  });
}

async function withErrorHandling<T>(body: () => Promise<T>) {
  return body().catch((e) => {
    if (!(e instanceof Error)) throw e;
    const errnoExcpetion = e as NodeJS.ErrnoException;
    if (errnoExcpetion.code === "ENOENT") {
      throw new NotFoundError({
        message: `Resource not found: ${errnoExcpetion.path}`,
      });
    }
    throw e;
  });
}

async function listFilesRecursively(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listFilesRecursively(fullPath)));
    } else {
      files.push(fullPath);
    }
  }
  return files;
}

export async function list(prefix: string[]) {
  const dir = getBaseDir();
  const targetDir = path.join(dir, ...prefix);
  try {
    const files = await listFilesRecursively(targetDir);
    const result = files.map((filePath) => {
      const relativePath = path.relative(targetDir, filePath);
      return [...prefix, ...relativePath.slice(0, -5).split(path.sep)];
    });
    result.sort();
    return result;
  } catch {
    return [];
  }
}
