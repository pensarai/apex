import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  realpath,
  rename,
  unlink,
} from "node:fs/promises";
import path from "node:path";
import { remoteFileOperation } from "./fileWorkspaceRemote";
import type { ToolContext } from "./types";

const MAX_FILE_BYTES = 1024 * 1024;
const localLocks = new Map<string, Promise<void>>();
const sandboxLocks = new WeakMap<object, Map<string, Promise<void>>>();

function paths(ctx: ToolContext) {
  return ctx.sandbox?.type === "windows"
    ? path.win32
    : ctx.sandbox
      ? path.posix
      : path;
}

function contained(root: string, file: string, api: typeof path) {
  const relative = api.relative(root, file);
  return (
    relative !== ".." &&
    !relative.startsWith(`..${api.sep}`) &&
    !api.isAbsolute(relative)
  );
}

function isMissing(error: unknown) {
  return (error as NodeJS.ErrnoException).code === "ENOENT";
}

async function canonicalLocal(file: string): Promise<string> {
  try {
    return await realpath(file);
  } catch (error) {
    if (!isMissing(error)) throw error;
    // A dangling symlink is an existing entry, not a missing creation target.
    const entry = await lstat(file).catch((error: unknown) => {
      if (!isMissing(error)) throw error;
      return undefined;
    });
    if (entry?.isSymbolicLink()) throw new Error(`Dangling symlink: ${file}`);
    const parent = path.dirname(file);
    if (parent === file) throw error;
    return path.join(await canonicalLocal(parent), path.basename(file));
  }
}

async function scopedLocal(ctx: ToolContext, file: string, root?: string) {
  const canonical = await canonicalLocal(file);
  const boundary = root ?? ctx.fileWorkspaceRoot;
  if (boundary && !contained(await canonicalLocal(boundary), canonical, path)) {
    throw new Error(`Path escapes file workspace: ${file}`);
  }
  return canonical;
}

export async function resolveFilePath(
  ctx: ToolContext,
  input: string,
  options: { confineToCwd?: boolean } = {},
): Promise<string> {
  ctx.abortSignal?.throwIfAborted();
  if (!input || input.includes("\0"))
    throw new Error("File path must be nonempty and contain no NUL bytes");
  const api = paths(ctx);
  const base = ctx.fileWorkspaceRoot ?? ctx.agentCwd;
  if (!api.isAbsolute(base))
    throw new Error("File workspace must be an absolute runtime path");
  const file = api.resolve(base, input);
  const root =
    ctx.fileWorkspaceRoot ?? (options.confineToCwd ? ctx.agentCwd : undefined);
  if (ctx.sandbox) {
    const result = await remoteFileOperation(ctx, {
      action: "resolve",
      path: file,
      root,
    });
    if (typeof result.path !== "string")
      throw new Error("Sandbox returned no resolved file path");
    return result.path;
  }
  return scopedLocal(ctx, file, root);
}

function decodeText(bytes: Uint8Array): string {
  if (bytes.includes(0))
    throw new Error("Binary files are not supported by text mutation tools");
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      bytes,
    );
  } catch {
    throw new Error("File is not valid UTF-8 text");
  }
}

async function readLocal(file: string): Promise<string> {
  const handle = await open(
    file,
    constants.O_RDONLY |
      (constants.O_NOFOLLOW ?? 0) |
      (constants.O_NONBLOCK ?? 0),
  );
  try {
    const info = await handle.stat();
    if (!info.isFile()) throw new Error(`Not an ordinary file: ${file}`);
    if (info.size > MAX_FILE_BYTES)
      throw new Error(
        `Text mutation limit is ${MAX_FILE_BYTES} bytes; use a bounded read and a smaller file`,
      );
    const buffer = Buffer.alloc(info.size + 1);
    let captured = 0;
    while (captured < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        captured,
        buffer.length - captured,
        captured,
      );
      if (!bytesRead) break;
      captured += bytesRead;
    }
    if (captured > info.size)
      throw new Error("File grew during read; read it again before editing");
    return decodeText(buffer.subarray(0, captured));
  } finally {
    await handle.close();
  }
}

export async function readWorkspaceFile(
  ctx: ToolContext,
  file: string,
): Promise<string> {
  ctx.abortSignal?.throwIfAborted();
  if (ctx.sandbox) {
    const result = await remoteFileOperation(ctx, {
      action: "read",
      path: file,
    });
    if (typeof result.content !== "string")
      throw new Error("Sandbox returned no file content");
    return decodeText(Buffer.from(result.content, "base64"));
  }
  return readLocal(await scopedLocal(ctx, file));
}

export async function withWorkspaceFileLock<T>(
  ctx: ToolContext,
  file: string,
  operation: () => Promise<T>,
): Promise<T> {
  let locks = localLocks;
  if (ctx.sandbox) {
    const existing = sandboxLocks.get(ctx.sandbox);
    if (existing) locks = existing;
    else {
      locks = new Map();
      sandboxLocks.set(ctx.sandbox, locks);
    }
  }
  const normalized = paths(ctx).normalize(file);
  const key = (
    ctx.sandbox
      ? ctx.sandbox.type === "windows"
      : process.platform === "win32"
  )
    ? normalized.toLowerCase()
    : normalized;
  const previous = locks.get(key) ?? Promise.resolve();
  let release = () => {};
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  locks.set(key, current);
  await previous;
  try {
    ctx.abortSignal?.throwIfAborted();
    return await operation();
  } finally {
    release();
    if (locks.get(key) === current) locks.delete(key);
  }
}

function digest(content: string) {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

export async function writeWorkspaceFile(
  ctx: ToolContext,
  file: string,
  content: string,
  options: { expected?: string | null } = {},
): Promise<void> {
  const bytes = Buffer.from(content, "utf8");
  if (bytes.length > MAX_FILE_BYTES)
    throw new Error(`Text mutation limit is ${MAX_FILE_BYTES} bytes`);
  decodeText(bytes);
  await withWorkspaceFileLock(ctx, file, async () => {
    if (ctx.sandbox) {
      await remoteFileOperation(ctx, {
        action: "write",
        path: file,
        content: bytes.toString("base64"),
        exclusive: options.expected === null,
        expectedHash:
          typeof options.expected === "string"
            ? digest(options.expected)
            : undefined,
      });
      return;
    }
    const target = await scopedLocal(ctx, file);
    const info = await lstat(target).catch((error: unknown) => {
      if (!isMissing(error)) throw error;
      return undefined;
    });
    if (info && !info.isFile())
      throw new Error(`Not an ordinary file: ${target}`);
    if (info && options.expected === null)
      throw new Error(`File already exists: ${target}`);
    if (info && options.expected === undefined) await readLocal(target);
    const checkExpected = async () => {
      if (
        typeof options.expected === "string" &&
        (await readLocal(target)) !== options.expected
      ) {
        throw new Error(
          "File changed since it was read; re-read it and prepare the edit again",
        );
      }
    };
    await checkExpected();
    await mkdir(path.dirname(target), { recursive: true });
    ctx.abortSignal?.throwIfAborted();
    const temporary = path.join(
      path.dirname(target),
      `.${path.basename(target)}.${randomUUID()}.tmp`,
    );
    try {
      const handle = await open(
        temporary,
        "wx",
        info ? info.mode & 0o777 : 0o666,
      );
      try {
        await handle.writeFile(bytes);
        if (info) await handle.chmod(info.mode & 0o777);
      } finally {
        await handle.close();
      }
      await checkExpected();
      ctx.abortSignal?.throwIfAborted();
      if (options.expected === null) await link(temporary, target);
      else await rename(temporary, target);
    } finally {
      await unlink(temporary).catch((error: unknown) => {
        if (!isMissing(error)) throw error;
      });
    }
  });
}

export async function deleteWorkspaceFile(
  ctx: ToolContext,
  file: string,
  options: { expected?: string } = {},
): Promise<void> {
  await withWorkspaceFileLock(ctx, file, async () => {
    if (ctx.sandbox) {
      await remoteFileOperation(ctx, {
        action: "delete",
        path: file,
        expectedHash:
          options.expected === undefined ? undefined : digest(options.expected),
      });
      return;
    }
    const target = await scopedLocal(ctx, file);
    const actual = await readLocal(target);
    if (options.expected !== undefined && actual !== options.expected) {
      throw new Error(
        "File changed since it was read; re-read it before deleting",
      );
    }
    ctx.abortSignal?.throwIfAborted();
    await unlink(target);
  });
}
