import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir, realpath, stat } from "node:fs/promises";
import { basename, isAbsolute, relative, resolve, sep } from "node:path";
import { globIterate } from "glob";
import type {
  SourceProvider,
  SourceReadInput,
  SourceRequestOptions,
  SourceSearchInput,
  SourceSearchResult,
  SourceTreeInput,
} from "./source";

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_SEARCH_FILES = 20_000;

export class LocalSourceProvider implements SourceProvider {
  constructor(private readonly rootPath: string) {}

  private async resolvePath(path: string) {
    if (
      isAbsolute(path) ||
      path.includes("\\") ||
      path.split("/").includes("..")
    ) {
      throw new Error("Source paths must be repository-relative");
    }
    const root = await realpath(this.rootPath);
    const target = await realpath(resolve(root, path));
    const rel = relative(root, target);
    if (isAbsolute(rel) || rel === ".." || rel.startsWith(`..${sep}`)) {
      throw new Error("Source path is outside the configured repository");
    }
    return { root, target };
  }

  private async read(path: string, options?: SourceRequestOptions) {
    options?.signal?.throwIfAborted();
    const { target } = await this.resolvePath(path);
    const file = await open(
      target,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    try {
      const info = await file.stat();
      if (!info.isFile()) throw new Error("Source path is not a regular file");
      if (info.size > MAX_FILE_BYTES) return null;
      const buffer = Buffer.alloc(info.size + 1);
      let length = 0;
      while (length < buffer.length) {
        options?.signal?.throwIfAborted();
        const { bytesRead } = await file.read(
          buffer,
          length,
          buffer.length - length,
          length,
        );
        if (!bytesRead) break;
        length += bytesRead;
      }
      if (length > info.size)
        throw new Error("Source file changed while reading; retry");
      const bytes = buffer.subarray(0, length);
      if (bytes.includes(0)) return null;
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch {
        return null;
      }
    } finally {
      await file.close();
    }
  }

  async describe(options?: SourceRequestOptions) {
    options?.signal?.throwIfAborted();
    const { root } = await this.resolvePath(".");
    return {
      name: basename(root),
      kind: "local" as const,
      description:
        "Mutable local working tree. Search excludes .git, node_modules, and symlinks; reads are limited to 2 MiB UTF-8 files. Live deployment revision is unknown.",
    };
  }

  async listTree(input: SourceTreeInput, options?: SourceRequestOptions) {
    options?.signal?.throwIfAborted();
    const { target } = await this.resolvePath(input.path);
    const children = (await readdir(target, { withFileTypes: true }))
      .filter((entry) => entry.isFile() || entry.isDirectory())
      .sort((a, b) => a.name.localeCompare(b.name));
    const end = input.offset + input.limit;
    return {
      entries: children.slice(input.offset, end).map((entry) => ({
        path:
          input.path === "." || input.path === ""
            ? entry.name
            : `${input.path}/${entry.name}`,
        kind: entry.isDirectory() ? ("directory" as const) : ("file" as const),
      })),
      nextOffset: end < children.length ? end : null,
    };
  }

  async readFile(input: SourceReadInput, options?: SourceRequestOptions) {
    const content = await this.read(input.path, options);
    if (content === null)
      throw new Error("Source file exceeds 2 MiB or is not UTF-8 text");
    const version = createHash("sha256").update(content).digest("hex");
    if (input.version && input.version !== version) {
      throw new Error("Source file changed; restart reading from offset 0");
    }
    if (input.offset > content.length)
      throw new Error("Source offset is outside the file");
    const end = Math.min(input.offset + input.limit, content.length);
    return {
      path: input.path,
      content: content.slice(input.offset, end),
      version,
      offset: input.offset,
      nextOffset: end < content.length ? end : null,
      firstLine: content.slice(0, input.offset).split("\n").length,
    };
  }

  async search(
    input: SourceSearchInput,
    options?: SourceRequestOptions,
  ): Promise<SourceSearchResult> {
    options?.signal?.throwIfAborted();
    const { root, target } = await this.resolvePath(input.path);
    const files = (await stat(target)).isDirectory()
      ? globIterate("**/*", {
          cwd: target,
          nodir: true,
          dot: true,
          follow: false,
          ignore: ["**/.git/**", "**/node_modules/**"],
          signal: options?.signal,
          absolute: true,
        })
      : [target];
    const matches: SourceSearchResult["matches"] = [];
    let scanned = 0;
    let skippedFiles = 0;
    for await (const file of files) {
      options?.signal?.throwIfAborted();
      if (++scanned > MAX_SEARCH_FILES)
        return { matches, truncated: true, skippedFiles };
      if ((await lstat(file)).isSymbolicLink()) {
        skippedFiles++;
        continue;
      }
      const path = relative(root, file).split(sep).join("/");
      const content = await this.read(path, options);
      if (content === null) {
        skippedFiles++;
        continue;
      }
      const lines = content.split("\n");
      for (const [index, line] of lines.entries()) {
        const position = line.indexOf(input.query);
        if (position < 0) continue;
        if (matches.length >= input.limit)
          return { matches, truncated: true, skippedFiles };
        const start = Math.max(0, position - 100);
        matches.push({
          path,
          line: index + 1,
          text: line.slice(start, start + 1200),
        });
      }
    }
    return { matches, truncated: false, skippedFiles };
  }
}
