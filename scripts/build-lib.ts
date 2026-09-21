#!/usr/bin/env bun
/**
 * Library build (design §3.6): emits ESM + .d.ts for every package.json
 * `exports` subpath under build/lib, mirroring src/ 1:1. Entrypoints are
 * derived from package.json so it can't drift from the exports map.
 * Separate from `bun run build` (the CLI bundle) — that script still
 * `rm -rf build`s the whole dir, so run `build:lib` after `build`, not
 * before.
 */
import { rm } from "node:fs/promises";
import { spawnSync } from "bun";
import pkg from "../package.json";

const OUTDIR = "build/lib";

function libEntrypoints(): string[] {
  const entries = new Set<string>();
  for (const value of Object.values(pkg.exports)) {
    if (typeof value !== "object" || value === null) continue;
    const importPath = (value as { import?: string }).import;
    if (!importPath?.startsWith(`./${OUTDIR}/`)) continue;
    const src = importPath.slice(`./${OUTDIR}/`.length).replace(/\.js$/, ".ts");
    entries.add(`src/${src}`);
  }
  return [...entries];
}

const entrypoints = libEntrypoints();
if (entrypoints.length === 0) {
  throw new Error("no library entrypoints found in package.json exports");
}

// Clear both the output dir and its incremental cache together — an output
// wipe (e.g. from `bun run build`'s `rm -rf build`) with a stale
// .tsbuildinfo left behind makes tsc believe files are already emitted and
// skip re-emitting them.
await rm(OUTDIR, { recursive: true, force: true });
await rm(".cache/tsc.lib.tsbuildinfo", { force: true });

const result = await Bun.build({
  entrypoints,
  outdir: OUTDIR,
  root: "src",
  target: "node",
  format: "esm",
  splitting: true,
  packages: "external",
});

if (!result.success) {
  for (const log of result.logs) console.error(log);
  throw new Error("bun build failed for the library entry");
}

const tsc = spawnSync({
  cmd: ["node_modules/.bin/tsc", "-p", "tsconfig.lib.json"],
  stdout: "inherit",
  stderr: "inherit",
});
if (tsc.exitCode !== 0) {
  process.exit(tsc.exitCode ?? 1);
}

console.log(`[build:lib] ${entrypoints.length} entrypoints -> ${OUTDIR}`);
