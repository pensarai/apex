#!/usr/bin/env bun
/**
 * Fails when a manifest declares a dependency by anything other than an exact
 * version, so every version change is an explicit, reviewable diff.
 *
 * A range such as `^1.2.3` lets `bun add`, `bun update` or a regenerated lockfile
 * pull a release nobody chose. The lockfile pins what CI installs; this pins
 * what the manifest asks for.
 *
 * Accepted:
 *   - an exact version: `1.2.3`, `1.2.3-beta.1`
 *   - `workspace:*`, required for this repository's own workspace packages.
 *     `*` would also match a package of the same name on the public registry.
 *   - an alias to an exact version: `npm:typescript@7.0.2`
 *
 * Checked sections: `dependencies`, `devDependencies`, `optionalDependencies`
 * and `overrides`. `peerDependencies` are ranges by design and are not checked.
 *
 * Run `bun run check:dependency-pins`. Bun-only APIs stay inside the CLI
 * functions so the module imports under vitest for its unit test.
 */
import { join, resolve } from "node:path";

export interface Manifest {
  /** Path relative to the repo root, e.g. `console/package.json`. */
  path: string;
  pkg: { name?: string } & Record<string, unknown>;
}

export interface Violation {
  path: string;
  section: string;
  name: string;
  spec: string;
  fix: string;
}

const SECTIONS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "overrides",
] as const;

const EXACT = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;
const ALIAS = /^npm:(@[^/@]+\/)?[^/@]+@(.+)$/;

function isExact(spec: string): boolean {
  if (EXACT.test(spec)) return true;
  const alias = ALIAS.exec(spec);
  return alias !== null && EXACT.test(alias[2]!);
}

/** Every declared dependency that is not an exact version or a workspace link. */
export function findUnpinned(manifests: Manifest[]): Violation[] {
  const workspaceNames = new Set<string>();
  for (const { pkg } of manifests) {
    if (typeof pkg.name === "string") workspaceNames.add(pkg.name);
  }

  const violations: Violation[] = [];
  for (const { path, pkg } of manifests) {
    for (const section of SECTIONS) {
      const entries = pkg[section];
      if (entries === undefined) continue;
      if (typeof entries !== "object" || entries === null) {
        throw new Error(`${path}: "${section}" is not an object`);
      }
      for (const [name, spec] of Object.entries(entries)) {
        if (typeof spec !== "string") {
          // A nested override (`{ "parent": { "child": "1.0.0" } }`) cannot be
          // verified here, so it is rejected rather than skipped.
          violations.push({
            path,
            section,
            name,
            spec: JSON.stringify(spec),
            fix: 'use a flat `"name": "<exact version>"` entry',
          });
          continue;
        }
        const internal = section !== "overrides" && workspaceNames.has(name);
        if (internal) {
          if (spec !== "workspace:*") {
            violations.push({
              path,
              section,
              name,
              spec,
              fix: "use `workspace:*`",
            });
          }
          continue;
        }
        if (!isExact(spec)) {
          violations.push({
            path,
            section,
            name,
            spec,
            fix: "use the exact version from bun.lock",
          });
        }
      }
    }
  }
  return violations.sort(
    (a, b) => a.path.localeCompare(b.path) || a.name.localeCompare(b.name),
  );
}

/** `exact = true` under `[install]`, so `bun add` writes an exact version. */
export function bunfigWritesExact(bunfig: string): boolean {
  let section = "";
  for (const raw of bunfig.split("\n")) {
    const line = raw.split("#")[0]!.trim();
    const header = /^\[(.+)\]$/.exec(line);
    if (header) section = header[1]!.trim();
    else if (section === "install" && /^exact\s*=\s*true$/.test(line))
      return true;
  }
  return false;
}

// --- CLI (Bun-only below this line) -----------------------------------------

async function collectManifests(root: string): Promise<Manifest[]> {
  const glob = new Bun.Glob("**/package.json");
  const out: Manifest[] = [];
  for await (const rel of glob.scan({ cwd: root, dot: false })) {
    if (rel.includes("node_modules/")) continue;
    out.push({
      path: rel,
      pkg: JSON.parse(await Bun.file(join(root, rel)).text()),
    });
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

async function main() {
  const root = resolve(import.meta.dir, "..");
  const manifests = await collectManifests(root);
  const violations = findUnpinned(manifests);
  const exact = bunfigWritesExact(
    await Bun.file(join(root, "bunfig.toml")).text(),
  );

  if (violations.length === 0 && exact) {
    console.log(
      `check-dependency-pins: OK — ${manifests.length} manifests declare exact versions.`,
    );
    return;
  }

  if (violations.length > 0) {
    console.error(
      `check-dependency-pins: ${violations.length} dependency(ies) are not pinned to an exact version:\n`,
    );
    for (const v of violations) {
      console.error(
        `  - ${v.path} ${v.section}.${v.name}: "${v.spec}" — ${v.fix}`,
      );
    }
    console.error(
      "\nA range lets an install pull a release nobody reviewed. Declare the exact version" +
        "\n(`bun add <pkg>` writes one) and run `bun install`.",
    );
  }
  if (!exact) {
    console.error(
      "check-dependency-pins: bunfig.toml must set `exact = true` under [install], or `bun add` writes ranges.",
    );
  }
  process.exit(1);
}

if (import.meta.main) await main();
