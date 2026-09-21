#!/usr/bin/env bun
/**
 * Resolution test for the package.json `exports` map (design §3.6). Imports
 * every subpath through the package specifier itself — the same resolution
 * path a real consumer (console) goes through — plus a sample deep `src/**`
 * passthrough import, which must keep working until console's migration is
 * done. Run after `bun run build:lib`.
 */
import { existsSync } from "node:fs";
import pkg from "../package.json";

const PKG = pkg.name;
const failures: string[] = [];

for (const [subpath, condition] of Object.entries(pkg.exports)) {
  if (subpath === "./src/*") continue;
  const specifier = subpath === "." ? PKG : `${PKG}/${subpath.slice(2)}`;
  try {
    const mod = await import(specifier);
    if (!mod || typeof mod !== "object") {
      failures.push(`${specifier}: resolved but not a module object`);
    }
  } catch (e) {
    failures.push(`${specifier}: ${(e as Error).message}`);
  }

  const typesPath = typeof condition === "object" ? condition.types : undefined;
  if (typesPath && !existsSync(typesPath)) {
    failures.push(
      `${specifier}: types condition points to missing file ${typesPath}`,
    );
  }
}

// The migration passthrough: deep src/** imports (as console spells them
// today, with no extension) must still resolve.
try {
  await import(`${PKG}/src/core/eventBus`);
} catch (e) {
  failures.push(
    `${PKG}/src/core/eventBus (passthrough): ${(e as Error).message}`,
  );
}

if (failures.length > 0) {
  console.error(`[verify-lib-exports] ${failures.length} failure(s):`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}

console.log(
  `[verify-lib-exports] ${Object.keys(pkg.exports).length - 1} exports subpaths + src/* passthrough resolved`,
);
