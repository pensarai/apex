import { existsSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";

import { type EndpointInfo, type MapResult, map } from "@pensar/surface";

import type { ConsolidatedEndpoint, FrameworkId } from "./types";

// Mirrors `@pensar/surface`'s `DEP_FILENAMES`; package.json first since it
// resolves quickest in the common case.
const DEP_FILENAMES = [
  "package.json",
  "requirements.txt",
  "pyproject.toml",
  "setup.py",
  "Pipfile",
  "go.mod",
  "Cargo.toml",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "Gemfile",
  "composer.json",
];

/**
 * Walk up from `appPath` toward `repoRoot` to the nearest directory holding a
 * dependency manifest. Surface's framework detection reads dep files at the
 * scan dir, so pointing it at a subdir without one (e.g. Next.js `app/`)
 * returns `frameworks: []`. Bounded by `repoRoot`. Returns `appPath` if no
 * manifest is found — surface will then trigger the fallback gate.
 */
export function findDependencyRoot(appPath: string, repoRoot: string): string {
  const absApp = resolve(appPath);
  const absRoot = resolve(repoRoot);

  let current = absApp;
  while (true) {
    for (const f of DEP_FILENAMES) {
      if (existsSync(resolve(current, f))) {
        return current;
      }
    }
    if (current === absRoot) break;
    const parent = dirname(current);
    if (parent === current) break;
    if (!parent.startsWith(absRoot)) break;
    current = parent;
  }
  return absApp;
}

export type MapAppResult =
  | { mode: "fallback"; reason: string }
  | {
      mode: "surface";
      endpoints: ConsolidatedEndpoint[];
      frameworks: FrameworkId[];
    };

export type FallbackDecision =
  | { fallback: true; reason: string }
  | { fallback: false };

export function shouldFallback(result: MapResult): FallbackDecision {
  if (result.frameworks.length === 0) {
    return { fallback: true, reason: "no frameworks detected" };
  }
  if (result.endpoints.length === 0) {
    return { fallback: true, reason: "frameworks detected but zero endpoints" };
  }
  return { fallback: false };
}

/**
 * Group surface's per-`(method, path)` rows into one record per `(file, path)`.
 * Methods, handlers, and auth signals are unioned; `framework`, `line`, and
 * `internal` come from the first row seen for the route.
 */
export function consolidateBySameRoute(
  endpoints: EndpointInfo[],
): ConsolidatedEndpoint[] {
  const groups = new Map<string, ConsolidatedEndpoint>();
  const handlerSets = new Map<string, Set<string>>();

  for (const ep of endpoints) {
    const key = `${ep.file}\u0000${ep.path}`;
    const existing = groups.get(key);
    if (!existing) {
      groups.set(key, {
        method: [ep.method],
        path: ep.path,
        handler: ep.handler,
        file: ep.file,
        line: ep.line,
        framework: ep.framework,
        kind: ep.kind,
        auth: [...ep.auth],
        internal: ep.internal,
      });
      handlerSets.set(key, new Set(ep.handler ? [ep.handler] : []));
      continue;
    }

    if (!existing.method.includes(ep.method)) {
      existing.method.push(ep.method);
    }

    if (ep.handler) {
      const handlers = handlerSets.get(key)!;
      if (!handlers.has(ep.handler)) {
        handlers.add(ep.handler);
        existing.handler = existing.handler
          ? `${existing.handler}, ${ep.handler}`
          : ep.handler;
      }
    }

    for (const a of ep.auth) {
      if (!existing.auth.includes(a)) {
        existing.auth.push(a);
      }
    }
  }

  return [...groups.values()];
}

/**
 * Rewrite each endpoint's `file` to be relative to `repoRoot` rather than
 * the directory surface scanned. Required because downstream consumers
 * (the endpoint-documentation agent's `read_file`, the persisted
 * `document_endpoint` records) resolve `file` against the workflow's
 * `codebasePath`, which is `repoRoot`. Idempotent when `scanRoot === repoRoot`.
 */
export function rebaseFileToRepoRoot(
  endpoints: EndpointInfo[],
  scanRoot: string,
  repoRoot: string,
): EndpointInfo[] {
  const absScan = resolve(scanRoot);
  const absRoot = resolve(repoRoot);
  if (absScan === absRoot) return endpoints;
  return endpoints.map((ep) => ({
    ...ep,
    file: relative(absRoot, resolve(absScan, ep.file)),
  }));
}

/**
 * Keep only endpoints whose `file` resolves under `appPath`. Surface emits
 * `file` relative to the scan root, so resolve against that. Without this,
 * a climb-up scan returns the union of every sibling app's routes — see
 * `mapAppWithSurface` below.
 */
export function scopeEndpointsToApp(
  endpoints: EndpointInfo[],
  scanRoot: string,
  appPath: string,
): EndpointInfo[] {
  const absApp = resolve(appPath);
  const absScan = resolve(scanRoot);
  if (absApp === absScan) return endpoints;
  const prefix = absApp + sep;
  return endpoints.filter((ep) => {
    const epAbs = resolve(absScan, ep.file);
    return epAbs === absApp || epAbs.startsWith(prefix);
  });
}

/**
 * Run surface scoped to `appPath`, apply the fallback gate, then consolidate.
 *
 * Decision sequence:
 *   1. If `appPath === repoRoot`, force fallback. Phase 1 didn't disambiguate
 *      and a no-op filter would silently re-attribute every endpoint to a
 *      single app.
 *   2. Try a narrow `map(appPath)` first. When `appPath` has its own dep
 *      manifest this is the correct, fastest answer AND avoids surface's
 *      global `(method, path)` dedup eating routes across siblings.
 *   3. Otherwise climb to a parent dep manifest (so surface can detect the
 *      framework), scan there, then filter results back to `appPath`'s
 *      subtree. If nothing survives, fall back to the legacy CodeAgent path.
 *
 * Endpoints pass through with their raw surface fields — `kind` is the
 * authoritative page/api signal. Apex's storage convention (method="PAGE"
 * for pages) is applied at the document_endpoint write boundary, not here.
 */
export function mapAppWithSurface(
  appPath: string,
  repoRoot: string,
): MapAppResult {
  const absApp = resolve(appPath);
  const absRoot = resolve(repoRoot);

  // (1) Force fallback when the app's location is the repo root itself.
  if (absApp === absRoot) {
    return {
      mode: "fallback",
      reason: "app.location is repo root — cannot scope",
    };
  }

  // (2) Narrow scan first. If `appPath` carries its own manifest surface
  //     finds the framework here and the result is already scoped — no
  //     filter needed, no cross-sibling dedup hazard.
  const narrow = map(absApp, { includeInternal: false });
  if (narrow.frameworks.length > 0 && narrow.endpoints.all.length > 0) {
    const rebased = rebaseFileToRepoRoot(narrow.endpoints.all, absApp, absRoot);
    return {
      mode: "surface",
      endpoints: consolidateBySameRoute(rebased),
      frameworks: narrow.frameworks,
    };
  }

  // (3) Climb to the nearest parent manifest, scan there, then filter back
  //     to `appPath`'s subtree.
  const scanRoot = findDependencyRoot(appPath, repoRoot);
  if (resolve(scanRoot) === absApp) {
    // No manifest at appPath and none above it. Narrow already returned
    // empty so there's nothing more surface can do.
    return { mode: "fallback", reason: "no frameworks detected" };
  }

  const wide = map(scanRoot, { includeInternal: false });
  if (wide.frameworks.length === 0) {
    return { mode: "fallback", reason: "no frameworks detected" };
  }

  const scoped = scopeEndpointsToApp(wide.endpoints.all, scanRoot, appPath);
  if (scoped.length === 0) {
    return {
      mode: "fallback",
      reason: "frameworks detected but zero endpoints in app.location",
    };
  }

  const rebased = rebaseFileToRepoRoot(scoped, scanRoot, absRoot);
  return {
    mode: "surface",
    endpoints: consolidateBySameRoute(rebased),
    frameworks: wide.frameworks,
  };
}
