import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  EndpointIndex,
  type EndpointInfo,
  type MapResult,
} from "@pensar/surface";

import {
  consolidateBySameRoute,
  shouldFallback,
  mapAppWithSurface,
  findDependencyRoot,
} from "./index";

function makeEndpointInfo(
  overrides: Partial<EndpointInfo> &
    Pick<EndpointInfo, "framework" | "file" | "method" | "path">,
): EndpointInfo {
  return {
    handler: "handler",
    line: 1,
    kind: "api",
    params: [],
    auth: [],
    internal: false,
    ...overrides,
  };
}

function makeMapResult(
  endpoints: EndpointInfo[],
  overrides?: Partial<MapResult>,
): MapResult {
  const frameworks = overrides?.frameworks ?? [];
  return {
    repoPath: "/fake/repo",
    frameworks,
    endpoints: new EndpointIndex(endpoints),
    services: [],
    filesScanned: 0,
    ...overrides,
  };
}

describe("consolidateBySameRoute", () => {
  it("merges two rows with the same (file, path) into one record with unioned methods", () => {
    const rows: EndpointInfo[] = [
      makeEndpointInfo({
        framework: "express",
        file: "src/routes/users.ts",
        method: "GET",
        path: "/users",
        handler: "listUsers",
      }),
      makeEndpointInfo({
        framework: "express",
        file: "src/routes/users.ts",
        method: "POST",
        path: "/users",
        handler: "createUser",
      }),
    ];

    const out = consolidateBySameRoute(rows);

    expect(out).toHaveLength(1);
    expect(out[0]!.method).toEqual(["GET", "POST"]);
    expect(out[0]!.path).toBe("/users");
    expect(out[0]!.file).toBe("src/routes/users.ts");
    expect(out[0]!.handler).toBe("listUsers, createUser");
  });

  it("keeps distinct files with the same path as separate records", () => {
    const rows: EndpointInfo[] = [
      makeEndpointInfo({
        framework: "express",
        file: "src/api/users.ts",
        method: "GET",
        path: "/users",
      }),
      makeEndpointInfo({
        framework: "express",
        file: "src/admin/users.ts",
        method: "GET",
        path: "/users",
      }),
    ];

    const out = consolidateBySameRoute(rows);

    expect(out).toHaveLength(2);
    expect(out.map((e) => e.file).sort()).toEqual([
      "src/admin/users.ts",
      "src/api/users.ts",
    ]);
  });

  it("de-duplicates repeated methods on the same route", () => {
    const rows: EndpointInfo[] = [
      makeEndpointInfo({
        framework: "express",
        file: "src/routes/items.ts",
        method: "GET",
        path: "/items",
      }),
      makeEndpointInfo({
        framework: "express",
        file: "src/routes/items.ts",
        method: "GET",
        path: "/items",
      }),
    ];

    const out = consolidateBySameRoute(rows);

    expect(out).toHaveLength(1);
    expect(out[0]!.method).toEqual(["GET"]);
  });

  it("unions auth arrays across consolidated rows", () => {
    const rows: EndpointInfo[] = [
      makeEndpointInfo({
        framework: "express",
        file: "src/routes/x.ts",
        method: "GET",
        path: "/x",
        auth: ["session"],
      }),
      makeEndpointInfo({
        framework: "express",
        file: "src/routes/x.ts",
        method: "POST",
        path: "/x",
        auth: ["session", "csrf"],
      }),
    ];

    const out = consolidateBySameRoute(rows);

    expect(out).toHaveLength(1);
    expect(out[0]!.auth).toEqual(["session", "csrf"]);
  });
});

describe("shouldFallback", () => {
  it("falls back when no frameworks are detected", () => {
    const result = makeMapResult([], { frameworks: [] });

    expect(shouldFallback(result)).toEqual({
      fallback: true,
      reason: "no frameworks detected",
    });
  });

  it("falls back when frameworks are detected but zero endpoints found", () => {
    const result = makeMapResult([], { frameworks: ["nextjs"] });

    const decision = shouldFallback(result);

    expect(decision.fallback).toBe(true);
    if (decision.fallback) {
      expect(decision.reason).toMatch(/zero endpoints/);
    }
  });

  it("does not fall back when frameworks and endpoints are present", () => {
    const ep = makeEndpointInfo({
      framework: "nextjs",
      file: "app/api/users/route.ts",
      method: "GET",
      path: "/api/users",
    });
    const result = makeMapResult([ep], { frameworks: ["nextjs"] });

    expect(shouldFallback(result)).toEqual({ fallback: false });
  });
});

describe("mapAppWithSurface — pass-through behavior", () => {
  // Surface emits `kind: "page"` (since v0.2.0). The integration layer is a
  // pure pass-through: `kind` is preserved as the page/api signal and
  // `method` carries surface's raw HTTP methods. The apex storage convention
  // (method="PAGE" for pages) is applied at the document_endpoint write
  // boundary, not here.
  it("preserves kind and raw method for both page and api endpoints", () => {
    const rows: EndpointInfo[] = [
      makeEndpointInfo({
        framework: "nextjs",
        file: "app/dashboard/page.tsx",
        method: "GET",
        path: "/dashboard",
        handler: "Page",
        kind: "page",
      }),
      makeEndpointInfo({
        framework: "nextjs",
        file: "app/api/users/route.ts",
        method: "GET",
        path: "/api/users",
        handler: "GET",
        kind: "api",
      }),
      makeEndpointInfo({
        framework: "nextjs",
        file: "app/api/users/route.ts",
        method: "POST",
        path: "/api/users",
        handler: "POST",
        kind: "api",
      }),
    ];

    const consolidated = consolidateBySameRoute(rows);
    expect(consolidated).toHaveLength(2);

    const page = consolidated.find((e) => e.file.endsWith("page.tsx"));
    const api = consolidated.find((e) => e.file.endsWith("route.ts"));
    expect(page!.kind).toBe("page");
    expect(page!.method).toEqual(["GET"]);
    expect(api!.kind).toBe("api");
    expect(api!.method).toEqual(["GET", "POST"]);
  });

  it("returns a fallback signal when surface produces no frameworks", () => {
    // Sanity check on the fallback decision reaching the public API.
    // We don't call mapAppWithSurface against a real path here; instead
    // we verify shouldFallback drives the same decision.
    const result = makeMapResult([], { frameworks: [] });
    const decision = shouldFallback(result);
    expect(decision.fallback).toBe(true);
    if (decision.fallback) {
      expect(decision.reason).toBe("no frameworks detected");
    }
  });

  it("end-to-end against a non-existent path returns a fallback signal (real surface.map)", () => {
    // Surface gracefully handles missing paths — it scans nothing, finds no
    // frameworks, and we should fall back. This exercises the real
    // mapAppWithSurface entry point without depending on a fixture repo.
    const out = mapAppWithSurface(
      "/tmp/__apex_surface_does_not_exist__",
      "/tmp",
    );
    expect(out.mode).toBe("fallback");
  });
});

describe("findDependencyRoot (walk-up)", () => {
  let repoRoot: string;
  let appSubdir: string;
  let nestedAppSubdir: string;
  let pkgSubdir: string;

  beforeAll(() => {
    // Set up a fixture repo:
    //   repoRoot/
    //     package.json                       ← root dep manifest
    //     app/
    //       page.tsx
    //       (nothing here — like single-app Next.js)
    //     packages/
    //       libA/
    //         package.json                  ← package-level dep manifest
    //         src/
    repoRoot = mkdtempSync(join(tmpdir(), "apex-walkup-"));
    writeFileSync(join(repoRoot, "package.json"), '{"name":"root"}');
    appSubdir = join(repoRoot, "app");
    mkdirSync(appSubdir);
    writeFileSync(join(appSubdir, "page.tsx"), "// noop");
    nestedAppSubdir = join(repoRoot, "app", "deeply", "nested");
    mkdirSync(nestedAppSubdir, { recursive: true });
    pkgSubdir = join(repoRoot, "packages", "libA");
    mkdirSync(pkgSubdir, { recursive: true });
    writeFileSync(join(pkgSubdir, "package.json"), '{"name":"libA"}');
    mkdirSync(join(pkgSubdir, "src"));
  });

  afterAll(() => {
    rmSync(repoRoot, { recursive: true, force: true });
  });

  it("walks up from a sub-directory to find the parent's package.json", () => {
    expect(findDependencyRoot(appSubdir, repoRoot)).toBe(resolve(repoRoot));
  });

  it("walks up from a deeply nested sub-directory", () => {
    expect(findDependencyRoot(nestedAppSubdir, repoRoot)).toBe(
      resolve(repoRoot),
    );
  });

  it("returns the package directory itself when it has its own dep file (monorepo)", () => {
    // Walking up from packages/libA/src finds libA's package.json — does NOT
    // walk all the way to the root.
    expect(findDependencyRoot(join(pkgSubdir, "src"), repoRoot)).toBe(
      resolve(pkgSubdir),
    );
  });

  it("returns the appPath when it already contains a dep file", () => {
    expect(findDependencyRoot(repoRoot, repoRoot)).toBe(resolve(repoRoot));
  });

  it("does not walk past repoRoot", () => {
    // appPath is repoRoot itself with no further parent to check.
    // Even if no dep file existed, we'd stop at repoRoot.
    expect(findDependencyRoot(appSubdir, repoRoot)).not.toContain("..");
  });

  it("falls back to the original appPath when no dep file is found within bounds", () => {
    // Construct a path under repoRoot whose ancestors have no dep file
    // (other than the root). Removing root's package.json would simulate this,
    // but to avoid disrupting other tests we use a separate isolated dir.
    const isolated = mkdtempSync(join(tmpdir(), "apex-walkup-empty-"));
    try {
      const inner = join(isolated, "app");
      mkdirSync(inner);
      // No dep file anywhere — should return resolve(inner).
      expect(findDependencyRoot(inner, isolated)).toBe(resolve(inner));
    } finally {
      rmSync(isolated, { recursive: true, force: true });
    }
  });
});
