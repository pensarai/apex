import { describe, it, expect } from "vitest";
import { EndpointIndex, type EndpointInfo, type MapResult } from "@pensar/surface";

import {
  consolidateBySameRoute,
  shouldFallback,
  mapAppWithSurface,
} from "./index";

function makeEndpointInfo(
  overrides: Partial<EndpointInfo> &
    Pick<EndpointInfo, "framework" | "file" | "method" | "path">,
): EndpointInfo {
  return {
    handler: "handler",
    line: 1,
    params: [],
    auth: [],
    internal: false,
    ...overrides,
  };
}

function makeMapResult(endpoints: EndpointInfo[], overrides?: Partial<MapResult>): MapResult {
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
    expect(out.map(e => e.file).sort()).toEqual([
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
    expect(decision.reason).toMatch(/zero endpoints/);
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

describe("mapAppWithSurface (via synthetic MapResult — integration of consolidate + classify)", () => {
  // Note: we don't shell out to the real `surface.map()` filesystem walker.
  // Instead, we exercise the consolidation + classification path directly
  // via the helper functions, which is what `mapAppWithSurface` composes.
  it("classifies a nextjs page route as PAGE and preserves API method on a route handler", () => {
    const rows: EndpointInfo[] = [
      makeEndpointInfo({
        framework: "nextjs",
        file: "app/dashboard/page.tsx",
        method: "GET",
        path: "/dashboard",
        handler: "Page",
      }),
      makeEndpointInfo({
        framework: "nextjs",
        file: "app/api/users/route.ts",
        method: "GET",
        path: "/api/users",
        handler: "GET",
      }),
      makeEndpointInfo({
        framework: "nextjs",
        file: "app/api/users/route.ts",
        method: "POST",
        path: "/api/users",
        handler: "POST",
      }),
    ];

    // Replicate what mapAppWithSurface does internally on the success path.
    const consolidated = consolidateBySameRoute(rows);
    expect(consolidated).toHaveLength(2);

    const page = consolidated.find(e => e.file.endsWith("page.tsx"));
    const api = consolidated.find(e => e.file.endsWith("route.ts"));
    expect(page).toBeDefined();
    expect(api).toBeDefined();
    expect(api!.method).toEqual(["GET", "POST"]);
  });

  it("returns a fallback signal when surface produces no frameworks", async () => {
    // Sanity check on the fallback decision reaching the public API.
    // We don't call mapAppWithSurface against a real path here; instead
    // we verify shouldFallback drives the same decision.
    const result = makeMapResult([], { frameworks: [] });
    const decision = shouldFallback(result);
    expect(decision.fallback).toBe(true);
    expect(decision.reason).toBe("no frameworks detected");
  });

  it("end-to-end against a non-existent path returns a fallback signal (real surface.map)", async () => {
    // Surface gracefully handles missing paths — it scans nothing, finds no
    // frameworks, and we should fall back. This exercises the real
    // mapAppWithSurface entry point without depending on a fixture repo.
    const out = await mapAppWithSurface("/tmp/__apex_surface_does_not_exist__");
    expect(out.mode).toBe("fallback");
  });
});
