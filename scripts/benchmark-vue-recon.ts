#!/usr/bin/env bun

import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from "fs";
import { extname, join, resolve } from "path";
import { extractJavascriptEndpoints } from "../src/core/agents/specialized/attackSurface/jsExtraction";
import { mapAppWithSurface } from "../src/core/integrations/surface";

interface EndpointManifest {
  id: string;
  name: string;
  framework: string;
  appPath: string;
  staticBuildPath: string;
  expected: {
    pages: string[];
    apiEndpoints: string[];
    ignoredExternal: string[];
  };
}

interface CoverageResult {
  expected: string[];
  discovered: string[];
  matched: string[];
  missed: string[];
  falsePositives: string[];
  recall: number;
}

interface FixtureResult {
  id: string;
  name: string;
  framework: string;
  blackbox: {
    jsEndpoints: string[];
    externalJSFiles: string[];
    filesAnalyzed: number;
    message: string;
  };
  whitebox: {
    mode: "surface" | "fallback";
    reason?: string;
    frameworks: string[];
    endpoints: string[];
  };
  coverage: {
    pages: CoverageResult;
    apiEndpoints: CoverageResult;
    dynamicRoutes: CoverageResult;
  };
}

const MANIFEST_DIR = resolve("benchmarks/vue-recon/expected");
const OUTPUT_PATH = resolve("benchmarks/vue-recon/results/baseline-current.json");

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

function loadManifests(): EndpointManifest[] {
  return readdirSync(MANIFEST_DIR)
    .filter((file) => file.endsWith(".json"))
    .sort()
    .map((file) => {
      const fullPath = join(MANIFEST_DIR, file);
      return JSON.parse(readFileSync(fullPath, "utf-8")) as EndpointManifest;
    });
}

function startStaticServer(root: string): { url: string; stop: () => void } {
  const staticRoot = resolve(root);
  const server = Bun.serve({
    port: 0,
    fetch(request) {
      const requestUrl = new URL(request.url);
      const pathname = decodeURIComponent(requestUrl.pathname);
      const relativePath = pathname === "/" ? "index.html" : pathname.slice(1);
      const filePath = resolve(staticRoot, relativePath);

      if (!(filePath === staticRoot || filePath.startsWith(`${staticRoot}/`))) {
        return new Response("Forbidden", { status: 403 });
      }

      if (existsSync(filePath) && statSync(filePath).isFile()) {
        return new Response(Bun.file(filePath), {
          headers: {
            "content-type":
              MIME_TYPES[extname(filePath)] ?? "application/octet-stream",
          },
        });
      }

      const fallbackPath = join(staticRoot, "index.html");
      return new Response(Bun.file(fallbackPath), {
        headers: { "content-type": MIME_TYPES[".html"] },
      });
    },
  });

  return {
    url: `http://127.0.0.1:${server.port}`,
    stop: () => server.stop(true),
  };
}

function normalizePath(value: string): string {
  try {
    const parsed = new URL(value, "http://fixture.local");
    return parsed.pathname.replace(/\/$/, "") || "/";
  } catch {
    return value.split(/[?#]/, 1)[0]?.replace(/\/$/, "") || "/";
  }
}

function expectedPatternToRegex(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    .replace(/:[^/]+/g, "[^/]+");
  return new RegExp(`^${escaped}$`);
}

function matchesExpected(actual: string, expected: string): boolean {
  if (actual === expected) return true;
  if (expected.includes(":")) {
    return expectedPatternToRegex(expected).test(actual);
  }
  return false;
}

function compareCoverage(expected: string[], discoveredRaw: string[]): CoverageResult {
  const discovered = Array.from(new Set(discoveredRaw.map(normalizePath))).sort();
  const matched = expected
    .filter((expectedPath) =>
      discovered.some((actual) => matchesExpected(actual, expectedPath)),
    )
    .sort();
  const missed = expected
    .filter((expectedPath) => !matched.includes(expectedPath))
    .sort();
  const falsePositives = discovered
    .filter(
      (actual) =>
        !expected.some((expectedPath) => matchesExpected(actual, expectedPath)),
    )
    .sort();

  return {
    expected,
    discovered,
    matched,
    missed,
    falsePositives,
    recall: expected.length === 0 ? 1 : matched.length / expected.length,
  };
}

function dynamicOnly(paths: string[]): string[] {
  return paths.filter((path) => path.includes(":"));
}

async function runFixture(manifest: EndpointManifest): Promise<FixtureResult> {
  const appPath = resolve(manifest.appPath);
  const staticBuildPath = resolve(manifest.staticBuildPath);
  const server = startStaticServer(staticBuildPath);

  try {
    const jsResult = await extractJavascriptEndpoints({
      url: server.url,
      includeExternalJS: true,
    });

    const jsEndpoints = jsResult.endpoints?.map((endpoint) => endpoint.endpoint) ?? [];
    const surfaceResult = mapAppWithSurface(appPath, appPath, {
      isSingleAppRepo: true,
    });

    const surfaceEndpoints =
      surfaceResult.mode === "surface" ? surfaceResult.endpoints : [];
    const surfacePages = surfaceEndpoints
      .filter((endpoint) => endpoint.kind === "page")
      .map((endpoint) => endpoint.path);
    const surfaceApiEndpoints = surfaceEndpoints
      .filter((endpoint) => endpoint.kind === "api")
      .map((endpoint) => endpoint.path);

    const discoveredPages = jsEndpoints
      .filter((endpoint) => !normalizePath(endpoint).startsWith("/api"))
      .concat(surfacePages);
    const discoveredApiEndpoints = jsEndpoints
      .filter((endpoint) => normalizePath(endpoint).startsWith("/api"))
      .concat(surfaceApiEndpoints);

    return {
      id: manifest.id,
      name: manifest.name,
      framework: manifest.framework,
      blackbox: {
        jsEndpoints: Array.from(new Set(jsEndpoints.map(normalizePath))).sort(),
        externalJSFiles: jsResult.externalJSFiles ?? [],
        filesAnalyzed: jsResult.filesAnalyzed ?? 0,
        message: jsResult.message,
      },
      whitebox:
        surfaceResult.mode === "surface"
          ? {
              mode: "surface",
              frameworks: surfaceResult.frameworks,
              endpoints: surfaceResult.endpoints
                .map((endpoint) => endpoint.path)
                .sort(),
            }
          : {
              mode: "fallback",
              reason: surfaceResult.reason,
              frameworks: [],
              endpoints: [],
            },
      coverage: {
        pages: compareCoverage(manifest.expected.pages, discoveredPages),
        apiEndpoints: compareCoverage(
          manifest.expected.apiEndpoints,
          discoveredApiEndpoints,
        ),
        dynamicRoutes: compareCoverage(
          dynamicOnly([
            ...manifest.expected.pages,
            ...manifest.expected.apiEndpoints,
          ]),
          [...discoveredPages, ...discoveredApiEndpoints],
        ),
      },
    };
  } finally {
    server.stop();
  }
}

function average(values: number[]): number {
  return values.length === 0
    ? 0
    : values.reduce((sum, value) => sum + value, 0) / values.length;
}

async function main(): Promise<void> {
  const manifests = loadManifests();
  const results: FixtureResult[] = [];

  for (const manifest of manifests) {
    console.log(`Running Vue recon benchmark: ${manifest.id}`);
    results.push(await runFixture(manifest));
  }

  const report = {
    generatedAt: new Date().toISOString(),
    metricSources: [
      "extractJavascriptEndpoints",
      "mapAppWithSurface",
    ],
    summary: {
      fixtures: results.length,
      pageRouteRecall: average(results.map((r) => r.coverage.pages.recall)),
      apiEndpointRecall: average(
        results.map((r) => r.coverage.apiEndpoints.recall),
      ),
      dynamicRouteRecall: average(
        results.map((r) => r.coverage.dynamicRoutes.recall),
      ),
      totalFalsePositives: results.reduce(
        (sum, result) =>
          sum +
          result.coverage.pages.falsePositives.length +
          result.coverage.apiEndpoints.falsePositives.length,
        0,
      ),
    },
    results,
  };

  mkdirSync(resolve("benchmarks/vue-recon/results"), { recursive: true });
  await Bun.write(OUTPUT_PATH, `${JSON.stringify(report, null, 2)}\n`);

  console.log("");
  console.log("Vue recon baseline summary");
  console.log(`Fixtures: ${report.summary.fixtures}`);
  console.log(
    `Page route recall: ${(report.summary.pageRouteRecall * 100).toFixed(1)}%`,
  );
  console.log(
    `API endpoint recall: ${(report.summary.apiEndpointRecall * 100).toFixed(1)}%`,
  );
  console.log(
    `Dynamic route recall: ${(report.summary.dynamicRouteRecall * 100).toFixed(1)}%`,
  );
  console.log(`False positives: ${report.summary.totalFalsePositives}`);
  console.log(`Report: ${OUTPUT_PATH}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
