import { describe, it, expect } from "vitest";
import {
  buildEnrichmentObjective,
  type AppInfo,
  type EnrichmentEndpoint,
} from "./enrichmentAgent";

describe("buildEnrichmentObjective", () => {
  const app: AppInfo = {
    name: "myapp",
    framework: "Next.js 14 App Router",
    description: "Synthetic app for enrichment-prompt unit tests.",
    location: "apps/myapp",
    type: "full_stack",
  };

  const pageEndpoint: EnrichmentEndpoint = {
    method: ["GET"],
    classifiedMethod: ["PAGE"],
    isPage: true,
    path: "/dashboard",
    handler: "DashboardPage",
    file: "apps/myapp/app/dashboard/page.tsx",
    line: 12,
    framework: "nextjs",
    auth: ["middleware:requireAuth"],
    internal: false,
  };

  const apiEndpoint: EnrichmentEndpoint = {
    method: ["GET", "POST"],
    classifiedMethod: ["GET", "POST"],
    isPage: false,
    path: "/api/users",
    handler: "GET, POST",
    file: "apps/myapp/app/api/users/route.ts",
    line: 7,
    framework: "nextjs",
    auth: [],
    internal: false,
  };

  const objective = buildEnrichmentObjective({
    app,
    codebasePath: "/repo",
    endpoints: [pageEndpoint, apiEndpoint],
    frameworks: ["nextjs"],
  });

  it("opens with the per-app enrichment header", () => {
    expect(objective).toContain("# Enrich Endpoints for myapp");
  });

  it("includes the deterministic non-discovery instruction verbatim", () => {
    expect(objective).toContain("Do NOT re-discover routes");
  });

  it("renders codebase context (root, app location, framework)", () => {
    expect(objective).toContain("**Repository root:** /repo");
    expect(objective).toContain("**App location:** apps/myapp");
    expect(objective).toContain("**Framework(s):** nextjs");
  });

  it("numbers endpoints starting at 1 with method,path formatting", () => {
    expect(objective).toContain("1. **PAGE /dashboard**");
    expect(objective).toContain("2. **GET,POST /api/users**");
  });

  it("renders file:line and handler sub-bullets per endpoint", () => {
    expect(objective).toContain("file: apps/myapp/app/dashboard/page.tsx:12");
    expect(objective).toContain("handler: DashboardPage");
    expect(objective).toContain("file: apps/myapp/app/api/users/route.ts:7");
    expect(objective).toContain("handler: GET, POST");
  });

  it("renders auth signals (joined for non-empty, 'none' otherwise)", () => {
    expect(objective).toContain("auth signals: middleware:requireAuth");
    expect(objective).toContain("auth signals: none");
  });

  it("pre-fills authRequired from the auth-signal count", () => {
    // Page has one signal → true; API has zero signals → false
    expect(objective).toContain("prefilled authRequired: true");
    expect(objective).toContain("prefilled authRequired: false");
  });

  it("renders endpointType per entry (PAGE → web-endpoint, otherwise api-endpoint)", () => {
    expect(objective).toContain("endpointType: web-endpoint");
    expect(objective).toContain("endpointType: api-endpoint");
  });

  it("instructs the agent to call document_endpoint with the canary-shape flat fields", () => {
    expect(objective).toContain("document_endpoint");
    expect(objective).not.toContain("document_asset");
    expect(objective).toContain("appName");
    expect(objective).toContain('"myapp"');
    expect(objective).toContain("routePath");
    expect(objective).toContain("endpointType");
    expect(objective).toContain("description");
    expect(objective).toContain("riskLevel");
    expect(objective).toContain("CRITICAL");
    expect(objective).toContain("HIGH");
    expect(objective).toContain("MEDIUM");
    expect(objective).toContain("LOW");
  });

  it("does not instruct the agent to pass pentestObjectives — they are auto-generated", () => {
    expect(objective).toContain("auto");
    expect(objective).toContain("automatically");
    // The agent should NOT be told to provide pentestObjectives as a field.
    expect(objective).not.toMatch(
      /pentestObjectives.*: \d-\d specific testing/,
    );
  });

  it("ends with the response-tool summary instruction including the count", () => {
    expect(objective).toContain("call `response` with the count of endpoints");
    expect(objective).toContain("must equal the number above: 2");
  });

  it("falls back to 'unknown' when no frameworks are detected", () => {
    const obj = buildEnrichmentObjective({
      app,
      codebasePath: "/repo",
      endpoints: [apiEndpoint],
      frameworks: [],
    });
    expect(obj).toContain("**Framework(s):** unknown");
  });
});
