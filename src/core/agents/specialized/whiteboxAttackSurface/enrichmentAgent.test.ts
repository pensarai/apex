import { describe, it, expect } from "vitest";
import {
  buildEnrichmentObjective,
  type AppInfo,
  type EnrichmentEndpoint,
} from "./enrichmentAgent";

describe("buildEnrichmentObjective (per-endpoint)", () => {
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

  describe("page endpoint", () => {
    const objective = buildEnrichmentObjective({
      app,
      codebasePath: "/repo",
      endpoint: pageEndpoint,
      frameworks: ["nextjs"],
    });

    it("opens with the per-endpoint header (single endpoint scope)", () => {
      expect(objective).toContain("# Enrich Endpoint: PAGE /dashboard");
    });

    it("renders codebase context (root, app name, app location, framework)", () => {
      expect(objective).toContain("**Repository root:** /repo");
      expect(objective).toContain("**App:** myapp");
      expect(objective).toContain("**App location:** apps/myapp");
      expect(objective).toContain("**Framework(s):** nextjs");
    });

    it("renders the single endpoint's structural fields", () => {
      expect(objective).toContain("**method**: PAGE");
      expect(objective).toContain("**routePath**: /dashboard");
      expect(objective).toContain(
        "**file**: apps/myapp/app/dashboard/page.tsx:12",
      );
      expect(objective).toContain("**handler**: DashboardPage");
      expect(objective).toContain("**endpointType**: web-endpoint");
    });

    it("renders auth signals + prefilled authRequired", () => {
      expect(objective).toContain("**auth signals**: middleware:requireAuth");
      expect(objective).toContain("**prefilled authRequired**: true");
    });

    it("instructs document_endpoint with the canary-shape flat fields", () => {
      expect(objective).toContain("document_endpoint");
      expect(objective).not.toContain("document_asset");
      expect(objective).toContain("appName");
      expect(objective).toContain('"myapp"');
      expect(objective).toContain("routePath");
      expect(objective).toContain("endpointType");
      expect(objective).toContain("riskLevel");
      expect(objective).toContain("CRITICAL");
      expect(objective).toContain("HIGH");
      expect(objective).toContain("MEDIUM");
      expect(objective).toContain("LOW");
    });

    it("does not instruct the agent to pass pentestObjectives — auto-generated", () => {
      expect(objective).toContain(
        "document_endpoint` generates them automatically",
      );
      expect(objective).not.toMatch(
        /pentestObjectives.*: \d-\d specific testing/,
      );
    });

    it("scopes the agent to a single endpoint and forbids re-discovery", () => {
      expect(objective).toContain("**exactly one** endpoint");
      expect(objective).toContain("Do not document other endpoints");
      expect(objective).toContain("Do not enumerate routes");
    });

    it("ends with the response-tool ask using endpointsDocumented: 1", () => {
      expect(objective).toContain("endpointsDocumented: 1");
    });

    it("renders PAGE methods as a single string (not array) in the document_endpoint ask", () => {
      // Single-method endpoints serialize as the string, not the one-element array.
      expect(objective).toContain('`"PAGE"`');
    });
  });

  describe("api endpoint with multiple methods", () => {
    const objective = buildEnrichmentObjective({
      app,
      codebasePath: "/repo",
      endpoint: apiEndpoint,
      frameworks: ["nextjs"],
    });

    it("opens with comma-joined methods", () => {
      expect(objective).toContain("# Enrich Endpoint: GET,POST /api/users");
    });

    it("renders endpointType as api-endpoint", () => {
      expect(objective).toContain("**endpointType**: api-endpoint");
    });

    it("prefills authRequired=false when no auth signals", () => {
      expect(objective).toContain("**auth signals**: none");
      expect(objective).toContain("**prefilled authRequired**: false");
    });

    it("serializes multi-method as a JSON array string for the document_endpoint ask", () => {
      expect(objective).toContain('`["GET","POST"]`');
    });
  });

  it("falls back to 'unknown' framework label when none detected", () => {
    const obj = buildEnrichmentObjective({
      app,
      codebasePath: "/repo",
      endpoint: apiEndpoint,
      frameworks: [],
    });
    expect(obj).toContain("**Framework(s):** unknown");
  });
});
