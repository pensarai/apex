import { describe, expect, it } from "vitest";
import type { ConsolidatedEndpoint } from "../../../integrations/surface/types";
import { buildEndpointDocumentationObjective } from "./endpointDocumentationAgent";
import type { AppInfo } from "./types";

describe("buildEndpointDocumentationObjective (per-endpoint)", () => {
  const app: AppInfo = {
    name: "myapp",
    framework: "Next.js 14 App Router",
    description: "Synthetic app for endpoint-documentation prompt unit tests.",
    location: "apps/myapp",
    type: "full_stack",
  };

  // Page endpoint: surface emits kind="page" with the raw HTTP method
  // (e.g. "GET"). The objective builder is responsible for converting to
  // method="PAGE" when emitting document_endpoint instructions.
  const pageEndpoint: ConsolidatedEndpoint = {
    method: ["GET"],
    kind: "page",
    path: "/dashboard",
    handler: "DashboardPage",
    file: "apps/myapp/app/dashboard/page.tsx",
    line: 12,
    framework: "nextjs",
    auth: ["middleware:requireAuth"],
    internal: false,
  };

  const apiEndpoint: ConsolidatedEndpoint = {
    method: ["GET", "POST"],
    kind: "api",
    path: "/api/users",
    handler: "GET, POST",
    file: "apps/myapp/app/api/users/route.ts",
    line: 7,
    framework: "nextjs",
    auth: [],
    internal: false,
  };

  const grpcEndpoint: ConsolidatedEndpoint = {
    method: ["ANY"],
    kind: "api",
    path: "/ledger.v1.LedgerService/GetAccount",
    handler: "GetAccount",
    file: "proto/ledger/v1/ledger.proto",
    line: 8,
    framework: "grpc",
    auth: [],
    internal: false,
    transport: "grpc",
    grpc: {
      serviceFqn: "ledger.v1.LedgerService",
      method: "GetAccount",
      streamingType: "unary",
    },
  };

  describe("grpc endpoint", () => {
    const objective = buildEndpointDocumentationObjective({
      app,
      codebasePath: "/repo",
      endpoint: grpcEndpoint,
      frameworks: ["grpc"],
    });

    it("renders the gRPC section with transport + service metadata", () => {
      expect(objective).toContain(
        "## gRPC (deterministically extracted by surface)",
      );
      expect(objective).toContain("**transport**: grpc");
      expect(objective).toContain(
        "**grpc.serviceFqn**: ledger.v1.LedgerService",
      );
      expect(objective).toContain("**grpc.method**: GetAccount");
      expect(objective).toContain("**grpc.streamingType**: unary");
    });

    it("instructs the agent to pass transport + grpc to document_endpoint", () => {
      expect(objective).toContain('transport: "grpc"');
      expect(objective).toContain("a `grpc` object");
      expect(objective).toContain('schemaSource: "proto"');
    });

    it("keeps endpointType api-endpoint (a gRPC method is still an API)", () => {
      expect(objective).toContain("**endpointType**: api-endpoint");
    });
  });

  describe("page endpoint", () => {
    const objective = buildEndpointDocumentationObjective({
      app,
      codebasePath: "/repo",
      endpoint: pageEndpoint,
      frameworks: ["nextjs"],
    });

    it("opens with the per-endpoint header (single endpoint scope)", () => {
      expect(objective).toContain("# Document Endpoint: PAGE /dashboard");
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
    const objective = buildEndpointDocumentationObjective({
      app,
      codebasePath: "/repo",
      endpoint: apiEndpoint,
      frameworks: ["nextjs"],
    });

    it("opens with comma-joined methods", () => {
      expect(objective).toContain("# Document Endpoint: GET,POST /api/users");
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
    const obj = buildEndpointDocumentationObjective({
      app,
      codebasePath: "/repo",
      endpoint: apiEndpoint,
      frameworks: [],
    });
    expect(obj).toContain("**Framework(s):** unknown");
  });
});
