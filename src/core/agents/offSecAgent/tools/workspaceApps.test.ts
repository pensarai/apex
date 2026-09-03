import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import type { ToolContext } from "./types";

const api = vi.hoisted(() => ({
  createApp: vi.fn(),
  createEndpoint: vi.fn(),
  listApps: vi.fn(),
  listEndpoints: vi.fn(),
  searchApps: vi.fn(),
  searchEndpoints: vi.fn(),
  updateApp: vi.fn(),
  updateEndpoint: vi.fn(),
}));

vi.mock("../../../api/apps", () => api);

import {
  createWorkspaceApp,
  createWorkspaceEndpoint,
  listWorkspaceApps,
  listWorkspaceEndpoints,
  updateWorkspaceApp,
  updateWorkspaceEndpoint,
} from "./workspaceApps";

function makeCtx(): ToolContext {
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: [],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: "/tmp/test",
      logsPath: "/tmp/test/logs",
      findingsPath: "/tmp/test/findings",
      scratchpadPath: "/tmp/test/scratchpad",
      pocsPath: "/tmp/test/pocs",
    } as SessionInfo,
    agentCwd: "/tmp/test",
  };
}

const executionOptions = {
  toolCallId: "tc_test",
  messages: [],
  abortSignal: undefined,
};

describe("authenticated workspace tools", () => {
  beforeEach(() => {
    for (const mock of Object.values(api)) mock.mockReset();
  });

  it("lists applications through the in-process API", async () => {
    api.listApps.mockResolvedValue({
      apps: [{ id: "app-1", name: "API" }],
      hasMore: false,
      limit: 50,
      offset: 0,
    });

    const result = await listWorkspaceApps(makeCtx()).execute?.(
      {
        limit: 50,
        offset: 0,
        toolCallDescription: "List workspace applications",
      },
      executionOptions,
    );

    expect(api.listApps).toHaveBeenCalledWith({ limit: 50, offset: 0 });
    expect(result).toMatchObject({ success: true, apps: [{ id: "app-1" }] });
  });

  it("searches applications when a query is provided", async () => {
    api.searchApps.mockResolvedValue({
      apps: [],
      hasMore: false,
      limit: 50,
      offset: 0,
      query: "api",
    });

    await listWorkspaceApps(makeCtx()).execute?.(
      {
        query: "api",
        limit: 50,
        offset: 0,
        toolCallDescription: "Find the API application",
      },
      executionOptions,
    );

    expect(api.searchApps).toHaveBeenCalledWith("api", {
      limit: 50,
      offset: 0,
    });
    expect(api.listApps).not.toHaveBeenCalled();
  });

  it("creates an application without forwarding display-only arguments", async () => {
    api.createApp.mockResolvedValue({ id: "app-1", name: "API" });

    const result = await createWorkspaceApp(makeCtx()).execute?.(
      {
        name: "API",
        description: "Primary API",
        type: "api-service",
        toolCallDescription: "Create the API application",
      },
      executionOptions,
    );

    expect(api.createApp).toHaveBeenCalledWith({
      name: "API",
      description: "Primary API",
      type: "api-service",
    });
    expect(result).toEqual({
      success: true,
      application: { id: "app-1", name: "API" },
    });
  });

  it("links an existing application to a workspace domain", async () => {
    api.updateApp.mockResolvedValue({
      id: "app-1",
      domainId: "domain-1",
      domainUrl: "https://example.com",
    });

    const result = await updateWorkspaceApp(makeCtx()).execute?.(
      {
        applicationId: "app-1",
        domainId: "domain-1",
        toolCallDescription: "Link the API application to example.com",
      },
      executionOptions,
    );

    expect(api.updateApp).toHaveBeenCalledWith("app-1", {
      domainId: "domain-1",
    });
    expect(result).toMatchObject({
      success: true,
      application: { id: "app-1", domainId: "domain-1" },
    });
  });

  it("lists endpoints under the requested application", async () => {
    api.listEndpoints.mockResolvedValue({
      endpoints: [],
      hasMore: false,
      limit: 50,
      offset: 0,
    });

    await listWorkspaceEndpoints(makeCtx()).execute?.(
      {
        applicationId: "app-1",
        minRiskScore: 5,
        limit: 50,
        offset: 0,
        toolCallDescription: "List API endpoints",
      },
      executionOptions,
    );

    expect(api.listEndpoints).toHaveBeenCalledWith("app-1", {
      type: undefined,
      minRiskScore: 5,
      limit: 50,
      offset: 0,
    });
  });

  it("creates an endpoint under its parent application", async () => {
    api.createEndpoint.mockResolvedValue({ id: "endpoint-1" });

    const result = await createWorkspaceEndpoint(makeCtx()).execute?.(
      {
        applicationId: "app-1",
        endpoint: "/users",
        description: "User API",
        type: "api-endpoint",
        transport: "grpc",
        authenticationRequired: { required: true },
        toolCallDescription: "Create the users endpoint",
      },
      executionOptions,
    );

    expect(api.createEndpoint).toHaveBeenCalledWith("app-1", {
      endpoint: "/users",
      description: "User API",
      type: "api-endpoint",
      transport: "grpc",
      authenticationRequired: { required: true },
    });
    expect(result).toEqual({
      success: true,
      endpoint: { id: "endpoint-1" },
    });
  });

  it("repairs an existing endpoint transport", async () => {
    api.updateEndpoint.mockResolvedValue({
      id: "endpoint-1",
      transport: "connect",
    });

    const result = await updateWorkspaceEndpoint(makeCtx()).execute?.(
      {
        endpointId: "endpoint-1",
        transport: "connect",
        toolCallDescription: "Correct the endpoint transport",
      },
      executionOptions,
    );

    expect(api.updateEndpoint).toHaveBeenCalledWith("endpoint-1", {
      transport: "connect",
    });
    expect(result).toEqual({
      success: true,
      endpoint: { id: "endpoint-1", transport: "connect" },
    });
  });

  it("returns an actionable authentication failure", async () => {
    api.createApp.mockRejectedValue(
      new Error(
        "Not authenticated. Run `/login` in Apex or `pensar login` to reconnect to Pensar Console.",
      ),
    );

    const result = await createWorkspaceApp(makeCtx()).execute?.(
      {
        name: "API",
        description: "Primary API",
        toolCallDescription: "Create the API application",
      },
      executionOptions,
    );

    expect(result).toEqual({
      success: false,
      error:
        "Not authenticated. Run `/login` in Apex or `pensar login` to reconnect to Pensar Console.",
      recovery:
        "Ask the user to run `/login` in Apex (or the local checkout's `bun src/cli.ts login`), then retry this tool.",
    });
  });
});
