import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import type { ToolContext } from "./types";

const api = vi.hoisted(() => ({
  createDomain: vi.fn(),
  listDomains: vi.fn(),
}));

vi.mock("../../../api/domains", () => api);

import {
  createWorkspaceDomain,
  listWorkspaceDomains,
} from "./workspaceDomains";

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

describe("authenticated workspace domain tools", () => {
  beforeEach(() => {
    for (const mock of Object.values(api)) mock.mockReset();
  });

  it("lists public domain summaries", async () => {
    api.listDomains.mockResolvedValue({
      domains: [
        {
          id: "domain-1",
          url: "https://example.com",
          verified: false,
        },
      ],
    });

    const result = await listWorkspaceDomains(makeCtx()).execute?.(
      { toolCallDescription: "List workspace domains" },
      executionOptions,
    );

    expect(api.listDomains).toHaveBeenCalledOnce();
    expect(result).toMatchObject({
      success: true,
      domains: [{ id: "domain-1", url: "https://example.com" }],
    });
  });

  it("creates or resolves a canonical domain without forwarding display input", async () => {
    api.createDomain.mockResolvedValue({
      id: "domain-1",
      url: "https://example.com",
      verified: false,
    });

    const result = await createWorkspaceDomain(makeCtx()).execute?.(
      {
        url: "example.com",
        toolCallDescription: "Add example.com to the workspace",
      },
      executionOptions,
    );

    expect(api.createDomain).toHaveBeenCalledWith({ url: "example.com" });
    expect(result).toEqual({
      success: true,
      domain: {
        id: "domain-1",
        url: "https://example.com",
        verified: false,
      },
    });
  });

  it("returns an actionable authentication failure", async () => {
    api.listDomains.mockRejectedValue(
      new Error(
        "Not authenticated. Run `/login` in Apex or `pensar login` to reconnect to Pensar Console.",
      ),
    );

    const result = await listWorkspaceDomains(makeCtx()).execute?.(
      { toolCallDescription: "List workspace domains" },
      executionOptions,
    );

    expect(result).toMatchObject({
      success: false,
      recovery: expect.stringContaining("run `/login`"),
    });
  });
});
