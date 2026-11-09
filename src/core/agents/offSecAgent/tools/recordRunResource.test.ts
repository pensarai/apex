import { afterEach, describe, expect, it, vi } from "vitest";
import { buildRunResourceCall, recordRunResource } from "./recordRunResource";
import type { ToolContext } from "./types";

async function execute(
  tool: ReturnType<typeof recordRunResource>,
  toolCallId: string,
) {
  if (!tool.execute) throw new Error("record_run_resource has no execute");
  return tool.execute(input, { toolCallId, messages: [] });
}

const input = {
  kind: "account" as const,
  operation: "created" as const,
  attribution: "ambiguous" as const,
  outcome: "succeeded" as const,
  label: "pensar-test-admin",
  toolCallDescription: "Noted an account whose owner is unclear",
};

describe("buildRunResourceCall", () => {
  it("sends the caller attribution and the evidence ids, not the UI description", () => {
    expect(
      buildRunResourceCall(input, {
        sessionId: "ses_child",
        toolCallId: "call_1",
      }),
    ).toEqual({
      method: "runResources.record",
      args: [
        {
          kind: "account",
          operation: "created",
          attribution: "ambiguous",
          outcome: "succeeded",
          label: "pensar-test-admin",
          sessionId: "ses_child",
          toolCallId: "call_1",
        },
      ],
    });
  });
});

describe("recordRunResource", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("does not catalogue a change when the run is outside Console", async () => {
    vi.stubEnv("AGENT_API_URL", "");
    vi.stubEnv("AGENT_API_TOKEN", "");
    const tool = recordRunResource({
      session: { id: "ses_root" },
    } as ToolContext);
    const result = await execute(tool, "call_1");
    expect(result).toMatchObject({ success: false });
  });

  it("posts the record and does not treat a similar name as created by the run", async () => {
    vi.stubEnv("AGENT_API_URL", "https://agent.example");
    vi.stubEnv("AGENT_API_TOKEN", "token");
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      text: async () => JSON.stringify({ result: { id: "row-1" } }),
    });
    vi.stubGlobal("fetch", fetchMock);
    const tool = recordRunResource({
      session: { id: "ses_root" },
      subagentId: "ses_child",
    } as ToolContext);
    const result = await execute(tool, "call_1");
    expect(result).toMatchObject({ success: true, id: "row-1" });
    const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body));
    expect(body.args[0].attribution).toBe("ambiguous");
    expect(body.args[0].sessionId).toBe("ses_child");
    expect(JSON.stringify(body)).not.toContain("toolCallDescription");
  });
});
