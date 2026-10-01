import { describe, expect, it, vi } from "vitest";

const constructorCalls = vi.hoisted(() => [] as Array<Record<string, unknown>>);

vi.mock("../../offSecAgent/offensiveSecurityAgent", () => ({
  OffensiveSecurityAgent: class {
    constructor(input: Record<string, unknown>) {
      constructorCalls.push(input);
    }
  },
}));

import {
  AuthenticationAgent,
  type AuthenticationAgentInput,
  authenticationAgentDefinition,
} from "./agent";

function makeOpts(
  overrides: Partial<AuthenticationAgentInput> = {},
): AuthenticationAgentInput {
  return {
    model: "test-model",
    // biome-ignore lint/suspicious/noExplicitAny: minimal SessionInfo stand-in
    session: { rootPath: "/tmp/session", targets: [] } as any,
    target: "https://app.example.com",
    ...overrides,
  };
}

describe("authenticationAgentDefinition — golden prompt/toolset (design doc §3.5)", () => {
  it("keeps the fixed auth toolset and target for a given input", () => {
    const opts = makeOpts();
    const activeTools = authenticationAgentDefinition.activeTools(
      opts,
      undefined,
    );

    expect(activeTools).toEqual([
      "execute_command",
      "complete_authentication",
      "browser_navigate",
      "browser_snapshot",
      "browser_screenshot",
      "browser_click",
      "browser_fill",
      "browser_evaluate",
      "browser_console",
      "browser_get_cookies",
      "email_list_inboxes",
      "email_list_messages",
      "email_search_messages",
      "email_get_message",
      "send_email",
      "sms_list_messages",
      "web_search",
      "get_page",
    ]);
    expect(authenticationAgentDefinition.target?.(opts, undefined)).toBe(
      "https://app.example.com",
    );
  });

  it("includes auth hints and application context in the prompt, unchanged for the same input", () => {
    const opts = makeOpts({
      authHints: { authScheme: "form", csrfRequired: true },
      context: "Application: Billing",
    });

    const prompt = authenticationAgentDefinition.prompt(opts, undefined);

    expect(prompt).toContain("TARGET: https://app.example.com");
    expect(prompt).toContain("APPLICATION CONTEXT");
    expect(prompt).toContain("Application: Billing");
    expect(prompt).toContain("Auth scheme: form");
    expect(prompt).toContain("CSRF protection detected");
  });
});

describe("AuthenticationAgent hook forwarding (design doc §3.5)", () => {
  it("forwards sandbox, subagentSpawner, smsInbox and emailAdapterFor — the hooks the pre-A7 constructor dropped", () => {
    constructorCalls.length = 0;

    const sandbox = { kind: "fake-sandbox" };
    const subagentSpawner = { spawnMany: vi.fn() };
    const smsInbox = { reserve: vi.fn(), list: vi.fn() };
    const emailAdapterFor = vi.fn(() => null);
    const extraTools = { extra_tool: {} };

    new AuthenticationAgent(
      makeOpts({
        // biome-ignore lint/suspicious/noExplicitAny: fake UnifiedSandbox stand-in
        sandbox: sandbox as any,
        // biome-ignore lint/suspicious/noExplicitAny: fake SubagentSpawner stand-in
        subagentSpawner: subagentSpawner as any,
        smsInbox,
        emailAdapterFor,
        // biome-ignore lint/suspicious/noExplicitAny: fake ToolSet stand-in
        extraTools: extraTools as any,
      }),
    );

    expect(constructorCalls).toHaveLength(1);
    const forwarded = constructorCalls[0]!;
    expect(forwarded.sandbox).toBe(sandbox);
    expect(forwarded.subagentSpawner).toBe(subagentSpawner);
    expect(forwarded.smsInbox).toBe(smsInbox);
    expect(forwarded.emailAdapterFor).toBe(emailAdapterFor);
    expect(forwarded.extraTools).toEqual(extraTools);
  });
});
