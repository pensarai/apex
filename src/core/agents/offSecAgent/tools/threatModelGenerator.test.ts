import { describe, expect, it, vi } from "vitest";
import type { ToolContext } from "./types";
import {
  buildThreatModelPrompt,
  generateThreatModelForEndpoint,
  threatModelExcludeTools,
  type GenerateThreatModelInput,
} from "./threatModelGenerator";

// Capture what the (real entry point) hands to the CodeAgent constructor, and
// stub the LLM call — the one thing that genuinely needs cloud creds.
const captured = vi.hoisted(() => ({ opts: [] as Array<Record<string, any>> }));

vi.mock("../../specialized/codeAgent/agent", async (importActual) => {
  const actual =
    await importActual<typeof import("../../specialized/codeAgent/agent")>();
  return {
    ...actual,
    CodeAgent: class {
      constructor(opts: Record<string, any>) {
        captured.opts.push(opts);
      }
      async consume() {
        return {
          businessLogic: "bl",
          threatModel: "tm",
          exposure: 3,
          dataSensitivity: 2,
          functionCriticality: 1,
          securityIndicators: 0,
          riskScoreJustification: "because",
          pentestObjectives: [
            {
              title: "t",
              hypothesis: "h",
              prerequisites: "None.",
              setup: "No setup.",
              procedure: "do x",
              successSignal: "200",
              priority: "p1",
            },
          ],
        };
      }
    },
  };
});

const input: GenerateThreatModelInput = {
  appName: "shop",
  routePath: "/api/orders/:id",
  method: "GET",
  description: "Returns a single order by id.",
};

describe("threatModelExcludeTools", () => {
  it("only excludes the document tools when source is available (whitebox)", () => {
    const excluded = threatModelExcludeTools(true);
    expect(excluded).toEqual(["document_endpoint", "document_app"]);
    // Whitebox keeps source-reading tools.
    expect(excluded).not.toContain("read_file");
    expect(excluded).not.toContain("grep");
  });

  it("also excludes source-reading tools when source is unavailable (blackbox)", () => {
    const excluded = threatModelExcludeTools(false);
    expect(excluded).toContain("document_endpoint");
    for (const t of ["read_file", "list_files", "grep", "execute_command"]) {
      expect(excluded).toContain(t);
    }
    // Live HTTP + research stay available so it can work from description/HTTP.
    for (const t of ["http_request", "web_search", "get_page"]) {
      expect(excluded).not.toContain(t);
    }
  });
});

describe("buildThreatModelPrompt", () => {
  it("tells the agent to read the source file in whitebox mode", () => {
    const prompt = buildThreatModelPrompt(input, undefined, true);
    expect(prompt).toContain("Read the source file");
    expect(prompt).not.toContain("blackbox");
  });

  it("does not push source reading in blackbox mode", () => {
    const prompt = buildThreatModelPrompt(input, undefined, false);
    expect(prompt).not.toContain("Read the source file");
    expect(prompt).toContain("blackbox");
    expect(prompt).toContain("source-unavailable mode");
    // Caps priority and forbids fabricated citations.
    expect(prompt).toContain("p1");
    expect(prompt).toContain("never fabricate");
  });

  it("defaults to whitebox behavior when the flag is omitted", () => {
    expect(buildThreatModelPrompt(input)).toContain("Read the source file");
  });
});

// End-to-end through the real entry point: only the LLM agent is stubbed.
// Reproduces the blackbox scenario from issue #842 and asserts the spawned
// agent is built source-free with the blackbox prompt — the structural reason
// it can no longer flail on missing source / loop on `response`.
describe("generateThreatModelForEndpoint (blackbox vs whitebox wiring)", () => {
  function makeCtx(agentCwd: string): ToolContext {
    return {
      session: {
        id: "ses_test",
        rootPath: "/sessions/ses_test",
        targets: ["https://example.com"],
        config: {},
      },
      agentCwd,
      model: "test-model",
    } as unknown as ToolContext;
  }

  it("blackbox (agentCwd === session.rootPath): source-free agent + blackbox prompt", async () => {
    captured.opts.length = 0;
    const out = await generateThreatModelForEndpoint(
      makeCtx("/sessions/ses_test"),
      input,
    );

    expect(captured.opts).toHaveLength(1);
    const opts = captured.opts[0];
    expect(opts.excludeTools).toContain("read_file");
    expect(opts.excludeTools).toContain("grep");
    expect(opts.objective).toContain("blackbox");
    expect(opts.objective).not.toContain("Read the source file");

    // Real flattening/score wiring still produces a usable result.
    expect(out?.riskScore.score).toBe(6);
    expect(out?.pentestObjectives[0]).toContain("[P1] t");
  });

  it("whitebox (agentCwd !== session.rootPath): source-first agent + read-the-code prompt", async () => {
    captured.opts.length = 0;
    const out = await generateThreatModelForEndpoint(
      makeCtx("/repo/checkout"),
      input,
    );

    expect(captured.opts).toHaveLength(1);
    const opts = captured.opts[0];
    expect(opts.excludeTools).not.toContain("read_file");
    expect(opts.excludeTools).toEqual(["document_endpoint", "document_app"]);
    expect(opts.objective).toContain("Read the source file");
    expect(out?.riskScore.score).toBe(6);
  });

  it("returns null (heuristic fallback) when no model is configured", async () => {
    const ctx = makeCtx("/sessions/ses_test");
    (ctx as { model?: unknown }).model = undefined;
    expect(await generateThreatModelForEndpoint(ctx, input)).toBeNull();
  });
});
