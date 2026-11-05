import { describe, expect, it } from "vitest";
import {
  buildFindingJudgePrompt,
  FINDING_JUDGE_SYSTEM_PROMPT,
} from "./prompts";
import type { FindingJudgeInput, RecordedCallback } from "./types";

const URL = "https://3f2b8c1e.cb.example.net/ssrf-avatar-url-1";

function finding(
  callbackEvidence?: FindingJudgeInput["callbackEvidence"],
): FindingJudgeInput {
  return {
    pocScript: `curl -s https://app.example.com/avatar -d 'url=${URL}'`,
    pocType: "bash",
    target: "https://app.example.com",
    pocOutput: { stdout: "{}", stderr: "", exitCode: 0 },
    claim: {
      title: "Blind SSRF in avatar import",
      description: "The avatar importer fetches any URL.",
      impact: "Server-side requests to attacker-chosen hosts.",
      evidence: `Sent ${URL}; callback received from the server.`,
      endpoint: "https://app.example.com/avatar",
      vulnerabilityClass: "ssrf",
    },
    ...(callbackEvidence ? { callbackEvidence } : {}),
  };
}

const hit: RecordedCallback = {
  id: "hit-1",
  receivedAt: "2026-11-05T12:00:00.000Z",
  method: "GET",
  path: "/ssrf-avatar-url-1",
  sourceIp: "203.0.113.7",
  userAgent: "python-requests/2.31",
  bodyPreview: "",
  late: false,
};

describe("finding judge callback evidence", () => {
  it("omits the section when the host supplied no callback evidence", () => {
    expect(buildFindingJudgePrompt(finding())).not.toContain(
      "Recorded Callbacks",
    );
  });

  it("shows the recorded callbacks for the finding's marked URLs", () => {
    const prompt = buildFindingJudgePrompt(
      finding({ urls: [URL], callbacks: [hit] }),
    );
    expect(prompt).toContain("## Recorded Callbacks");
    expect(prompt).toContain(`- ${URL}`);
    expect(prompt).toContain(
      "GET /ssrf-avatar-url-1 from 203.0.113.7 (user agent: python-requests/2.31)",
    );
    expect(prompt).toContain("id=hit-1");
  });

  it("says plainly when nothing was recorded", () => {
    const prompt = buildFindingJudgePrompt(
      finding({ urls: [URL], callbacks: [] }),
    );
    expect(prompt).toContain("No request to these URLs was recorded.");
  });

  it("says when the PoC has no marker to attribute a callback to", () => {
    const prompt = buildFindingJudgePrompt(
      finding({ urls: [], callbacks: [] }),
    );
    expect(prompt).toContain("without a path marker");
  });

  it("tells the judge only host-recorded callbacks prove an out-of-band claim", () => {
    expect(FINDING_JUDGE_SYSTEM_PROMPT).toContain("Recorded Callbacks");
    expect(FINDING_JUDGE_SYSTEM_PROMPT).toContain(
      'when the only "callback" is in the agent\'s evidence or PoC output',
    );
  });
});
