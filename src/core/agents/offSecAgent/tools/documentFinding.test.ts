import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentEventBus, type AgentEventMap } from "../../../eventBus";
import {
  type FindingJudgeResult,
  judgeFinding,
} from "../../specialized/findingJudge";
import {
  documentVulnerability,
  validatePocPortability,
} from "./documentFinding";

vi.mock("../../specialized/findingJudge", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("../../specialized/findingJudge")>();
  return {
    ...actual,
    judgeFinding: vi.fn(),
  };
});

vi.mock("../../specialized/cvssScorer", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("../../specialized/cvssScorer")>();
  return {
    ...actual,
    scoreFindingWithCVSS: vi.fn().mockResolvedValue({
      score: 7.1,
      severity: "HIGH",
      vectorString:
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
      metrics: {
        AV: "N",
        AC: "L",
        AT: "N",
        PR: "N",
        UI: "N",
        VC: "H",
        VI: "N",
        VA: "N",
        SC: "N",
        SI: "N",
        SA: "N",
        E: "A",
      },
      scoreType: "CVSS-BT",
      reasoning: "Mock CVSS result.",
      cwes: [],
    }),
  };
});

const mockedJudgeFinding = vi.mocked(judgeFinding);

type DocumentToolResult = {
  success: boolean;
  judgeRejected?: boolean;
  judgeReasoning?: string;
  finding?: {
    judge: {
      confidence: number;
      concerns: string[];
      error?: { message: string };
    };
  };
};

function makeDocumentInput() {
  return {
    title: "Exposed Admin Data",
    description: "Admin data is exposed without authorization.",
    impact: "An attacker can read sensitive admin data.",
    evidence: "PoC output showed admin data.",
    materiality: {
      exploitPath: "Unauthenticated request to /admin returns sensitive data.",
      securityImpact: "An attacker can read non-public admin data.",
      affectedAssetOrAbusePath: "Non-public admin data exposure.",
      falsePositiveRationale:
        "The endpoint is not intentionally public and the PoC reads real non-public data.",
    },
    endpoint: "https://example.com/admin",
    remediation: "Require authorization before returning admin data.",
    vulnerabilityClass: "missing-authentication",
    toolCallDescription: "Documenting exposed admin data",
    pocName: "admin_data",
    pocType: "bash" as const,
    pocContent: 'echo "admin data leaked"\nexit 0',
    pocDescription: "Requests the admin endpoint and prints leaked data.",
  };
}

function makeToolContext(rootPath: string) {
  const pocsPath = join(rootPath, "pocs");
  const findingsPath = join(rootPath, "findings");
  const logsPath = join(rootPath, "logs");
  mkdirSync(pocsPath, { recursive: true });
  mkdirSync(findingsPath, { recursive: true });
  mkdirSync(logsPath, { recursive: true });

  return {
    session: {
      id: "test-session",
      rootPath,
      pocsPath,
      findingsPath,
      logsPath,
      targets: ["https://example.com"],
      config: {},
    },
    agentCwd: rootPath,
    model: "test-model",
    target: "https://example.com",
  } as Parameters<typeof documentVulnerability>[0];
}

describe("documentVulnerability judge handling", () => {
  let rootPath: string;

  beforeEach(() => {
    rootPath = mkdtempSync(join(tmpdir(), "apex-document-finding-"));
    mockedJudgeFinding.mockReset();
  });

  afterEach(() => {
    rmSync(rootPath, { recursive: true, force: true });
  });

  it("cleans up the POC and returns judgeRejected when a completed judge rejects", async () => {
    mockedJudgeFinding.mockResolvedValue({
      valid: false,
      findingType: "vulnerability",
      confidence: 0.9,
      reasoning: "The PoC prints static text and does not prove exploitation.",
      concerns: ["PoC evidence is fabricated."],
      verificationSteps: ["Inspected PoC output."],
      toolEvidence: ["stdout contained only static text."],
      reproducedPoc: false,
      webResearchUsed: false,
      limitations: [],
    });

    const ctx = makeToolContext(rootPath);
    const tool = documentVulnerability(ctx);
    const result = (await tool.execute?.(makeDocumentInput(), {
      toolCallId: "test",
      messages: [],
    })) as DocumentToolResult;

    expect(result.success).toBe(false);
    expect(result.judgeRejected).toBe(true);
    expect(result.judgeReasoning).toContain("does not prove exploitation");
    expect(existsSync(join(ctx.session.pocsPath, "poc_admin_data.sh"))).toBe(
      false,
    );
  });

  it("preserves a PoC-backed finding when the judge returns degraded unverified status", async () => {
    mockedJudgeFinding.mockResolvedValue({
      valid: true,
      findingType: "vulnerability",
      confidence: 0.4,
      reasoning:
        "Agentic finding judge could not complete. Preserving the successfully executed PoC-backed finding as unverified.",
      concerns: [
        "Agentic judge infrastructure failed before producing a completed verification judgment.",
      ],
      verificationSteps: [],
      toolEvidence: [],
      reproducedPoc: false,
      webResearchUsed: false,
      limitations: ["No independent judge verification was completed."],
      error: {
        message: "provider overloaded",
        type: "Error",
        model: "test-model",
      },
    });

    const ctx = makeToolContext(rootPath);
    const tool = documentVulnerability(ctx);
    const result = (await tool.execute?.(makeDocumentInput(), {
      toolCallId: "test",
      messages: [],
    })) as DocumentToolResult;

    expect(result.success).toBe(true);
    expect(result.judgeRejected).toBeUndefined();
    expect(result.finding?.judge.confidence).toBe(0.4);
    expect(result.finding?.judge.error?.message).toBe("provider overloaded");
    expect(result.finding?.judge.concerns[0]).toContain(
      "infrastructure failed",
    );
    expect(existsSync(join(ctx.session.pocsPath, "poc_admin_data.sh"))).toBe(
      true,
    );
  });
});

// ---------------------------------------------------------------------------
// Finding Judge subagent lifecycle (regression for the judge rendering as a
// top-level sibling instead of nested under the invoking worker).
// ---------------------------------------------------------------------------

function makeAcceptedJudgeResult(): FindingJudgeResult {
  return {
    valid: true,
    findingType: "vulnerability",
    confidence: 0.95,
    reasoning: "Reproduced the PoC and confirmed the data exposure.",
    concerns: [],
    verificationSteps: ["Reran the PoC."],
    toolEvidence: ["stdout contained the leaked admin data."],
    reproducedPoc: true,
    webResearchUsed: false,
    limitations: [],
  };
}

describe("documentVulnerability finding-judge subagent lifecycle", () => {
  let rootPath: string;

  beforeEach(() => {
    rootPath = mkdtempSync(join(tmpdir(), "apex-document-finding-"));
    mockedJudgeFinding.mockReset();
  });

  afterEach(() => {
    rmSync(rootPath, { recursive: true, force: true });
  });

  it("nests the judge under the invoking worker via lifecycle events and a child bus", async () => {
    const parentBus = new AgentEventBus();
    const spawns: AgentEventMap["subagent-spawn"][] = [];
    const completes: AgentEventMap["subagent-complete"][] = [];
    const textDeltas: AgentEventMap["text-delta"][] = [];
    parentBus.on("subagent-spawn", (e) => spawns.push(e));
    parentBus.on("subagent-complete", (e) => completes.push(e));
    parentBus.on("text-delta", (e) => textDeltas.push(e));

    let judgeCtx: Parameters<typeof judgeFinding>[1] | undefined;
    mockedJudgeFinding.mockImplementation(async (_input, ctx) => {
      judgeCtx = ctx;
      // Simulate the judge agent streaming on the bus it was handed.
      ctx.eventBus?.emit("text-delta", { text: "verifying finding" });
      return makeAcceptedJudgeResult();
    });

    const ctx = {
      ...makeToolContext(rootPath),
      eventBus: parentBus,
      subagentId: "pentest-agent-worker-1",
    };
    const tool = documentVulnerability(ctx);
    const result = (await tool.execute?.(makeDocumentInput(), {
      toolCallId: "test",
      messages: [],
    })) as DocumentToolResult;

    expect(result.success).toBe(true);

    // Lifecycle: one spawn + one complete, anchored to the worker.
    expect(spawns).toHaveLength(1);
    expect(spawns[0].name).toBe("Finding Judge");
    // The judge now gets its own `ses_` execution-session id (distinct Sentry
    // span session); the human label lives on `name`. Parent threading is
    // unchanged.
    expect(spawns[0].subagentId).toMatch(/^ses_/);
    expect(spawns[0].parentSubagentId).toBe("pentest-agent-worker-1");

    expect(completes).toHaveLength(1);
    expect(completes[0].subagentId).toBe(spawns[0].subagentId);
    expect(completes[0].status).toBe("completed");
    expect(completes[0].parentSubagentId).toBe("pentest-agent-worker-1");

    // The judge ran on a child bus with the same id the spawn announced,
    // and its untagged events reach the parent tagged with that id.
    expect(judgeCtx?.subagentId).toBe(spawns[0].subagentId);
    expect(judgeCtx?.eventBus).toBeDefined();
    expect(judgeCtx?.eventBus).not.toBe(parentBus);
    expect(textDeltas).toHaveLength(1);
    expect(textDeltas[0].subagentId).toBe(spawns[0].subagentId);
  });

  it("allocates a fresh judge subagent id per invocation", async () => {
    const parentBus = new AgentEventBus();
    const spawns: AgentEventMap["subagent-spawn"][] = [];
    parentBus.on("subagent-spawn", (e) => spawns.push(e));
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());

    const ctx = {
      ...makeToolContext(rootPath),
      eventBus: parentBus,
      subagentId: "pentest-agent-worker-2",
    };
    const tool = documentVulnerability(ctx);
    await tool.execute?.(makeDocumentInput(), {
      toolCallId: "t1",
      messages: [],
    });
    await tool.execute?.(
      { ...makeDocumentInput(), title: "Second Finding" },
      { toolCallId: "t2", messages: [] },
    );

    expect(spawns).toHaveLength(2);
    expect(spawns[0].subagentId).not.toBe(spawns[1].subagentId);
  });

  it("spawns the judge top-level (no parentSubagentId) when the documenting agent has none", async () => {
    const parentBus = new AgentEventBus();
    const spawns: AgentEventMap["subagent-spawn"][] = [];
    parentBus.on("subagent-spawn", (e) => spawns.push(e));
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());

    const ctx = { ...makeToolContext(rootPath), eventBus: parentBus };
    const tool = documentVulnerability(ctx);
    await tool.execute?.(makeDocumentInput(), {
      toolCallId: "test",
      messages: [],
    });

    expect(spawns).toHaveLength(1);
    expect(spawns[0].subagentId).toMatch(/^ses_/);
    expect(spawns[0].parentSubagentId).toBeUndefined();
  });

  it("marks the judge subagent failed when the judge falls back on infrastructure failure", async () => {
    const parentBus = new AgentEventBus();
    const completes: AgentEventMap["subagent-complete"][] = [];
    parentBus.on("subagent-complete", (e) => completes.push(e));

    mockedJudgeFinding.mockResolvedValue({
      valid: false,
      findingType: "informational",
      confidence: 0.4,
      reasoning: "Agentic finding judge could not complete.",
      concerns: ["Judge infrastructure failed."],
      verificationSteps: [],
      toolEvidence: [],
      reproducedPoc: false,
      webResearchUsed: false,
      limitations: [],
      error: { message: "provider overloaded", type: "Error", model: "m" },
    });

    const ctx = {
      ...makeToolContext(rootPath),
      eventBus: parentBus,
      subagentId: "pentest-agent-worker-3",
    };
    const tool = documentVulnerability(ctx);
    await tool.execute?.(makeDocumentInput(), {
      toolCallId: "test",
      messages: [],
    });

    expect(completes).toHaveLength(1);
    expect(completes[0].status).toBe("failed");
    expect(completes[0].parentSubagentId).toBe("pentest-agent-worker-3");
  });
});

describe("validatePocPortability", () => {
  describe("bash scripts", () => {
    it("detects grep -oP (Perl regex)", () => {
      const script = `#!/bin/bash
response=$(curl -s http://target.com/api/test)
id=$(echo "$response" | grep -oP '(?<=id":)[0-9]+')
echo "ID: $id"`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("grep -P or grep -oP");
      expect(warnings[0]).toContain("grep -E");
    });

    it("detects grep -P (Perl regex)", () => {
      const script = `#!/bin/bash
grep -P 'pattern' file.txt`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("grep -P or grep -oP");
    });

    it("detects grep -Po (flag ordering variant)", () => {
      const script = `#!/bin/bash
curl -s http://target.com | grep -Po '(?<=id":)[0-9]+'`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("grep -P or grep -oP");
    });

    it("detects grep -Poi (multiple flags with P)", () => {
      const script = `#!/bin/bash
grep -Poi 'pattern' file.txt`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("grep -P or grep -oP");
    });

    it("detects grep with separate flag groups (grep -i -P)", () => {
      const script = `#!/bin/bash
curl -s http://target.com | grep -i -P '(?<=id":)[0-9]+'`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("grep -P or grep -oP");
    });

    it("detects grep with multiple separate flags (grep -o -P)", () => {
      const script = `#!/bin/bash
grep -o -P 'pattern' file.txt`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("grep -P or grep -oP");
    });

    it("detects bc usage (piped)", () => {
      const script = `#!/bin/bash
result=$(echo "scale=2; 10 / 3" | bc)
echo "Result: $result"`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("bc command detected");
      expect(warnings[0]).toContain("$(( ))");
    });

    it("detects standalone bc usage on any line", () => {
      const script = `#!/bin/bash
echo "1+1" > calc.txt
bc < calc.txt`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("bc command detected");
    });

    it("detects bc in command substitution $(bc ...)", () => {
      const script = `#!/bin/bash
result=$(bc <<< "scale=2; 10/3")
echo "$result"`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("bc command detected");
    });

    it("detects bc in backtick command substitution", () => {
      const script = `#!/bin/bash
result=\`bc -l <<< "sqrt(2)"\`
echo "$result"`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("bc command detected");
    });

    it("does not warn about bc if it's checked first", () => {
      const script = `#!/bin/bash
if command -v bc >/dev/null 2>&1; then
  result=$(echo "scale=2; 10 / 3" | bc)
else
  result=$(python3 -c "print(10/3)")
fi`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(0);
    });

    it("detects GNU stat -c flag", () => {
      const script = `#!/bin/bash
stat -c '%s' /path/to/file`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("stat -c");
      expect(warnings[0]).toContain("GNU-specific");
    });

    it("detects GNU date long options", () => {
      const script = `#!/bin/bash
date --rfc-3339=seconds`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("GNU date long options");
    });

    it("detects seq usage", () => {
      const script = `#!/bin/bash
for i in $(seq 1 10); do
  echo $i
done`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("seq");
      expect(warnings[0]).toContain("brace expansion");
    });

    it("does not warn about seq if it's checked first", () => {
      const script = `#!/bin/bash
if which seq >/dev/null 2>&1; then
  for i in $(seq 1 10); do echo $i; done
else
  for i in {1..10}; do echo $i; done
fi`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(0);
    });

    it("detects multiple portability issues", () => {
      const script = `#!/bin/bash
id=$(curl -s http://target.com | grep -oP '(?<=id":)[0-9]+')
result=$(echo "scale=2; $id / 3" | bc)
stat -c '%s' /tmp/output
date --rfc-3339=seconds`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings.length).toBeGreaterThanOrEqual(4);
      expect(warnings.some((w) => w.includes("grep -P"))).toBe(true);
      expect(warnings.some((w) => w.includes("bc"))).toBe(true);
      expect(warnings.some((w) => w.includes("stat -c"))).toBe(true);
      expect(warnings.some((w) => w.includes("date"))).toBe(true);
    });

    it("returns empty array for portable bash script", () => {
      const script = `#!/bin/bash
set -e

response=$(curl -s http://target.com/api/test)
id=$(echo "$response" | grep -oE '"id":[0-9]+' | grep -oE '[0-9]+')

# Use shell arithmetic instead of bc
count=$((id * 2))

for i in {1..10}; do
  echo "Test iteration $i"
  curl -X POST "http://target.com/api/item/$id"
done

echo "Success: exploited endpoint with ID $id"
exit 0`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(0);
    });

    it("does not flag netstat -c (not the same as stat -c)", () => {
      const script = `#!/bin/bash
# Monitor network connections continuously
netstat -c`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(0);
    });

    it("does not flag vmstat or other *stat commands", () => {
      const script = `#!/bin/bash
vmstat -c 5
iostat -c 10`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(0);
    });

    it("does not flag update --fix-broken or similar date substrings", () => {
      const script = `#!/bin/bash
apt-get update --fix-broken
candidate --list`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(0);
    });
  });

  describe("python scripts", () => {
    it("returns empty array for python scripts", () => {
      const script = `#!/usr/bin/env python3
import requests
response = requests.get('http://target.com')
print(response.text)`;

      const warnings = validatePocPortability(script, "python");

      expect(warnings).toHaveLength(0);
    });

    it("does not validate portability for python", () => {
      // Even with bash-style commands in comments or strings,
      // we don't validate Python scripts
      const script = `#!/usr/bin/env python3
# This grep -oP would fail on macOS
import subprocess
subprocess.run(['grep', '-E', 'pattern'])`;

      const warnings = validatePocPortability(script, "python");

      expect(warnings).toHaveLength(0);
    });
  });

  describe("javascript scripts", () => {
    it("returns empty array for javascript scripts", () => {
      const script = `#!/usr/bin/env node
const axios = require('axios');
axios.get('http://target.com')
  .then(response => console.log(response.data));`;

      const warnings = validatePocPortability(script, "javascript");

      expect(warnings).toHaveLength(0);
    });
  });
});
