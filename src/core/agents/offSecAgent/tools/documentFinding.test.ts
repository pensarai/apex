import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CredentialManager } from "../../../credentials";
import { AgentEventBus, type AgentEventMap } from "../../../eventBus";
import { setLogSink } from "../../../logger/structured";
import { LocalBackends } from "../../../tools/backends/local";
import type { ToolBackends } from "../../../tools/backends/types";
import { scoreFindingWithCVSS } from "../../specialized/cvssScorer";
import {
  type FindingJudgeResult,
  judgeFinding,
} from "../../specialized/findingJudge";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import {
  documentVulnerability,
  validatePocPortability,
} from "./documentFinding";
import { PerCommandShell } from "./perCommandShell";
import type { ScriptSyntaxResult } from "./scriptSyntaxCheck";

vi.mock("node:path", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:path")>();
  return {
    ...actual,
    join: (...parts: string[]) =>
      parts[0]?.startsWith("/workspace/repo/.pensar") ||
      parts[0]?.includes("/remote-")
        ? actual.win32.join(...parts)
        : actual.join(...parts),
  };
});

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
const mockedScoreFindingWithCVSS = vi.mocked(scoreFindingWithCVSS);

type DocumentToolResult = {
  success: boolean;
  error?: string;
  judgeRejected?: boolean;
  judgeReasoning?: string;
  finding?: {
    credentialIds?: string[];
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
    credentialIds: [] as string[],
  };
}

// PoC execution now runs through `ctx.backends.command` (LocalBackends when
// unsandboxed), which requires a real commandShell — created per context
// and disposed in the module-level afterEach below.
const createdShells: PerCommandShell[] = [];

function makeToolContext(rootPath: string) {
  const pocsPath = join(rootPath, "pocs");
  const findingsPath = join(rootPath, "findings");
  const logsPath = join(rootPath, "logs");
  mkdirSync(pocsPath, { recursive: true });
  mkdirSync(findingsPath, { recursive: true });
  mkdirSync(logsPath, { recursive: true });

  const commandShell = new PerCommandShell({ cwd: rootPath });
  createdShells.push(commandShell);

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
    subagentSpawner: inProcessSubagentSpawner,
    commandShell,
  } as unknown as Parameters<typeof documentVulnerability>[0];
}

afterEach(() => {
  while (createdShells.length > 0) {
    createdShells.pop()?.dispose();
  }
});

describe("documentVulnerability judge handling", () => {
  let rootPath: string;

  beforeEach(() => {
    rootPath = mkdtempSync(join(tmpdir(), "apex-document-finding-"));
    mockedJudgeFinding.mockReset();
  });

  afterEach(() => {
    rmSync(rootPath, { recursive: true, force: true });
  });

  it("requires structured attack paths for multi-member findings", () => {
    const tool = documentVulnerability(makeToolContext(rootPath));

    expect(tool.description).toContain(
      "populate attackPath with every hop in order",
    );
    expect(tool.description).toContain(
      "do not leave the chain only in the description or evidence",
    );
  });

  it("blocks a financial-mutation PoC before executing it", async () => {
    const ctx = makeToolContext(rootPath);
    const tool = documentVulnerability(ctx);
    const result = (await tool.execute?.(
      {
        ...makeDocumentInput(),
        pocName: "large_payout",
        pocContent:
          `curl -X POST https://example.com/api/v2/payout-links ` +
          `-H 'Content-Type: application/json' ` +
          `-d '{"amount":99999999,"funding_source":"ach"}'`,
      },
      {
        toolCallId: "test",
        messages: [],
      },
    )) as DocumentToolResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("Destructive action blocked");
    expect(existsSync(join(ctx.session.pocsPath, "poc_large_payout.sh"))).toBe(
      false,
    );
    expect(mockedJudgeFinding).not.toHaveBeenCalled();
  });

  it("blocks an out-of-scope PoC before executing it", async () => {
    const ctx = makeToolContext(rootPath);
    const tool = documentVulnerability(ctx);
    const result = (await tool.execute?.(
      {
        ...makeDocumentInput(),
        pocName: "external_target",
        pocType: "python",
        pocContent:
          'import requests\nrequests.get("https://outside.example.net/admin")',
      },
      {
        toolCallId: "test",
        messages: [],
      },
    )) as DocumentToolResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("Scope violation");
    expect(
      existsSync(join(ctx.session.pocsPath, "poc_external_target.py")),
    ).toBe(false);
    expect(mockedJudgeFinding).not.toHaveBeenCalled();
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

  it("rejects an out-of-scope endpoint before POC/judge run (keeps infra findings out of the registry)", async () => {
    const ctx = makeToolContext(rootPath);
    const tool = documentVulnerability(ctx);
    const result = (await tool.execute?.(
      { ...makeDocumentInput(), endpoint: "http://127.0.0.1:9000/metrics" },
      { toolCallId: "test", messages: [] },
    )) as DocumentToolResult & { error?: string };

    expect(result.success).toBe(false);
    expect(result.error).toContain("Scope violation");
    // Fail closed before any judge/POC work.
    expect(mockedJudgeFinding).not.toHaveBeenCalled();
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

  it("comments every line of a multiline PoC description", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());

    const ctx = makeToolContext(rootPath);
    const tool = documentVulnerability(ctx);
    const result = (await tool.execute?.(
      {
        ...makeDocumentInput(),
        pocDescription: "Safe description\nexit 42",
      },
      {
        toolCallId: "test",
        messages: [],
      },
    )) as DocumentToolResult;

    expect(result.success).toBe(true);
    const poc = readFileSync(
      join(ctx.session.pocsPath, "poc_admin_data.sh"),
      "utf8",
    );
    expect(poc).toContain("# POC: Safe description\n# exit 42");
    expect(poc).not.toContain("\nexit 42\n");
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

describe("documentVulnerability credential provenance", () => {
  let rootPath: string;

  beforeEach(() => {
    rootPath = mkdtempSync(join(tmpdir(), "apex-document-finding-"));
    mockedJudgeFinding.mockReset();
  });

  afterEach(() => {
    rmSync(rootPath, { recursive: true, force: true });
  });

  it("records an empty credentialIds list for an unauthenticated proof", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const ctx = makeToolContext(rootPath);
    const tool = documentVulnerability(ctx);
    const result = (await tool.execute?.(makeDocumentInput(), {
      toolCallId: "test",
      messages: [],
    })) as DocumentToolResult;

    expect(result.success).toBe(true);
    expect(result.finding?.credentialIds).toEqual([]);
  });

  it("persists known credential IDs on the finding without secret values", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const cm = new CredentialManager();
    const id = cm.addFromAuthCredentials({
      id: "cred-stable",
      username: "alice",
      password: "s3cret-password",
      role: "admin",
    });
    const base = makeToolContext(rootPath);
    const ctx = {
      ...base,
      credentialManager: cm,
      session: { ...base.session, credentialManager: cm },
    };
    const tool = documentVulnerability(ctx);
    const result = (await tool.execute?.(
      { ...makeDocumentInput(), credentialIds: [id] },
      { toolCallId: "test", messages: [] },
    )) as DocumentToolResult;

    expect(result.success).toBe(true);
    expect(result.finding?.credentialIds).toEqual(["cred-stable"]);
    expect(JSON.stringify(result.finding)).not.toContain("s3cret-password");
  });

  it("rejects unknown credential IDs before running the POC", async () => {
    const cm = new CredentialManager();
    cm.addFromAuthCredentials({
      id: "cred-known",
      username: "alice",
      password: "s3cret",
    });
    const base = makeToolContext(rootPath);
    const ctx = {
      ...base,
      credentialManager: cm,
      session: { ...base.session, credentialManager: cm },
    };
    const tool = documentVulnerability(ctx);
    const result = (await tool.execute?.(
      { ...makeDocumentInput(), credentialIds: ["cred-missing"] },
      { toolCallId: "test", messages: [] },
    )) as DocumentToolResult & { error?: string };

    expect(result.success).toBe(false);
    expect(result.error).toContain("cred-missing");
    expect(mockedJudgeFinding).not.toHaveBeenCalled();
    expect(existsSync(join(ctx.session.pocsPath, "poc_admin_data.sh"))).toBe(
      false,
    );
  });
});

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

// ---------------------------------------------------------------------------
// CVSS scoring fallback. A failed scorer substitutes FALLBACK_CVSS, which sets
// the finding's severity too, so the failure has to be visible in the logs and
// flagged on the finding.
// ---------------------------------------------------------------------------

describe("documentVulnerability CVSS fallback", () => {
  let rootPath: string;
  let logLines: string[];

  beforeEach(() => {
    rootPath = mkdtempSync(join(tmpdir(), "apex-cvss-fallback-"));
    mockedJudgeFinding.mockReset();
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    logLines = [];
    process.env.PENSAR_LOG_FORMAT = "json";
    setLogSink((line) => logLines.push(line));
  });

  afterEach(() => {
    setLogSink(null);
    delete process.env.PENSAR_LOG_FORMAT;
    rmSync(rootPath, { recursive: true, force: true });
  });

  function readPersistedFinding(findingsPath: string) {
    const jsonFile = readdirSync(findingsPath).find((f) => f.endsWith(".json"));
    if (!jsonFile) throw new Error("no finding JSON was persisted");
    return JSON.parse(readFileSync(join(findingsPath, jsonFile), "utf8")) as {
      severity: string;
      cvss: { scored: boolean; score: number; vectorString: string };
    };
  }

  it("marks the finding unscored and warns with the real error", async () => {
    mockedScoreFindingWithCVSS.mockRejectedValueOnce(
      new Error("response did not match schema"),
    );

    const ctx = makeToolContext(rootPath);
    const result = (await documentVulnerability(ctx).execute?.(
      makeDocumentInput(),
      { toolCallId: "test", messages: [] },
    )) as DocumentToolResult;

    expect(result.success).toBe(true);

    const persisted = readPersistedFinding(ctx.session.findingsPath);
    expect(persisted.cvss.scored).toBe(false);
    expect(persisted.cvss.score).toBe(5.0);
    expect(persisted.cvss.vectorString).toBe("");

    const warning = logLines
      .map((line) => JSON.parse(line) as Record<string, unknown>)
      .find((record) => record.level === "WARN" && record.cancelled === false);
    expect(warning?.msg).toBe(
      "CVSS scoring fell back to estimated MEDIUM severity",
    );
    expect(warning?.error).toBe("response did not match schema");
  });

  it("does not retry a failed scorer", async () => {
    mockedScoreFindingWithCVSS.mockClear();
    mockedScoreFindingWithCVSS.mockRejectedValueOnce(
      new Error("response did not match schema"),
    );

    await documentVulnerability(makeToolContext(rootPath)).execute?.(
      makeDocumentInput(),
      { toolCallId: "test", messages: [] },
    );

    expect(mockedScoreFindingWithCVSS).toHaveBeenCalledTimes(1);
  });

  it("marks the finding scored when the scorer succeeds", async () => {
    const ctx = makeToolContext(rootPath);
    await documentVulnerability(ctx).execute?.(makeDocumentInput(), {
      toolCallId: "test",
      messages: [],
    });

    const persisted = readPersistedFinding(ctx.session.findingsPath);
    expect(persisted.cvss.scored).toBe(true);
    expect(persisted.cvss.vectorString).toContain("CVSS:4.0/");
    expect(
      logLines.some((line) => line.includes("fell back to estimated MEDIUM")),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// PoC + finding writes route through ctx.backends.fs, once, with no direct
// host `pocsPath`/`findingsPath` write bypassing the backend.
// ---------------------------------------------------------------------------

describe("documentVulnerability writes through ctx.backends.fs", () => {
  let rootPath: string;

  beforeEach(() => {
    rootPath = mkdtempSync(join(tmpdir(), "apex-document-finding-backend-"));
    mockedJudgeFinding.mockReset();
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
  });

  afterEach(() => {
    rmSync(rootPath, { recursive: true, force: true });
  });

  it("preserves both summary entries when findings finish concurrently", async () => {
    const first = makeToolContext(rootPath);
    const second = makeToolContext(rootPath);
    const results = await Promise.all(
      [first, second].map((ctx, i) =>
        documentVulnerability(ctx).execute?.(
          {
            ...makeDocumentInput(),
            title: `Finding ${i}`,
            pocName: `concurrent_${i}`,
          },
          { toolCallId: `finding-${i}`, messages: [] },
        ),
      ),
    );
    for (const result of results)
      expect(result).toMatchObject({ success: true });
    const summary = readFileSync(join(rootPath, "findings-summary.md"), "utf8");
    expect(summary).toContain("Finding 0");
    expect(summary).toContain("Finding 1");
  });

  it.each([
    "accepted",
    "rejected",
    "duplicate",
  ])("keeps classic sandbox PoCs owned and cleans up %s findings", async (outcome) => {
    const ctx = makeToolContext(rootPath);
    if (outcome === "rejected")
      mockedJudgeFinding.mockResolvedValue({
        ...makeAcceptedJudgeResult(),
        valid: false,
      });
    if (outcome === "duplicate")
      ctx.findingsRegistry = {
        isDuplicate: () => ({ duplicate: false }),
        register: async () => ({ duplicate: true }),
      } as unknown as typeof ctx.findingsRegistry;
    const remoteRoot = mkdtempSync(join(rootPath, "remote-"));
    const remoteShell = new PerCommandShell({ cwd: remoteRoot });
    ctx.agentCwd = remoteRoot;
    const execute = vi.fn(
      async (
        command: string,
        opts?: {
          timeout?: number;
          cwd?: string;
          envVars?: Record<string, string>;
        },
      ) => {
        const result = await remoteShell.execute(command, {
          cwd: opts?.cwd ?? remoteRoot,
          env: opts?.envVars,
          timeoutSeconds: opts?.timeout,
        });
        return { ...result, success: result.exitCode === 0 };
      },
    );
    ctx.sandbox = { type: "linux", execute };
    const hostExecute = vi.spyOn(ctx.commandShell!, "execute");
    const result = await documentVulnerability(ctx).execute?.(
      makeDocumentInput(),
      { toolCallId: "test", messages: [] },
    );
    expect(result).toMatchObject({ success: outcome === "accepted" });
    if (outcome === "rejected")
      expect(result).toMatchObject({ judgeRejected: true });
    if (outcome === "duplicate")
      expect(result).toMatchObject({ duplicate: true });
    expect(execute).toHaveBeenCalledWith(
      `bash '${posix.join(remoteRoot, ".pensar/pocs/poc_admin_data.sh")}'`,
      expect.objectContaining({ timeout: 60, cwd: remoteRoot }),
    );
    const remotePath = posix.join(remoteRoot, ".pensar/pocs/poc_admin_data.sh");
    expect(existsSync(remotePath)).toBe(outcome === "accepted");
    await remoteShell.dispose();
    expect(hostExecute).not.toHaveBeenCalled();
    expect(existsSync(join(ctx.session.pocsPath, "poc_admin_data.sh"))).toBe(
      outcome === "accepted",
    );
    expect(
      readdirSync(ctx.session.findingsPath).some((path) =>
        path.endsWith(".json"),
      ),
    ).toBe(outcome === "accepted");
  });

  it("keeps sandbox artifacts POSIX even when host join uses Windows separators", async () => {
    const base = makeToolContext(rootPath);
    const local = LocalBackends(base);
    const writes: string[] = [];
    const ctx = {
      ...base,
      backends: {
        ...local,
        sandboxed: true,
        fs: {
          ...local.fs,
          write: async (path: string) => {
            writes.push(path);
            return { success: true, path, error: "" };
          },
          readRaw: async (path: string) => ({
            success: true,
            content: "",
            path,
            error: "",
          }),
        },
        command: {
          async *run() {
            yield {
              type: "stdout" as const,
              seq: 0,
              bytes: "admin data leaked",
            };
            yield { type: "end" as const, exitCode: 0, timedOut: false };
          },
        },
      },
    };
    const result = await documentVulnerability(ctx).execute?.(
      makeDocumentInput(),
      { toolCallId: "remote", messages: [] },
    );
    expect(result).toMatchObject({ success: true });
    expect(writes).toContain("/workspace/repo/.pensar/pocs/poc_admin_data.sh");
    expect(
      writes.some(
        (path) =>
          path.startsWith("/workspace/repo/.pensar/findings/") &&
          path.endsWith(".json"),
      ),
    ).toBe(true);
    expect(writes).toContain("/workspace/repo/.pensar/findings-summary.md");
    expect(writes.every((path) => !path.includes("\\"))).toBe(true);
  });

  it("writes the PoC and the finding json/md via the injected backend, not a second host write", async () => {
    const base = makeToolContext(rootPath);
    const local = LocalBackends(base);
    const writeSpy = vi.fn(local.fs.write.bind(local.fs));
    const backends = { ...local, fs: { ...local.fs, write: writeSpy } };
    const ctx = { ...base, backends: backends as ToolBackends };

    const result = (await documentVulnerability(ctx).execute?.(
      makeDocumentInput(),
      { toolCallId: "test", messages: [] },
    )) as DocumentToolResult;

    expect(result.success).toBe(true);

    const pocPath = join(ctx.session.pocsPath, "poc_admin_data.sh");
    const writtenPaths = writeSpy.mock.calls.map((c) => c[0]);
    expect(writtenPaths).toContain(pocPath);
    expect(writtenPaths.some((p) => p.endsWith(".json"))).toBe(true);
    expect(writtenPaths.some((p) => p.endsWith(".md"))).toBe(true);

    // The backend call actually produced the file — no separate host write.
    expect(existsSync(pocPath)).toBe(true);
    expect(readFileSync(pocPath, "utf8")).toContain("admin data leaked");
  });

  it("throws (and unregisters the finding) when the injected backend fails to write the finding json", async () => {
    const findingsRegistry = {
      isDuplicate: () => ({ duplicate: false }),
      register: vi.fn(async () => ({ duplicate: false })),
      unregister: vi.fn(async () => {}),
    };
    const base = {
      ...makeToolContext(rootPath),
      findingsRegistry: findingsRegistry as never,
    };
    const local = LocalBackends(base);
    const writeSpy = vi.fn(
      async (
        path: string,
        content: string,
        o: { mode: "create" | "overwrite" },
      ) => {
        if (path.endsWith(".json")) {
          return { success: false, error: "disk full", path };
        }
        return local.fs.write(path, content, o);
      },
    );
    const backends = { ...local, fs: { ...local.fs, write: writeSpy } };
    const ctx = { ...base, backends: backends as ToolBackends };

    const result = (await documentVulnerability(ctx).execute?.(
      makeDocumentInput(),
      { toolCallId: "test", messages: [] },
    )) as DocumentToolResult & { error?: string };

    expect(result.success).toBe(false);
    expect(result.error).toContain("disk full");
    expect(findingsRegistry.unregister).toHaveBeenCalled();
  });
});

function sha256(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

describe("documentVulnerability native syntax checks", () => {
  let rootPath: string;

  beforeEach(() => {
    rootPath = mkdtempSync(join(tmpdir(), "apex-document-finding-"));
    mockedJudgeFinding.mockReset();
  });

  afterEach(() => {
    rmSync(rootPath, { recursive: true, force: true });
  });

  // Classic-sandbox harness: file ops and commands all route through the
  // sandbox transport (a real shell at remoteRoot), never the host shell.
  function sandboxContext(
    intercept?: (
      command: string,
    ) => { exitCode: number; stdout: string; stderr: string } | undefined,
  ) {
    const ctx = makeToolContext(rootPath);
    const remoteRoot = mkdtempSync(join(rootPath, "remote-"));
    const remoteShell = new PerCommandShell({ cwd: remoteRoot });
    createdShells.push(remoteShell);
    ctx.agentCwd = remoteRoot;
    const commands: Array<{ command: string; cwd?: string; timeout?: number }> =
      [];
    const scriptBytes: Array<{ command: string; bytes: string }> = [];
    const execute = vi.fn(
      async (
        command: string,
        opts?: {
          timeout?: number;
          cwd?: string;
          envVars?: Record<string, string>;
        },
      ) => {
        commands.push({ command, cwd: opts?.cwd, timeout: opts?.timeout });
        const intercepted = intercept?.(command);
        if (intercepted)
          return { ...intercepted, success: intercepted.exitCode === 0 };
        const scriptPath = (command.split(" ").pop() ?? "").replace(
          /^'|'$/g,
          "",
        );
        if (scriptPath.includes(".pensar/pocs/") && existsSync(scriptPath))
          scriptBytes.push({
            command,
            bytes: readFileSync(scriptPath, "utf8"),
          });
        const result = await remoteShell.execute(command, {
          cwd: opts?.cwd ?? remoteRoot,
          env: opts?.envVars,
          timeoutSeconds: opts?.timeout,
        });
        return { ...result, success: result.exitCode === 0 };
      },
    );
    ctx.sandbox = { type: "linux", execute };
    return { ctx, commands, scriptBytes, remoteRoot };
  }

  it("blocks an intentionally malformed PoC before execution, with file/line feedback", async () => {
    const { ctx, commands, remoteRoot } = sandboxContext();
    const input = makeDocumentInput();
    input.pocName = "broken_syntax";
    input.pocContent = 'if [ -n x ]; then\n  echo "unclosed"\n';

    const result = (await documentVulnerability(ctx).execute?.(input, {
      toolCallId: "syntax",
      messages: [],
    })) as DocumentToolResult & {
      syntaxFailed?: boolean;
      syntaxCheck?: ScriptSyntaxResult;
      message?: string;
    };

    expect(result).toMatchObject({ success: false, syntaxFailed: true });
    expect(result.syntaxCheck?.status).toBe("invalid");
    expect(result.syntaxCheck?.detail).toMatch(
      /poc_broken_syntax\.sh:\d+: syntax error/,
    );
    expect(result.syntaxCheck?.contentHash).toBeTruthy();
    expect(result.message).toContain("syntax check");
    expect(mockedJudgeFinding).not.toHaveBeenCalled();
    // The prepared executable was checked but never run.
    const staged = posix.join(remoteRoot, ".pensar/pocs/poc_broken_syntax.sh");
    expect(commands.some((c) => c.command === `bash -n '${staged}'`)).toBe(
      true,
    );
    expect(commands.some((c) => c.command === `bash '${staged}'`)).toBe(false);
    expect(existsSync(staged)).toBe(false);
    expect(existsSync(join(ctx.session.pocsPath, "poc_broken_syntax.sh"))).toBe(
      false,
    );
  });

  it("checks the exact staged bytes with the execution cwd before running them", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const { ctx, commands, scriptBytes, remoteRoot } = sandboxContext();

    const result = (await documentVulnerability(ctx).execute?.(
      makeDocumentInput(),
      { toolCallId: "syntax-ok", messages: [] },
    )) as DocumentToolResult;

    expect(result).toMatchObject({ success: true });
    const staged = posix.join(remoteRoot, ".pensar/pocs/poc_admin_data.sh");
    const check = commands.find((c) => c.command === `bash -n '${staged}'`);
    const run = commands.find((c) => c.command === `bash '${staged}'`);
    expect(check).toBeTruthy();
    expect(run).toBeTruthy();
    expect(commands.indexOf(check as never)).toBeLessThan(
      commands.indexOf(run as never),
    );
    // Same per-command cwd isolation and a bounded check deadline.
    expect(check?.cwd).toBe(remoteRoot);
    expect(check?.timeout).toBe(5);
    expect(run?.cwd).toBe(remoteRoot);
    expect(run?.timeout).toBe(60);
    // The checked bytes are the executed bytes: the generated script with
    // shebang and header, not the agent's raw pocContent.
    const checked = scriptBytes.find(
      (e) => e.command === check?.command,
    )?.bytes;
    const executed = scriptBytes.find((e) => e.command === run?.command)?.bytes;
    expect(checked).toBeTruthy();
    expect(checked).toBe(executed);
    expect(checked?.startsWith("#!/bin/bash\n# POC:")).toBe(true);
    expect(checked?.includes("set -e")).toBe(true);
    expect(checked?.includes('echo "admin data leaked"')).toBe(true);
    expect(checked).not.toBe(makeDocumentInput().pocContent);
    // The surfaced verdict certifies exactly those bytes by hash.
    const typedResult = result as DocumentToolResult & {
      syntaxCheck?: ScriptSyntaxResult;
    };
    expect(typedResult.syntaxCheck?.status).toBe("valid");
    expect(typedResult.syntaxCheck?.contentHash).toBe(
      sha256(checked as string),
    );
  });

  it("checks generated JavaScript with node before executing it", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const { ctx, commands, remoteRoot } = sandboxContext();
    const input = {
      ...makeDocumentInput(),
      pocType: "javascript" as const,
      pocName: "js_poc",
      pocContent: 'console.log("js poc ok");',
    };

    const result = (await documentVulnerability(ctx).execute?.(input, {
      toolCallId: "js",
      messages: [],
    })) as DocumentToolResult;

    expect(result).toMatchObject({ success: true });
    const staged = posix.join(remoteRoot, ".pensar/pocs/poc_js_poc.js");
    const check = commands.find(
      (c) => c.command === `node --check '${staged}'`,
    );
    const run = commands.find((c) => c.command === `node '${staged}'`);
    expect(check).toBeTruthy();
    expect(run).toBeTruthy();
    expect(commands.indexOf(check as never)).toBeLessThan(
      commands.indexOf(run as never),
    );
  });

  it("still executes and documents the PoC when the checker is missing (unchecked)", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const { ctx, commands, remoteRoot } = sandboxContext((command) =>
      command.includes("bash -n ")
        ? { exitCode: 127, stdout: "", stderr: "bash: command not found" }
        : undefined,
    );

    const result = (await documentVulnerability(ctx).execute?.(
      makeDocumentInput(),
      { toolCallId: "unchecked", messages: [] },
    )) as DocumentToolResult;

    expect(result).toMatchObject({ success: true });
    const staged = posix.join(remoteRoot, ".pensar/pocs/poc_admin_data.sh");
    expect(commands.some((c) => c.command === `bash -n '${staged}'`)).toBe(
      true,
    );
    expect(commands.some((c) => c.command === `bash '${staged}'`)).toBe(true);
  });

  it("passes the configured environment to both checker and execution through injected backends", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const ctx = makeToolContext(rootPath);
    ctx.environmentVariables = {
      PATH: "/custom/bin",
      APEX_ENV_MARKER: "configured",
    };
    const local = LocalBackends(ctx);
    const run = vi.fn<ToolBackends["command"]["run"]>(async function* () {
      yield { type: "stdout" as const, seq: 0, bytes: "admin data leaked" };
      yield { type: "end" as const, exitCode: 0, timedOut: false };
    });
    ctx.backends = {
      ...local,
      command: { run },
    } as unknown as ToolBackends;

    const result = (await documentVulnerability(ctx).execute?.(
      makeDocumentInput(),
      { toolCallId: "env", messages: [] },
    )) as DocumentToolResult;

    expect(result).toMatchObject({ success: true });
    const staged = join(ctx.session.pocsPath, "poc_admin_data.sh");
    const check = run.mock.calls.find((c) => c[0] === `bash -n '${staged}'`);
    const executed = run.mock.calls.find((c) => c[0] === `bash '${staged}'`);
    expect(check?.[1]).toMatchObject({
      envVars: { PATH: "/custom/bin", APEX_ENV_MARKER: "configured" },
    });
    expect(executed?.[1]).toMatchObject({
      envVars: { PATH: "/custom/bin", APEX_ENV_MARKER: "configured" },
    });
  });

  it("blocks a python PoC whose top-level return only full compilation rejects", async () => {
    const { ctx, commands, remoteRoot } = sandboxContext();
    const input = {
      ...makeDocumentInput(),
      pocType: "python" as const,
      pocName: "py_return",
      pocContent: "return 1",
    };

    const result = (await documentVulnerability(ctx).execute?.(input, {
      toolCallId: "py",
      messages: [],
    })) as DocumentToolResult & {
      syntaxFailed?: boolean;
      syntaxCheck?: ScriptSyntaxResult;
    };

    expect(result).toMatchObject({ success: false, syntaxFailed: true });
    expect(result.syntaxCheck?.status).toBe("invalid");
    expect(result.syntaxCheck?.detail).toMatch(/return.*outside function/);
    expect(mockedJudgeFinding).not.toHaveBeenCalled();
    const staged = posix.join(remoteRoot, ".pensar/pocs/poc_py_return.py");
    expect(commands.some((c) => c.command === `python3 '${staged}'`)).toBe(
      false,
    );
  });

  it("blocks a valid python generator whose declared emitted JavaScript is invalid", async () => {
    const { ctx, commands, remoteRoot } = sandboxContext();
    const emitted = "const = 1;\n";
    const input = {
      ...makeDocumentInput(),
      pocType: "python" as const,
      pocName: "gen_emit",
      pocContent: [
        'with open("poc_bad_emit.js", "w") as f:',
        '    f.write("const = 1;")',
        "    f.write(chr(10))",
        'print("emitted")',
      ].join("\n"),
      generatedExecutableArtifacts: [
        { path: "poc_bad_emit.js", language: "javascript" as const },
      ],
    };

    const result = (await documentVulnerability(ctx).execute?.(input, {
      toolCallId: "gen",
      messages: [],
    })) as DocumentToolResult & {
      syntaxFailed?: boolean;
      syntaxCheck?: ScriptSyntaxResult;
      generatedArtifactChecks?: Array<
        {
          path: string;
          language: string;
        } & ScriptSyntaxResult
      >;
      message?: string;
    };

    expect(result).toMatchObject({ success: false, syntaxFailed: true });
    // The wrapper itself parsed fine; only the declared emitted artifact failed.
    expect(result.syntaxCheck?.status).toBe("valid");
    expect(result.generatedArtifactChecks).toHaveLength(1);
    const artifact = result.generatedArtifactChecks?.[0];
    expect(artifact).toMatchObject({
      path: "poc_bad_emit.js",
      language: "javascript",
      status: "invalid",
    });
    expect(artifact?.detail).toMatch(
      /poc_bad_emit\.js:1: SyntaxError: Unexpected token/,
    );
    expect(artifact?.contentHash).toBe(sha256(emitted));
    expect(result.message).toContain("Generated executable");
    expect(mockedJudgeFinding).not.toHaveBeenCalled();
    // Declared artifacts are checked, never mutated or deleted.
    expect(existsSync(posix.join(remoteRoot, "poc_bad_emit.js"))).toBe(true);
    // The wrapper PoC itself was still executed once, then cleaned up.
    const stagedWrapper = posix.join(
      remoteRoot,
      ".pensar/pocs/poc_gen_emit.py",
    );
    expect(
      commands.some((c) => c.command === `python3 '${stagedWrapper}'`),
    ).toBe(true);
    expect(existsSync(stagedWrapper)).toBe(false);
    expect(existsSync(join(ctx.session.pocsPath, "poc_gen_emit.py"))).toBe(
      false,
    );
  });

  it("documents a generator whose declared emitted artifact parses, certifying it by hash", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const { ctx, remoteRoot } = sandboxContext();
    const emitted = 'console.log("emitted ok");\n';
    const input = {
      ...makeDocumentInput(),
      pocType: "python" as const,
      pocName: "gen_good",
      pocContent: [
        'with open("poc_good_emit.js", "w") as f:',
        '    f.write("console.log(" + chr(34) + "emitted ok" + chr(34) + ");")',
        "    f.write(chr(10))",
        'print("emitted")',
      ].join("\n"),
      generatedExecutableArtifacts: [
        { path: "poc_good_emit.js", language: "javascript" as const },
      ],
    };

    const result = (await documentVulnerability(ctx).execute?.(input, {
      toolCallId: "gen-ok",
      messages: [],
    })) as DocumentToolResult & {
      syntaxCheck?: ScriptSyntaxResult;
      generatedArtifactChecks?: Array<
        {
          path: string;
          language: string;
        } & ScriptSyntaxResult
      >;
    };

    expect(result).toMatchObject({ success: true });
    expect(result.syntaxCheck?.status).toBe("valid");
    expect(result.generatedArtifactChecks).toHaveLength(1);
    expect(result.generatedArtifactChecks?.[0]).toMatchObject({
      path: "poc_good_emit.js",
      language: "javascript",
      status: "valid",
    });
    expect(result.generatedArtifactChecks?.[0]?.contentHash).toBe(
      sha256(emitted),
    );
    expect(existsSync(posix.join(remoteRoot, "poc_good_emit.js"))).toBe(true);
  });

  it("surfaces unchecked, without blocking, when a declared artifact is absent after the run", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const { ctx } = sandboxContext();
    const input = {
      ...makeDocumentInput(),
      pocType: "python" as const,
      pocName: "gen_missing",
      pocContent: 'print("no emission")',
      generatedExecutableArtifacts: [
        { path: "never_emitted.js", language: "javascript" as const },
      ],
    };

    const result = (await documentVulnerability(ctx).execute?.(input, {
      toolCallId: "gen-missing",
      messages: [],
    })) as DocumentToolResult & {
      generatedArtifactChecks?: Array<
        {
          path: string;
          language: string;
        } & ScriptSyntaxResult
      >;
    };

    expect(result).toMatchObject({ success: true });
    expect(result.generatedArtifactChecks).toHaveLength(1);
    expect(result.generatedArtifactChecks?.[0]).toMatchObject({
      path: "never_emitted.js",
      status: "unchecked",
    });
    expect(result.generatedArtifactChecks?.[0]?.reason).toContain(
      "could not read the script bytes",
    );
  });

  it("rejects a declared artifact path that escapes the workspace before anything runs", async () => {
    const { ctx, commands } = sandboxContext();
    const input = {
      ...makeDocumentInput(),
      generatedExecutableArtifacts: [
        { path: "../../outside.js", language: "bash" as const },
      ],
    };

    const result = (await documentVulnerability(ctx).execute?.(input, {
      toolCallId: "escape",
      messages: [],
    })) as DocumentToolResult & { message?: string };

    expect(result).toMatchObject({ success: false });
    expect(result.message).toContain(
      "Generated executable declaration rejected",
    );
    expect(result.message).toContain("escapes");
    expect(mockedJudgeFinding).not.toHaveBeenCalled();
    // Nothing was staged, checked or executed.
    expect(commands.some((c) => c.command.includes("bash -n "))).toBe(false);
    expect(commands.some((c) => /^bash '/.test(c.command))).toBe(false);
  });
});

describe("documentVulnerability local retained PoC checks (confined helper workspace)", () => {
  let rootPath: string;

  beforeEach(() => {
    rootPath = mkdtempSync(join(tmpdir(), "apex-document-finding-"));
    mockedJudgeFinding.mockReset();
  });

  afterEach(() => {
    rmSync(rootPath, { recursive: true, force: true });
  });

  // Local harness mirroring helper agents: a confined file workspace for
  // file tools and commands, with session PoC artifacts retained under a
  // separate session root that the workspace backend must reject.
  function localContext() {
    const ctx = makeToolContext(rootPath);
    const helperRoot = mkdtempSync(join(rootPath, "helper-"));
    ctx.agentCwd = helperRoot;
    ctx.fileWorkspaceRoot = helperRoot;
    return { ctx, helperRoot };
  }

  it("checks the retained local PoC through the artifact owner despite the confined workspace", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const { ctx } = localContext();
    const argv = vi.spyOn(PerCommandShell.prototype, "executeArgv");
    try {
      const result = (await documentVulnerability(ctx).execute?.(
        makeDocumentInput(),
        { toolCallId: "local-ok", messages: [] },
      )) as DocumentToolResult & { syntaxCheck?: ScriptSyntaxResult };

      expect(result).toMatchObject({ success: true });
      // The check actually ran and decided, instead of silently reading
      // through the confined workspace backend and yielding unchecked.
      expect(result.syntaxCheck?.status).toBe("valid");
      const retained = join(ctx.session.pocsPath, "poc_admin_data.sh");
      expect(result.syntaxCheck?.contentHash).toBe(
        sha256(readFileSync(retained, "utf8")),
      );
      expect(
        argv.mock.calls.some(
          ([runner, args]) => runner === "bash" && args[0] === "-n",
        ),
      ).toBe(true);
    } finally {
      argv.mockRestore();
    }
  });

  it("blocks an invalid retained local PoC before execution", async () => {
    const { ctx } = localContext();
    const input = makeDocumentInput();
    input.pocName = "local_broken";
    input.pocContent = 'if [ -n x ]; then\n  echo "unclosed"\n';

    const result = (await documentVulnerability(ctx).execute?.(input, {
      toolCallId: "local-bad",
      messages: [],
    })) as DocumentToolResult & {
      syntaxFailed?: boolean;
      syntaxCheck?: ScriptSyntaxResult;
    };

    expect(result).toMatchObject({ success: false, syntaxFailed: true });
    expect(result.syntaxCheck?.status).toBe("invalid");
    expect(result.syntaxCheck?.detail).toMatch(
      /poc_local_broken\.sh:\d+: syntax error/,
    );
    expect(mockedJudgeFinding).not.toHaveBeenCalled();
    expect(existsSync(join(ctx.session.pocsPath, "poc_local_broken.sh"))).toBe(
      false,
    );
  });

  it("bounds the retained-artifact read: oversized scripts surface as unchecked and still run", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const { ctx } = localContext();
    const input = makeDocumentInput();
    input.pocName = "oversized";
    input.pocContent = "x=1\n".repeat(270_000);
    const argv = vi.spyOn(PerCommandShell.prototype, "executeArgv");
    try {
      const result = (await documentVulnerability(ctx).execute?.(input, {
        toolCallId: "local-big",
        messages: [],
      })) as DocumentToolResult & { syntaxCheck?: ScriptSyntaxResult };

      expect(result).toMatchObject({ success: true });
      expect(result.syntaxCheck?.status).toBe("unchecked");
      expect(result.syntaxCheck?.reason).toContain("limit");
      // No checker ran at all: the read was refused by the byte cap first.
      expect(
        argv.mock.calls.some(
          ([runner, args]) => runner === "bash" && args[0] === "-n",
        ),
      ).toBe(false);
    } finally {
      argv.mockRestore();
    }
  });

  it("checks a declared emitted artifact inside the confined helper workspace", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const { ctx, helperRoot } = localContext();
    const input = {
      ...makeDocumentInput(),
      pocType: "python" as const,
      pocName: "local_gen",
      pocContent: [
        'with open("poc_local_emit.js", "w") as f:',
        '    f.write("console.log(" + chr(34) + "emitted ok" + chr(34) + ");")',
        "    f.write(chr(10))",
        'print("emitted")',
      ].join("\n"),
      generatedExecutableArtifacts: [
        { path: "poc_local_emit.js", language: "javascript" as const },
      ],
    };

    const result = (await documentVulnerability(ctx).execute?.(input, {
      toolCallId: "local-gen",
      messages: [],
    })) as DocumentToolResult & {
      syntaxCheck?: ScriptSyntaxResult;
      generatedArtifactChecks?: Array<
        { path: string; language: string } & ScriptSyntaxResult
      >;
    };

    expect(result).toMatchObject({ success: true });
    // The retained wrapper was checked through the artifact owner; the
    // declared emission was checked through the confined workspace backend.
    expect(result.syntaxCheck?.status).toBe("valid");
    expect(result.generatedArtifactChecks).toHaveLength(1);
    expect(result.generatedArtifactChecks?.[0]).toMatchObject({
      path: "poc_local_emit.js",
      language: "javascript",
      status: "valid",
    });
    expect(result.generatedArtifactChecks?.[0]?.contentHash).toBe(
      sha256('console.log("emitted ok");\n'),
    );
    expect(existsSync(join(helperRoot, "poc_local_emit.js"))).toBe(true);
  });
});

describe("documentVulnerability injected Windows backend declarations", () => {
  let rootPath: string;

  beforeEach(() => {
    rootPath = mkdtempSync(join(tmpdir(), "apex-document-finding-"));
    mockedJudgeFinding.mockReset();
  });

  afterEach(() => {
    rmSync(rootPath, { recursive: true, force: true });
  });

  // Injected Windows transport: declared paths follow the backend's own
  // command.platform (win32), not the host or the classic sandbox type.
  // The execution cwd mirrors the win32 workspace so relative declarations
  // resolve coherently.
  function windowsContext(
    overrides: { agentCwd?: string; fileWorkspaceRoot?: string } = {},
  ) {
    const ctx = makeToolContext(rootPath);
    ctx.agentCwd = overrides.agentCwd ?? "C:\\repo";
    ctx.fileWorkspaceRoot = overrides.fileWorkspaceRoot ?? "C:\\repo";
    const run = vi.fn<ToolBackends["command"]["run"]>(async function* () {
      yield { type: "stdout" as const, seq: 0, bytes: "ok" };
      yield { type: "end" as const, exitCode: 0, timedOut: false };
    });
    const readRaw = vi.fn(async (path: string) => ({
      success: true,
      error: "",
      content: 'console.log("emitted ok");\n',
      path,
    }));
    ctx.backends = {
      command: { platform: "windows", run },
      fs: {
        write: async (path: string) => ({ success: true, error: "", path }),
        readRaw,
      },
    } as unknown as ToolBackends;
    return { ctx, run, readRaw };
  }

  it("confines and checks declared artifacts with win32 paths through the injected backend", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const { ctx, run, readRaw } = windowsContext();
    const input = {
      ...makeDocumentInput(),
      generatedExecutableArtifacts: [
        { path: "poc_win_emit.js", language: "javascript" as const },
      ],
    };

    const result = (await documentVulnerability(ctx).execute?.(input, {
      toolCallId: "win",
      messages: [],
    })) as DocumentToolResult & {
      generatedArtifactChecks?: Array<
        { path: string; language: string } & ScriptSyntaxResult
      >;
    };

    expect(result).toMatchObject({ success: true });
    expect(result.generatedArtifactChecks?.[0]).toMatchObject({
      path: "poc_win_emit.js",
      language: "javascript",
      status: "valid",
    });
    // The declared path resolved win32 against the workspace root.
    expect(readRaw).toHaveBeenCalledWith("C:\\repo\\poc_win_emit.js");
    // The checker ran through the selected Windows program transport.
    const checkCall = run.mock.calls.find(
      ([, options]) => options?.envVars?.APEX_PROGRAM_FILE === "node",
    );
    expect(checkCall?.[0]).toMatch(/^powershell\.exe /);
    expect(checkCall?.[1]?.envVars?.APEX_PROGRAM_ARGS_0).toContain("--check");
    expect(checkCall?.[1]?.envVars?.APEX_PROGRAM_ARGS_0).toContain(
      "C:\\repo\\poc_win_emit.js",
    );
  });

  it("rejects a declared path that escapes the win32 workspace root before anything runs", async () => {
    const { ctx, run } = windowsContext();
    const input = {
      ...makeDocumentInput(),
      generatedExecutableArtifacts: [
        { path: "..\\outside.js", language: "javascript" as const },
      ],
    };

    const result = (await documentVulnerability(ctx).execute?.(input, {
      toolCallId: "win-escape",
      messages: [],
    })) as DocumentToolResult & { message?: string };

    expect(result).toMatchObject({ success: false });
    expect(result.message).toContain(
      "Generated executable declaration rejected",
    );
    expect(result.message).toContain("escapes");
    expect(mockedJudgeFinding).not.toHaveBeenCalled();
    expect(run).not.toHaveBeenCalled();
  });

  it("resolves relative declarations from the win32 execution cwd into a differing helper workspace", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const { ctx, run, readRaw } = windowsContext({
      agentCwd: "C:\\repo",
      fileWorkspaceRoot: "C:\\repo\\helper",
    });
    const input = {
      ...makeDocumentInput(),
      generatedExecutableArtifacts: [
        { path: "helper\\file.js", language: "javascript" as const },
      ],
    };

    const result = (await documentVulnerability(ctx).execute?.(input, {
      toolCallId: "win-cwd",
      messages: [],
    })) as DocumentToolResult & {
      generatedArtifactChecks?: Array<
        { path: string; language: string } & ScriptSyntaxResult
      >;
    };

    expect(result).toMatchObject({ success: true });
    expect(result.generatedArtifactChecks?.[0]).toMatchObject({
      path: "helper\\file.js",
      status: "valid",
    });
    // Resolved from the execution cwd, then confined to the helper root.
    expect(readRaw).toHaveBeenCalledWith("C:\\repo\\helper\\file.js");
    const checkCall = run.mock.calls.find(
      ([, options]) => options?.envVars?.APEX_PROGRAM_FILE === "node",
    );
    expect(checkCall?.[1]?.envVars?.APEX_PROGRAM_ARGS_0).toContain(
      "C:\\repo\\helper\\file.js",
    );
  });

  it("accepts win32 dot-names inside the workspace while rejecting separator-anchored escapes", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const { ctx, readRaw } = windowsContext();
    const positive = {
      ...makeDocumentInput(),
      generatedExecutableArtifacts: [
        { path: "..hidden.js", language: "javascript" as const },
      ],
    };
    const positiveResult = (await documentVulnerability(ctx).execute?.(
      positive,
      { toolCallId: "win-dot", messages: [] },
    )) as DocumentToolResult;
    expect(positiveResult).toMatchObject({ success: true });
    expect(readRaw).toHaveBeenCalledWith("C:\\repo\\..hidden.js");

    const escaping = {
      ...makeDocumentInput(),
      generatedExecutableArtifacts: [
        { path: "..\\outside.js", language: "javascript" as const },
      ],
    };
    const escapeResult = (await documentVulnerability(ctx).execute?.(escaping, {
      toolCallId: "win-escape",
      messages: [],
    })) as DocumentToolResult & { message?: string };
    expect(escapeResult).toMatchObject({ success: false });
    expect(escapeResult.message).toContain("escapes the file workspace");
  });
});

describe("documentVulnerability declared artifact resolution (execution cwd vs file workspace)", () => {
  let rootPath: string;

  beforeEach(() => {
    rootPath = mkdtempSync(join(tmpdir(), "apex-document-finding-"));
    mockedJudgeFinding.mockReset();
  });

  afterEach(() => {
    rmSync(rootPath, { recursive: true, force: true });
  });

  // Local harness where the PoC's execution cwd (the parent) differs from
  // the confined helper file workspace (a subdirectory of it).
  function cwdBoundaryContext() {
    const ctx = makeToolContext(rootPath);
    const parentDir = mkdtempSync(join(rootPath, "parent-"));
    const helperRoot = join(parentDir, "helper");
    mkdirSync(helperRoot, { recursive: true });
    ctx.agentCwd = parentDir;
    ctx.fileWorkspaceRoot = helperRoot;
    return { ctx, parentDir, helperRoot };
  }

  it("checks a declared emission found via the execution cwd inside the differing helper root", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const { ctx, helperRoot } = cwdBoundaryContext();
    const input = {
      ...makeDocumentInput(),
      pocType: "python" as const,
      pocName: "gen_cwd",
      pocContent: [
        "import os",
        'os.makedirs("helper", exist_ok=True)',
        'with open("helper/file.js", "w") as f:',
        '    f.write("console.log(" + chr(34) + "emitted ok" + chr(34) + ");")',
        "    f.write(chr(10))",
        'print("emitted")',
      ].join("\n"),
      generatedExecutableArtifacts: [
        { path: "helper/file.js", language: "javascript" as const },
      ],
    };

    const result = (await documentVulnerability(ctx).execute?.(input, {
      toolCallId: "cwd-ok",
      messages: [],
    })) as DocumentToolResult & {
      syntaxCheck?: ScriptSyntaxResult;
      generatedArtifactChecks?: Array<
        { path: string; language: string } & ScriptSyntaxResult
      >;
    };

    expect(result).toMatchObject({ success: true });
    // The retained wrapper was read through the artifact owner; the
    // declaration resolved from the execution cwd into the helper root.
    expect(result.syntaxCheck?.status).toBe("valid");
    expect(result.generatedArtifactChecks?.[0]).toMatchObject({
      path: "helper/file.js",
      language: "javascript",
      status: "valid",
    });
    expect(result.generatedArtifactChecks?.[0]?.contentHash).toBe(
      sha256('console.log("emitted ok");\n'),
    );
    expect(existsSync(join(helperRoot, "file.js"))).toBe(true);
  });

  it("fails clearly when a relative declaration lands outside the helper workspace, never inspecting another file", async () => {
    const { ctx, helperRoot } = cwdBoundaryContext();
    // Decoy at the workspace root that the old workspace-rooted resolution
    // would have silently checked instead of the emitted file.
    writeFileSync(join(helperRoot, "file.js"), 'console.log("decoy");\n');
    const input = {
      ...makeDocumentInput(),
      generatedExecutableArtifacts: [
        { path: "file.js", language: "javascript" as const },
      ],
    };
    const argv = vi.spyOn(PerCommandShell.prototype, "executeArgv");
    try {
      const result = (await documentVulnerability(ctx).execute?.(input, {
        toolCallId: "cwd-escape",
        messages: [],
      })) as DocumentToolResult & {
        message?: string;
        generatedArtifactChecks?: unknown[];
      };

      expect(result).toMatchObject({ success: false });
      expect(result.message).toContain(
        "Generated executable declaration rejected",
      );
      expect(result.message).toContain("escapes the file workspace");
      expect(result.generatedArtifactChecks).toBeUndefined();
      expect(mockedJudgeFinding).not.toHaveBeenCalled();
      // Nothing was staged, checked or executed — the decoy was never read.
      expect(argv).not.toHaveBeenCalled();
    } finally {
      argv.mockRestore();
    }
  });

  it("accepts in-workspace dot-names while rejecting an actual parent escape", async () => {
    mockedJudgeFinding.mockResolvedValue(makeAcceptedJudgeResult());
    const ctx = makeToolContext(rootPath);
    ctx.fileWorkspaceRoot = rootPath;
    const input = {
      ...makeDocumentInput(),
      pocType: "python" as const,
      pocName: "gen_dots",
      pocContent: [
        'for name in ("..hidden.js", "...emit.js"):',
        '    with open(name, "w") as f:',
        '        f.write("console.log(1);")',
        "        f.write(chr(10))",
        'print("emitted")',
      ].join("\n"),
      generatedExecutableArtifacts: [
        { path: "..hidden.js", language: "javascript" as const },
        { path: "...emit.js", language: "javascript" as const },
      ],
    };

    const result = (await documentVulnerability(ctx).execute?.(input, {
      toolCallId: "dots",
      messages: [],
    })) as DocumentToolResult & {
      generatedArtifactChecks?: Array<
        { path: string; language: string } & ScriptSyntaxResult
      >;
    };

    expect(result).toMatchObject({ success: true });
    expect(result.generatedArtifactChecks).toHaveLength(2);
    expect(result.generatedArtifactChecks?.[0]).toMatchObject({
      path: "..hidden.js",
      status: "valid",
    });
    expect(result.generatedArtifactChecks?.[1]).toMatchObject({
      path: "...emit.js",
      status: "valid",
    });
    expect(result.generatedArtifactChecks?.[0]?.contentHash).toBe(
      sha256("console.log(1);\n"),
    );

    const escaping = {
      ...makeDocumentInput(),
      generatedExecutableArtifacts: [
        { path: "../outside.js", language: "javascript" as const },
      ],
    };
    const escapeResult = (await documentVulnerability(ctx).execute?.(escaping, {
      toolCallId: "dots-escape",
      messages: [],
    })) as DocumentToolResult & { message?: string };
    expect(escapeResult).toMatchObject({ success: false });
    expect(escapeResult.message).toContain("escapes the file workspace");
  });
});
