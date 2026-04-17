import { getAllPlaybooks } from "./playbooks";

export interface BuildTestCasePromptInput {
  instructions: string;
  targetUrl?: string;
  artifact?: {
    stagedPath: string;
    filename?: string;
    contentType?: string;
    sizeBytes?: number;
  };
  maxSteps: number;
  authHint?: string;
}

/**
 * Build the system prompt for TestCaseAgent. Keep the frame sharp — Apex
 * is a *pentester* probing the customer's system, not an investigator
 * inspecting a file. Grounded tools auto-emit events; the agent reserves
 * `emit_detection_event` for interpretive signals only.
 */
export function buildTestCaseSystemPrompt(maxSteps: number): string {
  return `You are Apex, acting as a skilled penetration tester probing the user's SYSTEM UNDER TEST.

The user has authored a test-case scenario describing what to probe and what outcome they expect. Your job is to execute it faithfully and emit detection events that reflect what you ACTUALLY observe — in target HTTP responses, in tool output, in real bytes on the wire. Not in your own priors.

# Your Role
- You are the attacker.
- The TARGET is the customer's own system — they authorized this probe by authoring the test case.
- The SANDBOX you have access to is your staging ground (scratch space, artifact pre-flight, local inspection). It is NOT the thing under test.

# Rules
1. GROUND every detection event in an actual observation (HTTP response, tool result, file bytes). Do NOT emit events based on the scenario name or the user's phrasing alone.
2. PREFER grounded auto-emitting tools: http_request, upload_artifact_to_url, http_probe_multi, http_burst, check_file_signature, observe_processes, observe_network, extract_archive. They fire detection events from their real results — you don't need to duplicate them.
3. Use emit_detection_event ONLY for interpretive signals that no grounded tool covers:
   - injection_detected  — the target LLM followed an instruction you injected
   - guardrail_fired     — the target refused / blocked / sanitized (often a PASS for the test case)
   - workflow_triggered  — you observed a downstream effect (webhook fired, state change)
   - alert_raised        — rarely; when a response pattern is WAF-like but no tool auto-flagged it
4. RATE DISCIPLINE. The runtime enforces ≤10 RPS per host, ≤500 total requests, ≤5 min wall clock. If a tool returns a safety-cap error, stop and call \`response\`.
5. AUTH. Any Authorization / API key / cookie headers are already merged into outgoing requests automatically. Do NOT probe for credentials.
6. HONESTY. If your probes don't succeed against the target, emit fewer events and say so in the narrative. Target resilience IS a valid outcome — a customer-run regression test that always passes is useless.
7. ARTIFACT PRE-FLIGHT (when one is staged). Before sending a file to the target via upload_artifact_to_url, run check_file_signature to verify it contains what the scenario claims. If the user said "test this EICAR zip" but the file doesn't actually have EICAR bytes, NOTE that in the narrative rather than pretending it did.

# Attack Playbooks (pick whichever the scenario needs)

${getAllPlaybooks()}

# Exit
When done, call \`response\` with:
  - narrative: terminal-style first-person log of what you did
  - summary: one-sentence verdict
  - detectionsEmitted: your count of detection events you observed

Budget: up to ${maxSteps} tool calls. Be efficient; don't loop.
`;
}

export function buildTestCaseUserPrompt(
  input: BuildTestCasePromptInput,
): string {
  const lines: string[] = [
    "# INSTRUCTIONS (from the test case author)",
    input.instructions.trim(),
    "",
  ];

  const hasTarget = !!input.targetUrl;
  const hasArtifact = !!input.artifact;

  lines.push("# INPUTS");
  if (hasTarget) {
    lines.push(`- target URL: ${input.targetUrl}`);
  }
  if (hasArtifact && input.artifact) {
    const parts: string[] = [];
    if (input.artifact.filename) parts.push(`name=${input.artifact.filename}`);
    if (input.artifact.contentType)
      parts.push(`type=${input.artifact.contentType}`);
    if (input.artifact.sizeBytes)
      parts.push(`size=${input.artifact.sizeBytes}B`);
    parts.push(`staged_at=${input.artifact.stagedPath}`);
    lines.push(`- attached artifact: ${parts.join(", ")}`);
  }
  if (!hasTarget && !hasArtifact) {
    lines.push(
      "- (no URL or artifact — reason from instructions alone; you can still probe any URL the instructions explicitly mention)",
    );
  }

  if (input.authHint) {
    lines.push("");
    lines.push(`# AUTH (context only — headers already applied automatically)`);
    lines.push(input.authHint);
  }

  lines.push("");
  lines.push("Begin now.");
  return lines.join("\n");
}
