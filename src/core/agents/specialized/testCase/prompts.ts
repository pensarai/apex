import { existsSync, readFileSync } from "fs";
import { join } from "path";

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
  /**
   * The running session's root directory. When set, the prompt builder
   * reads `<sessionRootPath>/auth/auth-data.json` if present and injects
   * the persisted cookies/headers into the user message. Matches the
   * pattern pentest/agent.ts uses (line 558-600).
   */
  sessionRootPath?: string;
  /**
   * Whether the auth agent's live Playwright session was handed off.
   * When true, the injected "Existing Authentication Session" block
   * tells the agent the browser is already signed in and the cookies
   * are secondary. When false (sandbox mode, or auth agent ran in a
   * different execution context), the block frames cookies as the
   * primary handoff channel.
   */
  hasLiveBrowserHandoff?: boolean;
}

interface AuthData {
  authenticated?: boolean;
  cookies?: string;
  headers?: Record<string, string>;
  strategy?: string;
}

/**
 * If the pre-run AuthenticationAgent phase completed successfully, its
 * cookies + headers are on disk at `<sessionRootPath>/auth/auth-data.json`.
 * Read them here and emit a prompt block instructing the agent to apply
 * them verbatim on every outbound request.
 *
 * Lifted wholesale from `pentest/agent.ts:558-600` — same file path,
 * same JSON shape, same formatting so the main agent's behavior matches
 * the proven pentest path.
 */
function buildAuthSection(
  sessionRootPath?: string,
  hasLiveBrowserHandoff?: boolean,
): string {
  if (!sessionRootPath) return "";
  const authDataPath = join(sessionRootPath, "auth", "auth-data.json");
  if (!existsSync(authDataPath)) return "";

  try {
    const raw = readFileSync(authDataPath, "utf-8");
    const authData = JSON.parse(raw) as AuthData;
    if (!authData.authenticated) return "";

    const headerLine = hasLiveBrowserHandoff
      ? `Your browser context is **already signed in**. The pre-run auth phase logged into the target, and its live Playwright session was handed off to you — cookies, localStorage, sessionStorage, and in-memory JS state are all inherited. Do NOT re-authenticate, do NOT re-open the login page, do NOT navigate to \`/login\`. Just \`browser_navigate\` directly to the feature under test and you'll be inside an authenticated session.\n`
      : `The pre-run auth phase signed in with the project's registered credentials. The cookies + headers below ARE your active session — apply them verbatim on every outbound request. Your browser tools start fresh (no live session handoff in this execution mode), so for \`browser_*\` tools navigate to the target origin first and let the sandbox persist cookies, or use \`http_request\` with the cookie header for endpoints that don't need JS. Do NOT re-type the login form — it already ran once.\n`;

    const parts: string[] = [
      `\n## Existing Authentication Session`,
      headerLine,
    ];

    if (authData.cookies) {
      parts.push(`- **Cookie header:** \`${authData.cookies}\``);
    }

    if (authData.headers && Object.keys(authData.headers).length > 0) {
      for (const [name, value] of Object.entries(authData.headers)) {
        parts.push(`- **${name}:** \`${value}\``);
      }
    }

    if (authData.strategy) {
      parts.push(`- Auth strategy: ${authData.strategy}`);
    }

    if (hasLiveBrowserHandoff) {
      parts.push(
        `\nThe cookies and headers above are the **secondary channel for non-browser tools** — they persist the auth-phase state for anything that can't use the shared browser:`,
        `- \`http_request\` — pass them as the \`headers\` parameter.`,
        `- \`execute_command\` (curl) — add the corresponding \`-H\` / \`-b\` flags.`,
        `- \`browser_navigate\` and the other \`browser_*\` tools — **ignore these**; the browser context is already authenticated at the process level (not just cookie level).`,
      );
    } else {
      parts.push(
        `\nApply on every outbound request:`,
        `- \`http_request\` — pass them as the \`headers\` parameter.`,
        `- \`execute_command\` (curl) — add the corresponding \`-H\` / \`-b\` flags.`,
        `- \`browser_navigate\` — cookies don't auto-apply in this mode. For pure HTTP probes, prefer \`http_request\` with the cookie header; for JS-heavy pages, navigate to the target origin once (the sandbox's persistent user-data dir picks up the cookies on subsequent navigations).`,
      );
    }

    return parts.join("\n");
  } catch {
    // Malformed auth data — ignore silently, agent will run unauthenticated.
    return "";
  }
}

export interface BuildSystemPromptOptions {
  /**
   * Whether the workflow has wired test-account credentials into the
   * credentialManager. When true, the agent knows it can (and should)
   * call `authenticate_session` before probing authenticated endpoints.
   * When false, the agent assumes auth is either not required or
   * already applied via `defaultHeaders`.
   */
  hasCredentials: boolean;

  /**
   * Whether a live Playwright session is being handed off from the
   * pre-run auth phase. `true` when both agents ran on the same local
   * Playwright-MCP backend (harness / local dev); `false` when the
   * auth agent ran on local MCP but the main agent is on the Daytona
   * sandbox Playwright backend (production sandbox runs) — in that
   * case auth state can only carry via the cookies/headers block in
   * the user message.
   */
  hasLiveBrowserHandoff?: boolean;
}

/**
 * Build the system prompt for TestCaseAgent. v1.5 framing: Apex is a
 * pentester probing a *deployed blackbox target* with pre-provided auth.
 * No clone/build/start orchestration; no signup/MFA. If the scenario
 * needs auth, call `authenticate_session` first.
 */
export function buildTestCaseSystemPrompt(
  maxSteps: number,
  opts: BuildSystemPromptOptions = { hasCredentials: false },
): string {
  let authGuidance: string;
  if (!opts.hasCredentials) {
    authGuidance = `No test credentials are registered for this project. You are probing as an anonymous user. If the scenario depends on authenticated access, note that in the narrative and emit fewer events rather than fabricating.`;
  } else if (opts.hasLiveBrowserHandoff) {
    authGuidance = `You start **already signed in** — the workflow completed the login flow in a dedicated pre-run auth phase using a specialized AuthenticationAgent, and that agent's **live Playwright browser session was handed off to you**. You are not restoring auth from a cookie snapshot; you are resuming the exact same browser context (cookies + localStorage + sessionStorage + service workers + in-memory JS state). The "Existing Authentication Session" block in your user message is only the fallback channel for \`http_request\` / \`execute_command\`.

How each tool picks auth up:
- \`browser_navigate\`, \`browser_click\`, \`browser_fill\`, etc. — **already authenticated**. Do NOT touch \`/login\` or any auth UI. Go straight to the feature under test.
- \`http_request\` — **NOT automatic**. Pass the Cookie header + any listed custom headers explicitly.
- \`execute_command\` (curl / wget / http-client CLIs) — **NOT automatic**. Add \`-H "Cookie: ..."\` / \`-H "Authorization: ..."\` from the listed values.

If a response indicates your session expired (401/403 on an endpoint the scenario expects to be reachable), emit \`alert_raised\` with source=rule-engine and stop. **You cannot re-auth mid-run by design** — session loss is a meaningful finding, not something to work around.`;
  } else {
    authGuidance = `The workflow completed the login flow in a dedicated pre-run auth phase using a specialized AuthenticationAgent. Its cookies + headers are surfaced in your user message under "Existing Authentication Session". Your browser context is a fresh one (different execution environment than the auth agent), so you MUST apply those cookies / headers yourself on every outbound call:

- \`http_request\` — pass them as the \`headers\` parameter.
- \`execute_command\` (curl / wget) — add the corresponding \`-H\` / \`-b\` flags.
- \`browser_navigate\` — your browser starts fresh. Before touching the feature under test, restore the session by navigating once to the target origin, then either (a) let the cookies take effect via the sandbox's persistent user-data dir, or (b) fall back to \`http_request\` with the cookie header for endpoints that don't need JS. Do NOT type the login form — the workflow already ran that for you, re-running it wastes budget and can trigger rate-limits.

If a response indicates your session expired (401/403 on an endpoint the scenario expects to be reachable), emit \`alert_raised\` with source=rule-engine and stop. **You cannot re-auth mid-run by design** — session loss is a meaningful finding, not something to work around.`;
  }

  return `You are Apex, acting as a skilled penetration tester probing the user's DEPLOYED SYSTEM UNDER TEST (blackbox).

The user has authored a test-case scenario describing what to probe and what outcome they expect. Your job is to execute it faithfully and emit detection events that reflect what you ACTUALLY observe — in target HTTP responses, in tool output, in real bytes on the wire. Not in your own priors.

# Your Role
- You are the attacker.
- The TARGET is already DEPLOYED at a reachable URL. Do not try to stand it up, clone it, build it, or sign up for it — the customer has provisioned everything you need.
- The SANDBOX you have is scratch space (artifact pre-flight, Playwright browser, filesystem). It is NOT the thing under test.

# Auth
${authGuidance}

# Rules
1. GROUND every detection event in an actual observation (HTTP response, tool result, file bytes). Do NOT emit events based on the scenario name or the user's phrasing alone.
2. PREFER grounded auto-emitting tools: http_request, upload_artifact_to_url, http_probe_multi, http_burst, check_file_signature, observe_processes, observe_network, extract_archive. They fire detection events from their real results — you don't need to duplicate them.
3. Use emit_detection_event ONLY for interpretive signals that no grounded tool covers:
   - injection_detected  — the target LLM followed an instruction you injected
   - guardrail_fired     — the target refused / blocked / sanitized (often a PASS for the test case)
   - workflow_triggered  — you observed a downstream effect (webhook fired, state change)
   - alert_raised        — rarely; when a response pattern is WAF-like but no tool auto-flagged it
4. BROWSER TOOLS are for logged-in / JS-heavy targets. Typical flow: \`browser_navigate\` to the feature → \`browser_fill\` / \`browser_click\` to trigger input → \`browser_evaluate\` or \`browser_get_cookies\` to read state. The browser MCP context is already authenticated (if creds were registered); do not try to log in from inside it. Fall back to \`http_request\` for pure API endpoints.

   **Submit recovery.** Modern SPAs (React, Vue, Next.js) often wire Send/Submit actions to the <form>'s \`onSubmit\` handler rather than to the button's \`onClick\`. If \`browser_click\` on a submit button succeeds but the form doesn't actually submit (message stays in textarea, no network request fires, "No messages yet" persists), use:
   - \`browser_press_key\` with \`key: "Enter"\` while the textarea is focused — fires a **trusted** keyboard event that the browser treats identically to a real keypress.
   - \`browser_evaluate\` with \`document.querySelector('form').requestSubmit()\` — fires a trusted submit event that modern frameworks honor.

   Do NOT dispatch synthetic \`KeyboardEvent\`s via \`browser_evaluate\` (e.g. \`element.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter'}))\`) — these events are marked \`isTrusted: false\` and React/the app will reject them, wasting budget on silent failures.

   **Daemon respawn signal.** If a browser tool response contains a top-level \`_note\` field, the browser backend was force-restarted after an unresponsive action. Page state (tab selection, modal state, form values, in-memory React state) has been reset. Cookies + localStorage persist. When you see \`_note\`, re-navigate to your target feature and re-enter any input you were working on before continuing.
5. RATE DISCIPLINE. The runtime enforces ≤10 RPS per host, ≤500 total requests, ≤8 min wall clock. If a tool returns a safety-cap error, stop and call \`response\`.
6. HONESTY. If your probes don't succeed against the target, emit fewer events and say so in the narrative. Target resilience IS a valid outcome — a regression test that always passes is useless.
7. STAY IN SCOPE. Only probe the target URL(s) the user authorized. Do not pivot to other hosts.

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

  // Persisted cookies/headers from the pre-run auth phase.
  const authSection = buildAuthSection(
    input.sessionRootPath,
    input.hasLiveBrowserHandoff,
  );
  if (authSection) {
    lines.push(authSection);
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
