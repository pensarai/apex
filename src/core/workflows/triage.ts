import { resolve as resolvePath } from "path";
import type { AIAuthConfig, AIModel } from "../ai";
import { ReportTriageAgent, defaultOutputDir } from "../agents/specialized/reportTriage";
import type {
  ReportSource,
  ReportTriageAgentRunResult,
  TriageResult,
} from "../agents/specialized/reportTriage";
import { extractHostname } from "../agents/offSecAgent/tools/scopeGuard";
import type { AgentEventBus } from "../eventBus";
import type { SessionInfo } from "../session";
import { sessions } from "../session";

export interface TriageWorkflowInput {
  /** Path to the inbound bug bounty report file. */
  reportPath: string;

  /** Live target URL — used for PoC reproduction and to derive allowed hosts. */
  target: string;

  /** Repository root — used for `.apex/bug-bounty/*` lookup and remediation drafting. Defaults to `process.cwd()`. */
  cwd?: string;

  /** Output directory for `triage.md` + `decision.json`. Defaults to `<cwd>/bounty-triage/<slug>`. */
  output?: string;

  /**
   * Source platform for the report. `"hackerone"` activates the deterministic
   * H1 JSON parser fast-path; `"auto"` (default) auto-detects.
   */
  source?: ReportSource;

  /** AI model. Defaults to `claude-sonnet-4-5`. */
  model?: AIModel;

  /** Existing session to reuse. When omitted one is auto-created with scope locked to the target host. */
  session?: SessionInfo;

  authConfig?: AIAuthConfig;
  eventBus?: AgentEventBus;
  abortSignal?: AbortSignal;

  /** Optional pre-existing findings directory to dedupe against. */
  findingsDir?: string;
}

export interface TriageWorkflowResult {
  session: SessionInfo;
  triageMarkdownPath: string;
  decisionJsonPath: string;
  result: TriageResult;
}

/**
 * Run the bug bounty triage workflow end-to-end.
 *
 * Auto-creates a session locked to the target's registrable domain so
 * live-verification HTTP/command tools stay in scope.
 */
export async function runTriageWorkflow(
  input: TriageWorkflowInput,
): Promise<TriageWorkflowResult> {
  const model: AIModel = input.model ?? "claude-sonnet-4-5";
  const cwd = resolvePath(input.cwd ?? process.cwd());
  const reportPath = resolvePath(input.reportPath);
  const outputDir = input.output
    ? resolvePath(input.output)
    : defaultOutputDir(cwd, reportPath);

  const targetHost = extractHostname(input.target);
  if (!targetHost) {
    throw new Error(
      `Triage workflow: target URL '${input.target}' could not be parsed for hostname`,
    );
  }

  const session =
    input.session ??
    (await sessions.create({
      name: "Bug Bounty Triage",
      targets: [input.target],
      config: {
        mode: "operator",
        agentCwd: cwd,
        scopeConstraints: {
          allowedHosts: [targetHost],
          strictScope: true,
        },
      },
    }));

  const agent = new ReportTriageAgent({
    cwd,
    reportPath,
    target: input.target,
    outputDir,
    source: input.source,
    model,
    session,
    authConfig: input.authConfig,
    eventBus: input.eventBus,
    abortSignal: input.abortSignal,
    findingsDir: input.findingsDir,
  });

  const runResult: ReportTriageAgentRunResult = await agent.run();

  return {
    session,
    triageMarkdownPath: runResult.outputs.triageMarkdownPath,
    decisionJsonPath: runResult.outputs.decisionJsonPath,
    result: runResult.result,
  };
}
