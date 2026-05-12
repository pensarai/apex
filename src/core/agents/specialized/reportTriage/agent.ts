import { resolve as resolvePath } from "path";
import type { AIAuthConfig, AIModel } from "../../../ai";
import type { AgentEventBus } from "../../../eventBus";
import { FindingsRegistry } from "../../../findings/registry";
import type { SessionInfo } from "../../../session";
import { PatchingAgent } from "../patching/agent";
import type { PatchResult, VulnerabilityDetails } from "../patching/types";
import { scoreFindingWithCVSS } from "../cvssScorer";
import { loadProgramContext } from "./contextLoader";
import { checkDuplicate } from "./dupCheck";
import { deriveDecision } from "./decisionLogic";
import { runLiveVerification } from "./liveVerify";
import { parseReport, type ReportSource } from "./parser";
import {
  defaultOutputDir,
  writeTriageOutputs,
  type WriteOutputsResult,
} from "./reportWriter";
import { checkScope } from "./scopeCheck";
import { alignWithThreatModel } from "./threatModelAlign";
import type {
  BountyReport,
  CvssSummary,
  LiveVerificationResult,
  ThreatModelAlignment,
  TriageResult,
} from "./types";

export interface ReportTriageAgentInput {
  /** Repository root — also the search root for `.apex/bug-bounty/*` and threat-model files. */
  cwd: string;

  /** Path to the inbound bug bounty report file (markdown / JSON / plaintext). */
  reportPath: string;

  /** Live target URL used for PoC reproduction. Must match the session's allowedHosts. */
  target: string;

  /** Output directory for `triage.md` + `decision.json`. */
  outputDir?: string;

  /**
   * Source platform for the report. Drives parser dispatch — `"hackerone"`
   * runs the deterministic H1 JSON parser first. Defaults to `"auto"`.
   */
  source?: ReportSource;

  /** AI model for parsing, scope policy, threat-model alignment, and verification. */
  model: AIModel;

  /** Session — must have `scopeConstraints.allowedHosts` set to the target host. */
  session: SessionInfo;

  /**
   * Optional pre-loaded findings registry for dedup. When omitted, an empty
   * registry is used (effectively skipping the dup check).
   */
  findingsRegistry?: FindingsRegistry;

  /**
   * Optional findings directory to pre-load the registry from.
   * Ignored when `findingsRegistry` is provided.
   */
  findingsDir?: string;

  authConfig?: AIAuthConfig;
  eventBus?: AgentEventBus;
  abortSignal?: AbortSignal;
}

export interface ReportTriageAgentRunResult {
  result: TriageResult;
  outputs: WriteOutputsResult;
}

/**
 * Orchestrates the full triage pipeline for a single inbound bug bounty
 * report. Unlike most specialized agents in apex, this is a plain
 * orchestration class — it composes other agents and helpers rather than
 * extending the {@link OffensiveSecurityAgent} harness directly.
 *
 * Pipeline:
 *   1. Parse report          (parser.ts)
 *   2. Load program context  (contextLoader.ts)
 *   3. Scope check           (scopeCheck.ts) — short-circuit on fail
 *   4. Duplicate check       (dupCheck.ts)   — short-circuit on dup
 *   5. Live verification     (liveVerify.ts → OffensiveSecurityAgent sub-run)
 *   6. CVSS recalibration    (cvssScorer)
 *   7. Threat-model alignment (threatModelAlign.ts)
 *   8. Decision              (decisionLogic.ts)
 *   9. Remediation draft     (PatchingAgent) — only when decision = accept
 *  10. Write outputs         (reportWriter.ts)
 */
export class ReportTriageAgent {
  constructor(private readonly input: ReportTriageAgentInput) {}

  async run(): Promise<ReportTriageAgentRunResult> {
    const { input } = this;
    const reportPath = resolvePath(input.reportPath);
    const outputDir =
      input.outputDir ?? defaultOutputDir(input.cwd, reportPath);

    // 1. Parse report.
    const report = await parseReport({
      filePath: reportPath,
      model: input.model,
      source: input.source,
      authConfig: input.authConfig,
      abortSignal: input.abortSignal,
    });

    // 2. Load program context.
    const programContext = await loadProgramContext(input.cwd);

    // 3. Scope check.
    const allowedHosts =
      input.session.config?.scopeConstraints?.allowedHosts ?? [];
    const scope = await checkScope({
      report,
      programContext,
      allowedHosts,
      model: input.model,
      authConfig: input.authConfig,
      abortSignal: input.abortSignal,
    });

    if (!scope.inScope) {
      return this.finalize({
        report,
        reportPath,
        outputDir,
        scope,
        duplicate: { duplicate: false, matchType: "none" },
        verification: null,
        cvss: null,
        threatModelAlignment: null,
        remediation: null,
      });
    }

    // 4. Duplicate check.
    const registry = await this.resolveRegistry();
    const duplicate = checkDuplicate({ report, registry });

    if (duplicate.duplicate) {
      return this.finalize({
        report,
        reportPath,
        outputDir,
        scope,
        duplicate,
        verification: null,
        cvss: null,
        threatModelAlignment: null,
        remediation: null,
      });
    }

    // 5. Live verification (whole reason live mode was selected).
    const verification = await runLiveVerification({
      report,
      target: input.target,
      model: input.model,
      session: input.session,
      authConfig: input.authConfig,
      eventBus: input.eventBus,
      abortSignal: input.abortSignal,
    });

    // 6 + 7 run in parallel — neither depends on the other.
    const [cvss, threatModelAlignment] = await Promise.all([
      this.scoreIfReproduced(report, verification),
      verification.reproduced
        ? alignWithThreatModel({
            report,
            verification,
            programContext,
            model: input.model,
            authConfig: input.authConfig,
            abortSignal: input.abortSignal,
          })
        : Promise.resolve<ThreatModelAlignment | null>(null),
    ]);

    // 8. Decision.
    const decision = deriveDecision({
      scope,
      duplicate,
      verification,
      report,
      cvss,
      threatModelAlignment,
    });

    // 9. Remediation draft — only when accepted.
    let remediation: PatchResult | null = null;
    if (decision.outcome === "accept") {
      remediation = await this.draftRemediation({
        report,
        verification,
        cvss,
      });
    }

    return this.finalize({
      report,
      reportPath,
      outputDir,
      scope,
      duplicate,
      verification,
      cvss,
      threatModelAlignment,
      remediation,
    });
  }

  // ---------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------

  private async resolveRegistry(): Promise<FindingsRegistry> {
    if (this.input.findingsRegistry) return this.input.findingsRegistry;
    if (this.input.findingsDir) {
      return FindingsRegistry.fromDirectory(this.input.findingsDir);
    }
    return new FindingsRegistry();
  }

  private async scoreIfReproduced(
    report: BountyReport,
    verification: LiveVerificationResult,
  ): Promise<CvssSummary | null> {
    if (!verification.reproduced) return null;

    const scorerResult = await scoreFindingWithCVSS(
      {
        finding: {
          title: report.title,
          description: report.description,
          impact: report.impact,
          evidence: verification.evidence,
          endpoint: report.affectedUrl,
          vulnerabilityClass: report.vulnerabilityClass,
        },
        agentMessages: [],
      },
      this.input.model,
      this.input.authConfig,
      this.input.abortSignal,
    );

    return {
      score: scorerResult.score,
      severity: scorerResult.severity,
      vectorString: scorerResult.vectorString,
      reasoning: scorerResult.reasoning,
    };
  }

  private async draftRemediation(opts: {
    report: BountyReport;
    verification: LiveVerificationResult;
    cvss: CvssSummary | null;
  }): Promise<PatchResult> {
    const vuln: VulnerabilityDetails = {
      name: opts.report.title,
      severity: opts.cvss?.severity ?? opts.report.claimedSeverity,
      description: `${opts.report.description}\n\nReproduction evidence:\n${opts.verification.evidence}`,
      location: opts.report.affectedUrl,
      poc: opts.report.pocCurl
        ? { fileName: "poc.txt", contents: opts.report.pocCurl }
        : undefined,
    };

    const patching = new PatchingAgent({
      cwd: this.input.cwd,
      vulnerability: vuln,
      model: this.input.model,
      session: this.input.session,
      authConfig: this.input.authConfig,
      abortSignal: this.input.abortSignal,
      eventBus: this.input.eventBus,
    });

    return patching.consume();
  }

  private async finalize(opts: {
    report: BountyReport;
    reportPath: string;
    outputDir: string;
    scope: TriageResult["scope"];
    duplicate: TriageResult["duplicate"];
    verification: LiveVerificationResult | null;
    cvss: CvssSummary | null;
    threatModelAlignment: ThreatModelAlignment | null;
    remediation: PatchResult | null;
  }): Promise<ReportTriageAgentRunResult> {
    const decision = deriveDecision({
      scope: opts.scope,
      duplicate: opts.duplicate,
      verification: opts.verification,
      cvss: opts.cvss,
      threatModelAlignment: opts.threatModelAlignment,
      report: opts.report,
    });

    const result: TriageResult = {
      schemaVersion: 1,
      reportPath: opts.reportPath,
      target: this.input.target,
      generatedAt: new Date().toISOString(),
      report: opts.report,
      scope: opts.scope,
      duplicate: opts.duplicate,
      verification: opts.verification,
      cvss: opts.cvss,
      threatModelAlignment: opts.threatModelAlignment,
      decision,
      remediation: opts.remediation,
    };

    const outputs = await writeTriageOutputs({
      result,
      outputDir: opts.outputDir,
    });

    return { result, outputs };
  }
}
