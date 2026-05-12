import type {
  BountyReport,
  CvssSummary,
  DupCheckResult,
  HackerOneState,
  LiveVerificationResult,
  ScopeCheckResult,
  ThreatModelAlignment,
  TriageDecision,
  TriageReason,
} from "./types";

/**
 * Deterministic decision rule over the signals collected during triage.
 *
 * Order matters — short-circuit on the cheapest, most definitive signals
 * first (scope, dup), then move to the signals that required real work
 * (verification, threat-model alignment).
 *
 * Returning `needs-info` is rare and only used when the report is so
 * incomplete that verification couldn't even be attempted.
 */
export function deriveDecision(opts: {
  scope: ScopeCheckResult;
  duplicate: DupCheckResult;
  verification: LiveVerificationResult | null;
  cvss: CvssSummary | null;
  threatModelAlignment: ThreatModelAlignment | null;
  report?: BountyReport;
}): TriageDecision {
  const core = decideCore(opts);

  return {
    ...core,
    suggestedHackerOneState: mapToHackerOneState(core.reason),
    draftReplyMessage: buildDraftReply({
      reason: core.reason,
      rationale: core.rationale,
      report: opts.report,
      cvss: opts.cvss,
      duplicate: opts.duplicate,
    }),
  };
}

function decideCore(opts: {
  scope: ScopeCheckResult;
  duplicate: DupCheckResult;
  verification: LiveVerificationResult | null;
  cvss: CvssSummary | null;
  threatModelAlignment: ThreatModelAlignment | null;
}): Pick<TriageDecision, "outcome" | "reason" | "rationale"> {
  // 1. Out of scope — short-circuit.
  if (!opts.scope.inScope) {
    return {
      outcome: "reject",
      reason: "out-of-scope",
      rationale: opts.scope.reason,
    };
  }

  // 2. Duplicate — short-circuit.
  if (opts.duplicate.duplicate) {
    const matched = opts.duplicate.matchedTitle
      ? ` Matched existing finding "${opts.duplicate.matchedTitle}".`
      : "";
    return {
      outcome: "reject",
      reason: "duplicate",
      rationale: `Report duplicates a known finding (${opts.duplicate.matchType} match).${matched}`,
    };
  }

  // 3. No verification result — verification was skipped. We can't make
  //    an evidence-grounded accept decision, so request more info.
  if (!opts.verification) {
    return {
      outcome: "needs-info",
      reason: "missing-info",
      rationale:
        "Live verification was not performed — cannot accept without reproduction.",
    };
  }

  // 4. Not reproducible — reject.
  if (!opts.verification.reproduced) {
    return {
      outcome: "reject",
      reason: "unreproducible",
      rationale: `Reporter PoC did not reproduce against the live target. ${opts.verification.observations}`,
    };
  }

  // 5. Reproduced but threat model marks this as an accepted business risk — reject.
  if (opts.threatModelAlignment?.businessAcceptedRisk) {
    return {
      outcome: "reject",
      reason: "business-accepted-risk",
      rationale: `Reproduced, but the threat model / business context marks this behavior as an accepted risk. ${opts.threatModelAlignment.notes}`,
    };
  }

  // 6. Reproduced but CVSS came back as "NONE" / score 0 — informational.
  if (opts.cvss && (opts.cvss.score === 0 || opts.cvss.severity === "NONE")) {
    return {
      outcome: "reject",
      reason: "informational",
      rationale: `Reproduced, but CVSS scoring shows no meaningful impact (score=${opts.cvss.score}, severity=${opts.cvss.severity}).`,
    };
  }

  // 7. Reproduced, in scope, not a dup, has impact → accept.
  const severity = opts.cvss?.severity ?? "unspecified";
  return {
    outcome: "accept",
    reason: "confirmed",
    rationale: `Reproduced against the live target; CVSS severity ${severity}.`,
  };
}

/**
 * Map our internal `TriageReason` onto a canonical HackerOne report state.
 *
 * Every reason has a clean mapping — see the README in
 * https://docs.hackerone.com/en/articles/8475030-report-states for the full
 * state machine.
 */
export function mapToHackerOneState(reason: TriageReason): HackerOneState {
  switch (reason) {
    case "confirmed":
      return "Triaged";
    case "duplicate":
      return "Duplicate";
    case "out-of-scope":
    case "unreproducible":
      return "Not Applicable";
    case "informational":
    case "business-accepted-risk":
      return "Informative";
    case "missing-info":
      return "Needs More Info";
  }
}

/**
 * Build a paste-ready reply paragraph for the reporter. Templated — the
 * engineer is expected to lightly edit before posting in the H1 inbox.
 */
function buildDraftReply(opts: {
  reason: TriageReason;
  rationale: string;
  report?: BountyReport;
  cvss: CvssSummary | null;
  duplicate: DupCheckResult;
}): string {
  const handle = opts.report?.reporterHandle
    ? `@${opts.report.reporterHandle}`
    : "Hi";
  const title = opts.report?.title ?? "this report";

  switch (opts.reason) {
    case "confirmed": {
      const sev = opts.cvss?.severity
        ? ` We've assessed it as ${opts.cvss.severity} severity (CVSS ${opts.cvss.score}).`
        : "";
      return `${handle} — thanks for the report. We've reproduced the issue described in "${title}" against the live environment and are moving it to Triaged.${sev} We'll follow up here once a fix is in flight.`;
    }
    case "duplicate": {
      const matched = opts.duplicate.matchedTitle
        ? ` It duplicates a previously reported finding ("${opts.duplicate.matchedTitle}").`
        : "";
      return `${handle} — thanks for the report. After review, "${title}" is a duplicate of a known issue we're already tracking internally.${matched} Reputation will be adjusted per the duplicate policy.`;
    }
    case "out-of-scope": {
      return `${handle} — thanks for taking the time to report "${title}". Unfortunately the affected asset / behavior is out of scope for this program. Specifically: ${opts.rationale} Please review our scope rules before submitting follow-up reports.`;
    }
    case "unreproducible": {
      return `${handle} — thanks for the report. We attempted to reproduce "${title}" against the live environment but were unable to: ${opts.rationale} If you can share additional details (HTTP request/response captures, account context, exact timing) we're happy to take another look.`;
    }
    case "informational": {
      return `${handle} — thanks for the report. We reproduced "${title}", but in this context it doesn't represent a meaningful security impact: ${opts.rationale} We're closing it as Informative — no reputation impact.`;
    }
    case "business-accepted-risk": {
      return `${handle} — thanks for the report. We reproduced "${title}", however this behavior is a documented accepted risk per our threat model. ${opts.rationale} We're closing it as Informative.`;
    }
    case "missing-info": {
      return `${handle} — thanks for the report on "${title}". To progress this we need additional details: a fully reproducible PoC (request, parameters, expected vs. observed response), the account context you tested from, and the time of your attempt. We'll auto-close after 30 days of inactivity per H1's policy.`;
    }
  }
}
