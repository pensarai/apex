import { existsSync, readdirSync, readFileSync } from "fs";
import { join } from "path";
import { z } from "zod";
import type { Finding } from "../agents/offSecAgent/types";
import { generateObjectResponse, type AIModel } from "../ai";
import type { AIAuthConfig } from "../ai/utils";

// ---------------------------------------------------------------------------
// Vuln class keyword mappings (order matters — first match wins)
// ---------------------------------------------------------------------------

const VULN_CLASS_PATTERNS: [RegExp, string][] = [
  [/sql\s*injection/i, "sql-injection"],
  [/command\s*injection/i, "command-injection"],
  [/remote\s*code\s*execution|(\b)rce(\b)/i, "rce"],
  [/server[\s-]*side\s*request\s*forgery|(\b)ssrf(\b)/i, "ssrf"],
  [/cross[\s-]*site\s*request\s*forgery|(\b)csrf(\b)/i, "csrf"],
  [
    /path\s*traversal|directory\s*traversal|local\s*file\s*inclusion|\blfi\b/i,
    "path-traversal",
  ],
  [
    /\bmissing\s*auth|\bno\s*auth|unauthenticated\s+access/i,
    "missing-authentication",
  ],
  [/\bidor\b|insecure\s*direct\s*object/i, "idor"],
  [/\bxss\b|cross[\s-]*site\s*scripting/i, "xss"],
  [/missing\s*content\s*security\s*policy|missing\s*csp\b/i, "missing-csp"],
  [/\bcors\b|cross[\s-]*origin/i, "cors"],
  [/authentication\s*bypass|auth\s*bypass/i, "auth-bypass"],
  [/privilege\s*escalation/i, "privilege-escalation"],
  [
    /information\s*disclosure|sensitive\s*data\s*exposure/i,
    "information-disclosure",
  ],
  [/open\s*redirect/i, "open-redirect"],
  [
    /missing.*rate[\s-]*limit|rate[\s-]*limit.*missing|no\s*rate[\s-]*limit/i,
    "missing-rate-limiting",
  ],
  [
    /user[\s-]*enumeration|account[\s-]*enumeration|email[\s-]*enumeration/i,
    "user-enumeration",
  ],
  [
    /hardcoded[\s-]*credential|hardcoded[\s-]*password|hardcoded[\s-]*key|exposed[\s-]*api[\s-]*key/i,
    "hardcoded-credentials",
  ],
  [/captcha[\s-]*bypass|missing[\s-]*captcha/i, "captcha-bypass"],
  [/missing.*header|security\s*header/i, "missing-security-header"],
];

// ---------------------------------------------------------------------------
// URL / path pattern used by extractTitleStem to strip endpoint references
// ---------------------------------------------------------------------------

const URL_PATH_PATTERN =
  /(?:https?:\/\/[^\s]+|\/[a-z0-9_\-/{}.:]+|\b(?:endpoint|url|path|route)\b)/gi;

// ---------------------------------------------------------------------------
// Public helpers (exported for testing)
// ---------------------------------------------------------------------------

/**
 * Classify a finding title into a canonical vulnerability class.
 * Returns a kebab-case identifier (e.g. "sql-injection", "xss").
 * Falls back to a normalised form of the title when no keyword matches.
 */
export function extractVulnClass(title: string): string {
  const t = title.trim();
  for (const [pattern, cls] of VULN_CLASS_PATTERNS) {
    if (pattern.test(t)) return cls;
  }
  return t
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .substring(0, 60);
}

/**
 * Content-aware vulnerability classification.
 *
 * Starts with the title-based class from {@link extractVulnClass}, then
 * inspects the finding's description and evidence to correct common
 * mis-classifications.  In particular, an `idor` classification is
 * upgraded to `missing-authentication` when the content indicates that
 * no authentication exists at all (IDOR requires auth to be present but
 * authorisation to be insufficient).
 */
export function classifyFromContent(finding: Finding): string {
  const titleClass = extractVulnClass(finding.title);

  if (titleClass === "idor") {
    const corpus = `${finding.description ?? ""} ${finding.evidence ?? ""}`;
    const missingAuthPattern =
      /no\s+authentication|unauthenticated|without\s+authentication|PR:N|PR=N/i;
    if (missingAuthPattern.test(corpus)) {
      return "missing-authentication";
    }
  }

  return titleClass;
}

/**
 * Derive a normalised "stem" from a finding title by stripping
 * endpoint-specific references (URLs, paths) and collapsing whitespace.
 *
 * Two findings that differ only by the affected endpoint will produce
 * the same stem, enabling application-wide dedup.
 */
export function extractTitleStem(title: string): string {
  return title
    .replace(URL_PATH_PATTERN, "")
    .replace(/[^a-zA-Z0-9 ]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

/**
 * Normalise an endpoint URL for comparison:
 * lowercase, strip trailing slash, strip query string and fragment.
 */
export function normalizeEndpoint(endpoint: string): string {
  let e = endpoint.trim().toLowerCase();

  // Strip fragment
  const hashIdx = e.indexOf("#");
  if (hashIdx !== -1) e = e.substring(0, hashIdx);

  // Strip query string
  const qIdx = e.indexOf("?");
  if (qIdx !== -1) e = e.substring(0, qIdx);

  // Strip trailing slash (but keep bare origin like "https://host.com")
  if (e.length > 1 && e.endsWith("/")) {
    e = e.replace(/\/+$/, "");
  }

  return e;
}

/**
 * Build the two fingerprint keys for a finding.
 *
 * - `exactKey`:   `<normalized_endpoint>||<vuln_class>` — precise per-endpoint dedup
 * - `appWideKey`: `<title_stem>` — catches the same root issue across endpoints
 *
 * The app-wide key intentionally uses only the stem (no vuln class prefix).
 * The stem already carries the semantic identity of the finding, and keeping
 * it independent of the pattern list means unknown vuln types still get
 * correct application-wide dedup.
 */
export function generateFingerprint(finding: Finding): {
  exactKey: string;
  appWideKey: string;
} {
  const vulnClass = classifyFromContent(finding);
  const stem = extractTitleStem(finding.title);
  const endpoint = normalizeEndpoint(finding.endpoint);

  return {
    exactKey: `${endpoint}||${vulnClass}`,
    appWideKey: stem,
  };
}

// ---------------------------------------------------------------------------
// DuplicateCheck result type
// ---------------------------------------------------------------------------

export interface DuplicateCheckResult {
  duplicate: boolean;
  matchedFinding?: Finding;
  matchType?: "exact" | "application-wide" | "semantic";
}

// ---------------------------------------------------------------------------
// Tier 3: LLM semantic dedup
// ---------------------------------------------------------------------------

const SemanticDedupResultSchema = z.object({
  isDuplicate: z
    .boolean()
    .describe("Whether the new finding is a duplicate of an existing one"),
  matchedIndex: z
    .number()
    .optional()
    .describe("1-based index of the matched existing finding, if duplicate"),
  reasoning: z
    .string()
    .describe("Brief explanation of why this is or is not a duplicate"),
});

const SEMANTIC_DEDUP_SYSTEM = `You are a security finding deduplication specialist. Your task is to determine whether a new vulnerability finding is a duplicate of any existing findings.

Two findings are duplicates if they describe the SAME underlying vulnerability, even if:
- They use different phrasing or terminology
- They affect different endpoints but share the same root cause
- One is more specific/detailed than the other

Two findings are NOT duplicates if they describe genuinely different vulnerabilities, even if:
- They affect the same endpoint
- They are the same class of vulnerability but with different root causes (e.g., reflected XSS vs stored XSS)

Be conservative: when in doubt, mark as NOT a duplicate. It is better to allow a borderline finding through than to suppress a genuinely new one.`;

const MAX_SEMANTIC_DEDUP_FINDINGS = 25;

function buildSemanticDedupPrompt(
  newFinding: Finding,
  existingFindings: readonly Finding[],
): string {
  const capped = existingFindings.slice(-MAX_SEMANTIC_DEDUP_FINDINGS);
  const offset = existingFindings.length - capped.length;

  const existingList = capped
    .map(
      (f, i) =>
        `${offset + i + 1}. [${f.severity}] "${f.title}" — endpoint: ${f.endpoint}\n   Description: ${f.description.substring(0, 200)}`,
    )
    .join("\n\n");

  return `## New Finding
Title: "${newFinding.title}"
Endpoint: ${newFinding.endpoint}
Severity: ${newFinding.severity}
Description: ${newFinding.description.substring(0, 300)}

## Existing Findings (${existingFindings.length} total${offset > 0 ? `, showing last ${capped.length}` : ""})
${existingList}

Is the new finding a duplicate of any existing finding?`;
}

// ---------------------------------------------------------------------------
// Root-cause grouping
// ---------------------------------------------------------------------------

export interface RootCauseGroup {
  groupId: string;
  findingIndices: number[];
  rootCause: string;
}

const RootCauseGroupResultSchema = z.object({
  groups: z.array(
    z.object({
      groupId: z.string().describe("Short kebab-case identifier for the group"),
      findingIndices: z
        .array(z.number())
        .describe("0-based indices of findings that share this root cause"),
      rootCause: z
        .string()
        .describe(
          "Brief description of the shared underlying misconfiguration or weakness",
        ),
    }),
  ),
});

const ROOT_CAUSE_GROUPING_SYSTEM = `You are a security finding analyst. Your task is to identify findings that share a common root cause.

These are NOT duplicates — they are distinct findings that stem from the same underlying misconfiguration, weakness, or architectural issue. Examples:
- "Email Enumeration via Forgot Password" and "Username Enumeration via Cognito Lockout Response" both stem from Cognito leaking user-existence information
- "Missing Rate Limiting on Email API" and "Unauthenticated Email Sending via SES API" on the same endpoint — the unauthenticated access is the root cause that enables both
- Multiple IDOR findings on different endpoints that all stem from missing authorization middleware

Group findings when:
1. One finding enables or is prerequisite to another
2. Both stem from the same underlying misconfiguration (e.g. same missing middleware, same leaky service)
3. Fixing the root cause would resolve or mitigate all findings in the group

Do NOT group findings that merely share a vulnerability class (e.g. two unrelated XSS on different endpoints with different root causes).

Return an empty groups array if no findings share a root cause.`;

function buildRootCauseGroupingPrompt(findings: readonly Finding[]): string {
  const list = findings
    .map(
      (f, i) =>
        `${i}. [${f.severity}] "${f.title}" — endpoint: ${f.endpoint}\n   Description: ${f.description.substring(0, 200)}`,
    )
    .join("\n\n");

  return `## Findings (${findings.length} total)
${list}

Which findings share a common root cause? Return groups using 0-based indices.`;
}

// ---------------------------------------------------------------------------
// FindingsRegistry options
// ---------------------------------------------------------------------------

export interface FindingsRegistryOptions {
  /** AI model for Tier 3 semantic dedup. When omitted, Tier 3 is skipped. */
  model?: AIModel;
  /** Per-provider API key overrides for the model. */
  authConfig?: AIAuthConfig;
  /** Signal to cancel in-flight LLM calls (Tier 3 semantic dedup). */
  abortSignal?: AbortSignal;
}

// ---------------------------------------------------------------------------
// FindingsRegistry
// ---------------------------------------------------------------------------

/**
 * Thread-safe, in-memory registry of known findings.
 *
 * Supports three dedup tiers:
 *   1. **Exact** — same normalised endpoint + same vuln class
 *   2. **Application-wide** — same title stem (endpoint-stripped title)
 *      (catches the same root vulnerability rediscovered on different endpoints)
 *   3. **Semantic** — LLM comparison against existing findings
 *      (catches differently-phrased duplicates that string matching misses)
 *
 * The registry is designed to be created once per session and shared
 * across all concurrent pentest agents via `ToolContext`.
 */
export class FindingsRegistry {
  private exactKeys = new Map<string, Finding>();
  private appWideKeys = new Map<string, Finding>();
  private findings: Finding[] = [];

  private model?: AIModel;
  private authConfig?: AIAuthConfig;
  private abortSignal?: AbortSignal;

  // Simple async mutex: a chain of promises. Each register() call
  // appends to the chain so concurrent callers serialise naturally.
  private mutex: Promise<void> = Promise.resolve();

  constructor(opts?: FindingsRegistryOptions) {
    this.model = opts?.model;
    this.authConfig = opts?.authConfig;
    this.abortSignal = opts?.abortSignal;
  }

  /** How many findings are tracked. */
  get size(): number {
    return this.findings.length;
  }

  /** Return a snapshot of all tracked findings. */
  getFindings(): readonly Finding[] {
    return [...this.findings];
  }

  // -----------------------------------------------------------------------
  // Factory
  // -----------------------------------------------------------------------

  /**
   * Create a registry pre-loaded with findings from a directory.
   * Reads every `.json` file, parses each as a `Finding`, and indexes it.
   * Malformed files are silently skipped.
   */
  static fromDirectory(
    findingsPath: string,
    opts?: FindingsRegistryOptions,
  ): FindingsRegistry {
    const registry = new FindingsRegistry(opts);

    if (!existsSync(findingsPath)) return registry;

    const files = readdirSync(findingsPath).filter((f) => f.endsWith(".json"));

    console.log(
      `[FindingsRegistry.fromDirectory] path=${findingsPath}, jsonFiles=${files.length}`,
    );

    for (const file of files) {
      try {
        const raw = readFileSync(join(findingsPath, file), "utf-8");
        const finding = JSON.parse(raw) as Finding;
        if (
          finding &&
          typeof finding.title === "string" &&
          typeof finding.endpoint === "string"
        ) {
          registry.indexFinding(finding);
          console.log(
            `[FindingsRegistry.fromDirectory]   indexed: "${finding.title}" endpoint="${finding.endpoint}" (file=${file})`,
          );
        } else {
          console.log(
            `[FindingsRegistry.fromDirectory]   skipped (missing title/endpoint): file=${file}`,
          );
        }
      } catch {
        console.log(
          `[FindingsRegistry.fromDirectory]   skipped (malformed): file=${file}`,
        );
      }
    }

    console.log(
      `[FindingsRegistry.fromDirectory] Registry initialized: ${registry.size} findings indexed`,
    );

    return registry;
  }

  /**
   * Create a registry pre-loaded with an array of findings (e.g. from Console).
   */
  static fromFindings(
    findings: Finding[],
    opts?: FindingsRegistryOptions,
  ): FindingsRegistry {
    const registry = new FindingsRegistry(opts);
    for (const f of findings) {
      registry.indexFinding(f);
    }
    return registry;
  }

  // -----------------------------------------------------------------------
  // Core API
  // -----------------------------------------------------------------------

  /**
   * Check whether a finding is a duplicate of something already registered.
   * Synchronous — only checks Tier 1 and Tier 2 (string-based).
   *
   * Tier 1: exact endpoint + vuln class
   * Tier 2: title stem only (application-wide)
   */
  isDuplicate(finding: Finding): DuplicateCheckResult {
    const { exactKey, appWideKey } = generateFingerprint(finding);

    const exactMatch = this.exactKeys.get(exactKey);
    if (exactMatch) {
      return {
        duplicate: true,
        matchedFinding: exactMatch,
        matchType: "exact",
      };
    }

    const appWideMatch = this.appWideKeys.get(appWideKey);
    if (appWideMatch) {
      return {
        duplicate: true,
        matchedFinding: appWideMatch,
        matchType: "application-wide",
      };
    }

    return { duplicate: false };
  }

  /**
   * Register a new finding in the registry.
   *
   * Flow:
   *   1. Tier 1+2 check inside the mutex (fast, deterministic)
   *   2. If no match and a model is configured, Tier 3 LLM check
   *      runs **outside** the mutex to avoid blocking other agents
   *   3. Re-check Tier 1+2 inside the mutex before final accept
   *      (guards against races during the LLM call)
   *
   * Returns the dedup check result. If the finding is a duplicate it is
   * **not** added to the registry.
   */
  async register(finding: Finding): Promise<DuplicateCheckResult> {
    console.log(
      `[FindingsRegistry.register] Checking: "${finding.title}" endpoint="${finding.endpoint}"`,
    );

    // -- Fast path: Tier 1+2 inside the mutex ----------------------------
    const fastResult = await new Promise<DuplicateCheckResult | null>(
      (resolve) => {
        this.mutex = this.mutex.then(() => {
          const check = this.isDuplicate(finding);
          if (check.duplicate) {
            console.log(
              `[FindingsRegistry.register] DUPLICATE (${check.matchType}): "${finding.title}" matched="${check.matchedFinding?.title}"`,
            );
            resolve(check);
          } else if (!this.model || this.findings.length === 0) {
            this.indexFinding(finding);
            console.log(
              `[FindingsRegistry.register] UNIQUE (Tier 1+2, no LLM needed): "${finding.title}" — registry size=${this.size}`,
            );
            resolve({ duplicate: false });
          } else {
            console.log(
              `[FindingsRegistry.register] Tier 1+2 pass — proceeding to Tier 3 LLM check for "${finding.title}"`,
            );
            resolve(null);
          }
        });
      },
    );

    if (fastResult !== null) return fastResult;

    // -- Tier 3: LLM semantic check (outside the mutex) ------------------
    const snapshot = this.getFindings();
    let semanticResult: DuplicateCheckResult = { duplicate: false };

    try {
      semanticResult = await this.semanticDedup(finding, snapshot);
    } catch {
      console.log(
        `[FindingsRegistry.register] Tier 3 LLM error for "${finding.title}" — falling back to Tier 1+2 only`,
      );
    }

    if (semanticResult.duplicate) {
      console.log(
        `[FindingsRegistry.register] DUPLICATE (semantic/Tier 3): "${finding.title}" matched="${semanticResult.matchedFinding?.title}"`,
      );
      return semanticResult;
    }

    // -- Re-check Tier 1+2 inside the mutex (guard against races) --------
    return new Promise<DuplicateCheckResult>((resolve) => {
      this.mutex = this.mutex.then(() => {
        const recheck = this.isDuplicate(finding);
        if (recheck.duplicate) {
          console.log(
            `[FindingsRegistry.register] DUPLICATE (race re-check, ${recheck.matchType}): "${finding.title}" matched="${recheck.matchedFinding?.title}"`,
          );
          resolve(recheck);
        } else {
          this.indexFinding(finding);
          console.log(
            `[FindingsRegistry.register] UNIQUE (all tiers passed): "${finding.title}" — registry size=${this.size}`,
          );
          resolve({ duplicate: false });
        }
      });
    });
  }

  // -----------------------------------------------------------------------
  // Tier 3: semantic dedup via LLM
  // -----------------------------------------------------------------------

  private async semanticDedup(
    finding: Finding,
    existingFindings: readonly Finding[],
  ): Promise<DuplicateCheckResult> {
    if (!this.model || existingFindings.length === 0) {
      return { duplicate: false };
    }

    const prompt = buildSemanticDedupPrompt(finding, existingFindings);

    const result = await generateObjectResponse({
      model: this.model,
      schema: SemanticDedupResultSchema,
      prompt,
      system: SEMANTIC_DEDUP_SYSTEM,
      authConfig: this.authConfig,
      abortSignal: this.abortSignal,
    });

    if (result.isDuplicate && result.matchedIndex != null) {
      const idx = result.matchedIndex - 1; // 1-based to 0-based
      const matched = existingFindings[idx];
      if (matched) {
        return {
          duplicate: true,
          matchedFinding: matched,
          matchType: "semantic",
        };
      }
    }

    return { duplicate: false };
  }

  /**
   * Remove a previously-registered finding from all indexes.
   *
   * This is the rollback counterpart to {@link register}: call it when a
   * finding was accepted by the registry but the caller failed to persist
   * it (e.g. disk-write error).  Without rollback the finding would remain
   * phantom-indexed — blocking future attempts to document the same issue.
   *
   * The operation is mutex-guarded so it is safe to call concurrently.
   */
  async unregister(finding: Finding): Promise<void> {
    return new Promise<void>((resolve) => {
      this.mutex = this.mutex.then(() => {
        this.removeFinding(finding);
        resolve();
      });
    });
  }

  // -----------------------------------------------------------------------
  // Root-cause grouping
  // -----------------------------------------------------------------------

  /**
   * Analyse all registered findings and group those that share a common
   * root cause (e.g. same misconfiguration, one enables another).
   *
   * This is NOT deduplication — grouped findings are distinct issues that
   * happen to stem from the same underlying weakness.
   *
   * Annotates findings in-place with `rootCauseGroup` and `relatedFindings`.
   * Returns the groups array (empty when fewer than 2 findings or no model).
   */
  async groupByRootCause(): Promise<RootCauseGroup[]> {
    if (!this.model || this.findings.length < 2) {
      return [];
    }

    // Snapshot findings before the (potentially slow) LLM call so that
    // concurrent register/unregister calls don't shift indices.
    const snapshot = [...this.findings];
    const prompt = buildRootCauseGroupingPrompt(snapshot);

    let result: z.infer<typeof RootCauseGroupResultSchema>;
    try {
      result = await generateObjectResponse({
        model: this.model,
        schema: RootCauseGroupResultSchema,
        prompt,
        system: ROOT_CAUSE_GROUPING_SYSTEM,
        authConfig: this.authConfig,
        abortSignal: this.abortSignal,
      });
    } catch {
      console.log(
        `[FindingsRegistry.groupByRootCause] LLM error — skipping root-cause grouping`,
      );
      return [];
    }

    // Sanitise groups: filter out-of-bounds indices and apply annotations
    // inside the mutex to avoid racing with register/unregister.
    const sanitised: RootCauseGroup[] = [];

    await new Promise<void>((resolve) => {
      this.mutex = this.mutex.then(() => {
        for (const group of result.groups) {
          const validIndices = group.findingIndices.filter(
            (i: number) => i >= 0 && i < snapshot.length,
          );
          if (validIndices.length < 2) continue;

          sanitised.push({
            groupId: group.groupId,
            findingIndices: validIndices,
            rootCause: group.rootCause,
          });

          for (const idx of validIndices) {
            const finding = snapshot[idx]!;
            finding.rootCauseGroup = group.groupId;
            // Use index-based exclusion so same-titled findings are handled correctly
            finding.relatedFindings = validIndices
              .filter((i: number) => i !== idx)
              .map((i: number) => snapshot[i]!.title);
          }
        }
        resolve();
      });
    });

    return sanitised;
  }

  // -----------------------------------------------------------------------
  // Internal
  // -----------------------------------------------------------------------

  private removeFinding(finding: Finding): void {
    const { exactKey, appWideKey } = generateFingerprint(finding);

    if (this.exactKeys.get(exactKey) === finding) {
      this.exactKeys.delete(exactKey);
    }
    if (this.appWideKeys.get(appWideKey) === finding) {
      this.appWideKeys.delete(appWideKey);
    }

    const idx = this.findings.indexOf(finding);
    if (idx !== -1) {
      this.findings.splice(idx, 1);
    }
  }

  private indexFinding(finding: Finding): void {
    const { exactKey, appWideKey } = generateFingerprint(finding);

    if (!this.exactKeys.has(exactKey)) {
      this.exactKeys.set(exactKey, finding);
    }
    if (!this.appWideKeys.has(appWideKey)) {
      this.appWideKeys.set(appWideKey, finding);
    }

    this.findings.push(finding);
  }
}
