import pLimit from "p-limit";
import { z } from "zod";
import { AgentEventBus } from "../../../eventBus";
import { writeErrorLog } from "../../../logger";
import type { RiskScore } from "../../specialized/whiteboxAttackSurface";
import type { ToolContext } from "./types";

// Process-wide cap — parents emit `document_endpoint` tool calls in parallel,
// so without this gate each parent fans out unboundedly.
const THREAT_MODEL_CONCURRENCY = 10;
const threatModelLimiter = pLimit(THREAT_MODEL_CONCURRENCY);

// ---------------------------------------------------------------------------
// Response schema
// ---------------------------------------------------------------------------
//
// The endpoint analysis agent returns one object containing four sections:
//
//   1. businessLogic   — comprehensive prose describing what the endpoint
//                        does and the rules it must uphold.
//   2. threatModel     — comprehensive prose grounded in the business logic
//                        covering attacker profiles, attack vectors, and a
//                        risk assessment.
//   3. Risk score      — the existing 4-dimension breakdown (unchanged shape).
//   4. pentestObjectives — a bounded array of falsifiable hypotheses the
//                          pentest agent can execute deterministically.
//
// `businessLogic` and `threatModel` are stored verbatim as text columns.
// `pentestObjectives` is flattened to markdown strings before persistence
// (the DB column is `text[]`).

const PentestObjectiveSchema = z.object({
  title: z
    .string()
    .describe("Short human-readable name. E.g. 'IDOR via orderId path param'."),
  hypothesis: z
    .string()
    .describe(
      "Falsifiable negative statement the test aims to prove true. " +
        "E.g. 'The endpoint fails to validate that the authenticated user owns the order " +
        "referenced by :orderId, permitting cross-tenant reads.'",
    ),
  prerequisites: z
    .string()
    .describe(
      "Concrete state that must exist in the application or environment before setup can " +
        "run. ONLY list application-specific state — NOT generic tooling (curl, HTTP client, " +
        "wordlists, hashcat, Python libraries are assumed and must not appear here). List: " +
        "specific account credentials (email + password), pre-existing records referenced by " +
        "id, env vars / secrets the endpoint depends on, feature flags, signing keys, " +
        "webhook secrets, seeded DB rows. Quote concrete values when the business logic exposes " +
        "them (e.g. admin credentials seeded in init.sql:42). If the test truly needs no " +
        "pre-existing state (pure public probe), write 'None.'",
    ),
  setup: z
    .string()
    .describe(
      "Ordered agent actions that establish the testable state, grounded in the endpoint's " +
        "business logic. The pentest agent can drive a real browser (navigate, fill forms, " +
        "click, read cookies/DOM) AND issue raw HTTP requests. Reference concrete routes, " +
        "parameters, and captures from the business logic you documented in Part 1. Each step " +
        "must name the interaction and what to capture. Numbered list in one string. " +
        "E.g. '1. Navigate browser to POST /api/auth/login with account A creds (prereq). " +
        "2. Capture the `token` cookie from the response Set-Cookie header; store as $TOKEN_A. " +
        "3. Repeat for account B; store as $TOKEN_B. 4. Call POST /api/orders as A with " +
        "{item: X, qty: 1}; record returned `orderId` as $ORDER_A.' " +
        "If the test is pure public probing with no state required, write 'No setup required — " +
        "target endpoint is reachable without authentication.' Never emit generic tooling " +
        "bootstrap (installing curl, starting the dev server) — assume the target is running.",
    ),
  procedure: z
    .string()
    .describe(
      "The hypothesis-executing steps that operate on the state established by Setup. " +
        "Numbered list in one string. Reference the captured values from Setup by their " +
        "names ($TOKEN_A, $ORDER_A, etc.). Each step must be directly executable without " +
        "re-inferring context. E.g. '1. Issue GET /api/orders/$ORDER_A with Cookie: token=$TOKEN_B. " +
        "2. Record HTTP status and response body. 3. Issue GET /api/orders/99999999 with " +
        "Cookie: token=$TOKEN_B as a baseline for not-found behavior.'",
    ),
  successSignal: z
    .string()
    .describe(
      "The observable result that confirms the vulnerability. Include common false-positive " +
        "traps inline. E.g. 'Step 1 returns HTTP 200 with $ORDER_A body. A 404 does NOT confirm " +
        "isolation — compare against the step 3 baseline to distinguish access-control " +
        "enforcement from not-found behavior.'",
    ),
  priority: z
    .enum(["p0", "p1", "p2"])
    .describe(
      "p0 = likely AND high/critical impact. p1 = one of (likely, high impact). " +
        "p2 = speculative or low impact.",
    ),
});

type PentestObjective = z.infer<typeof PentestObjectiveSchema>;

// Reused by every schema field that demands `file:line` citation. Mirrors the
// source-unavailable mode definition in the prompt body so the JSON-schema
// constraints don't contradict the prompt when the handler source is
// unreachable.
const SCHEMA_SOURCE_UNAVAILABLE_NOTE =
  "If the handler source is unreachable in your environment (source-unavailable mode — see prompt body), cite the grounding source you actually read (endpoint description, route table, OpenAPI spec, README) instead of `file:line` and tag the claim `[unverified: source unavailable]`. Never fabricate `file:line` references or invent code paths.";

const ThreatModelResultSchema = z.object({
  businessLogic: z
    .string()
    .describe(
      "Comprehensive narrative (aim for 800-2000 words) of what this endpoint does and the " +
        "rules it must uphold. Use markdown headings. Cover, in order: " +
        "(1) Purpose — what the endpoint accomplishes in user terms. " +
        "(2) Actors — who legitimately interacts with it, what they can do, how they authenticate. " +
        "(3) Data flow — inputs (with channel and trust level), transformations, side effects, outputs. " +
        "(4) Invariants — falsifiable business rules the endpoint must uphold, with enforcement " +
        "location (file:line) and confidence level. " +
        "(5) Trust boundaries — what actually guards each crossing (not what should). " +
        "(6) Analysis gaps — what you did NOT trace into and why. " +
        "Cite file:line for every concrete claim. Prefer completeness over brevity. " +
        SCHEMA_SOURCE_UNAVAILABLE_NOTE,
    ),

  threatModel: z
    .string()
    .describe(
      "Comprehensive threat model (aim for 800-2000 words) grounded in the business logic. " +
        "Use markdown headings. Cover: " +
        "(1) Attacker profiles — 2-4 realistic attackers with motivation, skill, position, and goal. " +
        "(2) Attack vectors — enumerate thoroughly (typically 8-15 for a non-trivial endpoint). " +
        "Each vector must reference a concrete input from the business logic, the invariant it " +
        "would break, the mechanism, the observable signal of success, an attacker profile, " +
        "likelihood, and impact. Cite file:line. " +
        "(3) Risk assessment — worst-case impact and vector prioritization. " +
        "Do not include generic OWASP filler ungrounded in evidence you actually read. " +
        SCHEMA_SOURCE_UNAVAILABLE_NOTE,
    ),

  exposure: z
    .number()
    .min(0)
    .max(3)
    .describe(
      "Exposure Level (0-3): how reachable is this endpoint by an attacker? " +
        "3 = Public, no authentication required. " +
        "2 = Standard authenticated user can reach it. " +
        "1 = Requires privileged/admin role. " +
        "0 = Private, internal-only, IP-restricted, or behind a service mesh.",
    ),
  exposureReasoning: z
    .string()
    .describe(
      "Cite specific code/config signals (file:line) that determined the exposure score: " +
        "route registration, auth middleware, role guards, IP allowlists, network placement. " +
        "E.g. 'Route registered on public router with no auth middleware (app.ts:18). " +
        "Handler does not check req.user.' " +
        SCHEMA_SOURCE_UNAVAILABLE_NOTE,
    ),

  dataSensitivity: z
    .number()
    .min(0)
    .max(3)
    .describe(
      "Data Sensitivity (0-3): how sensitive is the data this endpoint reads, writes, or returns? " +
        "3 = PII, PHI, financial records, passwords, tokens, secrets, session material. " +
        "2 = Business-operations data, tenant configs, internal settings, non-public metadata. " +
        "1 = Low-value user data (public profile, preferences). " +
        "0 = No meaningful data (static content, health checks, public catalog).",
    ),
  dataSensitivityReasoning: z
    .string()
    .describe(
      "Name the concrete data observed. Reference the table, field, or response shape (file:line). " +
        "E.g. 'Response includes users.email, users.phone, and order.total (query in userRepo.ts:42). " +
        "Email + phone are PII.' " +
        SCHEMA_SOURCE_UNAVAILABLE_NOTE,
    ),

  functionCriticality: z
    .number()
    .min(0)
    .max(2)
    .describe(
      "Function Criticality (0-2): how security-critical is the action this endpoint performs? " +
        "2 = Security-critical operations: authentication, password reset, MFA enrollment, payment, " +
        "permission/role changes, key rotation, account deletion. " +
        "1 = Core product functionality: CRUD on user-owned resources, standard mutations. " +
        "0 = Non-critical content or utility endpoints: static reads, health checks, metrics.",
    ),
  functionCriticalityReasoning: z
    .string()
    .describe(
      "State what the endpoint actually does and why that puts it in the chosen tier. " +
        "Reference transformations and side effects from the business logic. " +
        "E.g. 'Handler rotates API keys (keys.ts:90) and invalidates prior sessions — auth-critical.'",
    ),

  securityIndicators: z
    .number()
    .min(0)
    .max(2)
    .describe(
      "Security Indicators (0-2): severity of vulnerability patterns directly observed in code. " +
        "2 = Critical patterns present: string-concatenated SQL, shell interpolation of user input, " +
        "hardcoded secrets, unsafe deserialization, unvalidated path traversal, missing ownership checks. " +
        "1 = Moderate concerns: weak/absent input validation, verbose error handling leaking internals, " +
        "permissive CORS, missing output encoding, missing rate limiting on sensitive ops. " +
        "0 = No observable security issues — code follows standard defensive patterns for its context.",
    ),
  securityIndicatorsReasoning: z
    .string()
    .describe(
      "List the specific patterns observed with file:line references. If none were observed, say so " +
        "explicitly and note what defensive patterns ARE present. " +
        "E.g. 'Observed string concatenation into raw SQL at orders.ts:77 (user-controlled orderId). " +
        "No parameterization. No input validation upstream.' " +
        SCHEMA_SOURCE_UNAVAILABLE_NOTE +
        " In source-unavailable mode the appropriate score is usually `0` (no patterns observable) — say so in the reasoning rather than inferring patterns from the description.",
    ),

  riskScoreJustification: z
    .string()
    .describe(
      "One paragraph (3-6 sentences) explaining the overall risk posture. Tie the four sub-scores " +
        "together and explain which attacker profile from the threat model is most concerning given " +
        "the combination. Do not re-list the sub-scores mechanically — explain why this endpoint's " +
        "specific combination of exposure + data + criticality + observed issues produces its total.",
    ),

  pentestObjectives: z
    .array(PentestObjectiveSchema)
    .describe(
      "Adversarial test plan: 10-12 falsifiable hypotheses the pentest agent can execute " +
        "deterministically. Every objective must trace back to an attack vector named in the threat " +
        "model. Include every p0 objective; fill remaining slots with p1 (breadth over payload " +
        "variants); include p2 only if slots remain. Do not emit placeholder one-liners like " +
        "'Test for SQL injection'. If you have fewer than 10 meaningful tests, revisit the threat " +
        "model — you probably under-enumerated vectors.",
    ),
});

type ThreatModelResult = z.infer<typeof ThreatModelResultSchema>;

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

const THREAT_MODEL_SYSTEM_PROMPT = `You are an Endpoint Analysis Agent. For a single API endpoint or web page, you produce:
  1. a grounded **business logic model** — what the endpoint does and the rules it must uphold,
  2. a focused **threat model** derived from that business logic,
  3. a quantitative **risk score** (0-10),
  4. an **adversarial test plan** — falsifiable hypotheses a pentest agent can execute deterministically.

You read the source code before you reason. Every claim in your analysis must be grounded in evidence you actually read — code where available (cite file:line), or the endpoint description and upstream artifacts (route table, OpenAPI spec, README) when the handler source is unreachable. In the latter case, follow the source-unavailable mode rules in the prompt body: cite the grounding source, tag the claim \`[unverified: source unavailable]\`, and cap pentest objective priority at \`p1\`. Generic OWASP/security filler that isn't tied to a specific input, transformation, line, or upstream artifact is not acceptable.

Work the four parts in order. Do not skip ahead. The business logic is the anchor for the threat model; the threat model is the anchor for the test plan. Threats that do not reference the business logic are ungrounded. Tests that do not reference a threat are ungrounded.

Err on the side of comprehensiveness. It is better to trace one more dependency, name one more invariant, or include one more attack vector than to stop early. Downstream consumers of your analysis — UI, pentest agent, human reviewers — benefit more from depth than from brevity. Do not pad with restated rubrics or generic security advice, but do exhaust the surface area of what this specific endpoint does and what could go wrong with it.

Think in terms of concrete attackers — not abstract threat categories. Identify the realistic attacker profiles that would actually target this endpoint given its exposure, data, and function, then ground every attack vector and test in what a specific attacker would do. Skip profiles that are not realistic for this endpoint.

Your output is consumed by an automated pentest agent. The clarity and specificity of your test plan directly determines whether the pentest succeeds or fails. Vague tests produce vague results. Falsifiable hypotheses with concrete procedures and unambiguous success signals produce real findings.`;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface GenerateThreatModelInput {
  appName: string;
  routePath: string;
  method?: string | string[];
  file?: string;
  line?: number;
  handler?: string;
  authRequired?: boolean;
  description: string;
}

export interface ThreatModelOutput {
  businessLogic: string;
  threatModel: string;
  riskScore: RiskScore;
  pentestObjectives: string[];
}

/**
 * Spawn a dedicated CodeAgent to produce a business-logic model, threat model,
 * quantitative risk score, and adversarial test plan for a single endpoint.
 * All four sections come from one agent pass — the agent reads the source
 * code once and returns the full structured response.
 *
 * The structured `pentestObjectives` objects are flattened to markdown strings
 * before returning so downstream consumers (apex-adapter, DB) see the existing
 * `string[]` shape.
 */
export async function generateThreatModelForEndpoint(
  ctx: ToolContext,
  input: GenerateThreatModelInput,
): Promise<ThreatModelOutput | null> {
  if (!ctx.model) return null;
  const model = ctx.model;

  return threatModelLimiter(async () => {
    if (ctx.abortSignal?.aborted) return null;

    const { CodeAgent } = await import("../../specialized/codeAgent/agent");

    const subagentId = `threat-model-${sanitize(input.appName)}-${sanitize(input.routePath)}`;

    ctx.eventBus?.emit("subagent-spawn", {
      subagentId,
      name: `Threat Model: ${input.routePath}`,
      input: { app: input.appName, endpoint: input.routePath },
      parentSubagentId: ctx.subagentId,
    });

    const localBus = new AgentEventBus();
    AgentEventBus.attachChild(localBus, ctx.eventBus, subagentId);

    const prompt = buildThreatModelPrompt(input, ctx.projectThreatModel);

    const agent = new CodeAgent<ThreatModelResult>({
      codebasePath: ctx.agentCwd,
      objective: prompt,
      system: THREAT_MODEL_SYSTEM_PROMPT,
      model,
      session: ctx.session,
      authConfig: ctx.authConfig,
      abortSignal: ctx.abortSignal,
      eventBus: localBus,
      subagentId,
      responseSchema: ThreatModelResultSchema,
      excludeTools: ["document_endpoint", "document_app"],
    });

    try {
      const result = await agent.consume();
      ctx.eventBus?.emit("subagent-complete", {
        subagentId,
        status: "completed",
        parentSubagentId: ctx.subagentId,
      });

      if (!result) return null;

      const totalScore =
        result.exposure +
        result.dataSensitivity +
        result.functionCriticality +
        result.securityIndicators;

      return {
        businessLogic: result.businessLogic,
        threatModel: result.threatModel,
        riskScore: {
          score: totalScore,
          explanation: result.riskScoreJustification,
          breakdown: {
            exposure: result.exposure,
            dataSensitivity: result.dataSensitivity,
            functionCriticality: result.functionCriticality,
            securityIndicators: result.securityIndicators,
          },
        },
        pentestObjectives: (result.pentestObjectives ?? []).map(
          flattenPentestObjective,
        ),
      };
    } catch (error) {
      ctx.eventBus?.emit("subagent-complete", {
        subagentId,
        status: "failed",
        parentSubagentId: ctx.subagentId,
      });
      writeErrorLog(
        `Threat model generation failed for ${input.routePath}: ${error instanceof Error ? error.message : String(error)}`,
        "THREAT_MODEL",
      );
      return null;
    }
  });
}

// ---------------------------------------------------------------------------
// Prompt construction
// ---------------------------------------------------------------------------

function buildThreatModelPrompt(
  input: GenerateThreatModelInput,
  projectThreatModel?: string,
): string {
  const lineRange = input.line ? `around line ${input.line}` : "";
  const authInfo = input.authRequired
    ? "Authentication required"
    : "No authentication required";
  const methodStr = Array.isArray(input.method)
    ? input.method.join(", ")
    : (input.method ?? "unknown");

  let prompt = `# Endpoint Analysis

## Target Endpoint
- **Application**: ${input.appName}
- **Method**: ${methodStr}
- **Path**: ${input.routePath}
- **File**: ${input.file ?? "unknown"}${input.line ? `:${input.line}` : ""}
- **Handler**: ${input.handler ?? "unknown"}
- **Auth**: ${authInfo}
- **Description**: ${input.description}

## Reading the code

1. Read the source file at \`${input.file ?? "(unknown)"}\` ${lineRange ? `(${lineRange})` : ""} to understand the implementation.
2. Trace into anything the handler depends on that affects security: auth middleware, repositories, validators, ORM models, external SDK calls, shared helpers. Do not stop at the handler function body.
3. If a dependency is out of scope or you chose not to trace it, record that under \`analysisGaps\` in Part 1 — do not silently assume.
4. **Source-unavailable mode.** If the handler source isn't reachable in your environment at all — not just out of scope, but actually unavailable (not checked out, missing from the sandbox, only the route table or OpenAPI spec is present) — record this once in \`analysisGaps\` and continue. In this mode the \`Cite file:line\` requirements below loosen to "cite the grounding source you actually read" (the endpoint description, route table entry, OpenAPI spec, README, or other upstream artifact). Each emitted threat-model vector and pentest objective must be tagged \`[unverified: source unavailable]\` in its title, and pentest objectives derived only from a description are capped at priority \`p1\` (never \`p0\`) because the vector hasn't been confirmed reachable in this implementation. Never fabricate file:line citations or invent code paths.

Work Parts 1 → 4 in order. Do not start Part 2 until Part 1 is complete. Do not write Part 4 until Part 2 is complete.

---

## Part 1: Business Logic (field: \`businessLogic\`)

Produce a comprehensive narrative of what this endpoint does and what must be true for it to be correct. Aim for 800-2000 words — depth and completeness are preferred. Cover every section below thoroughly. Use markdown headings. Work in this order:

### Purpose
1-3 sentences: what this endpoint accomplishes in user terms, not the code's terms.

### Actors
Who legitimately interacts with this endpoint. For each actor list their role, what they can legitimately do via this endpoint, and how they authenticate (session cookie, JWT, signed webhook, mTLS, API key, IP allowlist, etc.).

### Data Flow
- **Inputs**: each input the handler accepts — name, channel (path / query / body / header / cookie / file / env / upstream-service / queue / webhook), trust level (untrusted / semi-trusted / trusted), and any observed validation. Cite file:line.
- **Transformations**: the ordered steps the handler takes — fetch, validate, authorize, compute, call external service. Cite file:line for each.
- **Side effects**: every write the handler causes — DB writes, external API calls, email/queue/file writes, auth-state changes, payments. Name the target (table, service, queue).
- **Outputs**: what the response body, headers, and status codes contain.

### Invariants
The falsifiable business rules this endpoint must uphold. State each as a rule the attacker would try to break. Prefer listing more invariants over fewer — an endpoint rarely has just 2-3 rules that matter; most have 5-10 when you account for ownership, state transitions, rate/volume constraints, temporal rules, cross-resource consistency, and preconditions for side effects.
- Phrase as falsifiable statements: "A user can only retrieve orders they placed", not "the system protects user data".
- For each invariant, note **how** it is enforced (cite file:line) and your confidence: enforced / partially-enforced / assumed / unenforced.
- Invariants are the anchor for Part 2 — every business-logic attack vector should target one of these.

### Trust Boundaries
Where untrusted input crosses into trusted territory. For each boundary note what actually guards the crossing (auth middleware, signature verification, input schema, rate limit) — not what you wish guarded it.

### Analysis Gaps
What you did NOT trace into and why. Be honest — this is a first-class signal, not a weakness. Example: "Did not trace into \`stripe.paymentIntents.confirm()\` — out of scope for single-endpoint analysis."

---

## Part 2: Threat Model (field: \`threatModel\`)

Produce a comprehensive threat model grounded in Part 1. Aim for 800-2000 words. Enumerate attack vectors thoroughly — an endpoint with 5 inputs and 6 invariants typically has 8-15 distinct attack vectors worth naming, not 2-3. Use markdown headings.

### Attacker Profiles
2-4 realistic attackers who would target THIS endpoint. For each:
- Name + 1-2 sentence motivation grounded in the application's domain and what this endpoint does.
- Skill level (low / medium / high / expert).
- What the attacker controls: network position, accounts, API keys, authenticated session, insider access.
- What they want to achieve *via this endpoint specifically* — data theft, privilege escalation, account takeover, service disruption, financial fraud, etc.

Include a mix: an opportunistic external attacker, an authenticated user abusing legitimate access, and at least one more sophisticated or insider profile when realistic. Skip profiles that don't make sense for this endpoint.

### Attack Vectors

Specific attacks relevant to this endpoint. Work in two steps.

#### Step 1 — classify by functional role

Before enumerating, name the 1–3 **functional roles** this endpoint plays (from Part 1's purpose and data flow), then for each role recall the abuse classes characteristic of endpoints of that kind. Common roles:

| Role | Characteristic abuse classes |
|---|---|
| **Authentication / authz flow** (login, OAuth, password reset, MFA, token exchange) | Credential stuffing, account enumeration via timing or error differential, session fixation, token replay, OAuth \`state\` / \`nonce\` / \`code\` confusion, MFA bypass, password-reset token timing, cross-provider account-linking abuse |
| **Money movement / billing** (payments, refunds, credits, subscription changes) | Double-spend race, idempotency-key replay or omission, currency or unit confusion, client-trusted totals or prices, refund-to-other-method abuse, treating a webhook as the source of truth |
| **Webhook receiver / external callback** | Signature stripping or partial-signature accept, signature timing oracle, replay without a \`Date\` or nonce window, SSRF via callback or follow-up URL, accept-on-malformed |
| **File / media processing** (upload, parse, transform) | Zip / decompression bombs, polyglot files, parser RCE in image / PDF / XML / archive libs, MIME spoofing across downstream handlers, path traversal in stored filenames, content-disposition or cross-site download abuse |
| **AI / LLM interaction** (model prompt, tool call, retrieval — directly in this handler or via a downstream service it proxies user content to) | Direct prompt injection, indirect prompt injection via attachments / retrieved docs / tool output / cross-user data, system-prompt or context leakage, jailbreak or policy bypass, tool / function-call hijacking, unsafe handling of model output (passed to \`exec\` / \`eval\`, rendered as HTML or markdown, used to build SQL or shell, returned across tenants) |
| **Search / query** (full-text, structured filters, GraphQL) | ReDoS, NoSQL operator injection, query-language eval, mass-assignment via filter or sort params, pagination boundary disclosure |
| **Outbound messaging** (email, SMS, push) | Header injection (CRLF in subject / to / from), open-relay abuse, IDN or homoglyph spoofing, recipient enumeration, attachment-based delivery abuse |
| **Admin / privileged operation** (bulk delete, role change, impersonation, audit) | Audit-log bypass, dangerous defaults on bulk operations, UI-only gating not enforced server-side, impersonation token misuse, takeover via support or "act-as" surfaces |
| **Multi-tenant data access** (handler whose authority depends on a tenant or owner ID it accepts) | Cross-tenant ID injection in path / body / header, tenant-ID type confusion, shared-cache leakage across tenants, ownership check missing on referenced sub-resources |
| **Public content / static** | Cache pollution, response-splitting or header injection, scraping or amplification, parameter-based information disclosure |

This is a **recall checklist, not a license to invent.** Skip role classes that have no anchor in this endpoint's code. Endpoint-specific vectors that don't fall under a listed role are welcome — mark them "endpoint-specific". Endpoint descriptions that name a role (e.g. "AI assistant", "payment intent", "webhook receiver", "password reset") are a strong signal to classify the corresponding role; if the handler source is unreachable, classify the role anyway and proceed under **source-unavailable mode** (defined in the reading-the-code section) — vectors still emit, but they're tagged \`[unverified: source unavailable]\` and capped at \`p1\` in Part 4.

#### Step 2 — enumerate

Each vector must:
- Reference a concrete **input** from Part 1's data flow (the entry point).
- Reference the **invariant(s)** from Part 1 that it would break, when applicable. If a vector is a config/infrastructure concern with no business invariant, say so.
- Describe the **mechanism** concretely — reference actual parameters, data flows, and code patterns you observed. Cite file:line (or, in source-unavailable mode, the grounding source you read — see the reading-the-code section).
- State the **observable signal** of a successful exploit (what you would see externally to confirm it worked).
- Tie back to at least one attacker profile: "A [Profile Name] could …".
- Note **likelihood** (unlikely / possible / likely / near-certain) based on what you actually read — not OWASP base rates.
- Note **impact** (low / medium / high / critical).
- Reference the **role class** from Step 1 (e.g. "AI / LLM: indirect prompt injection") or label "endpoint-specific".

Be exhaustive rather than selective. It is fine — and expected — to include vectors rated \`likelihood: unlikely\` if they are technically realizable against this endpoint. Pruning happens in Part 4 via priority, not here. If two vectors differ only in payload variant (e.g. time-based vs. error-based SQLi on the same input), list them as separate vectors — they have different test procedures and success signals.

Do not list generic OWASP categories that aren't grounded in something you read. "Consider CSRF" without a state-changing endpoint and cookie auth is filler. The role registry above is a *recall trigger*, not a checklist of vectors to claim — every emitted vector must still trace to specific code, inputs, or invariants from Part 1.

### Risk Assessment
Worst-case impact of successful exploitation, and which vectors matter most given the combination of attackers and business logic above.

---

## Part 3: Risk Score

Score each dimension based on what you observed in the code. The total (0-10) is the sum.

### Exposure (0-3)
- 3 = Public, no auth
- 2 = Standard authenticated user
- 1 = Privileged/admin role required
- 0 = Private / internal-only / IP-restricted

### Data Sensitivity (0-3)
- 3 = PII, PHI, financial, passwords, tokens, secrets, session material
- 2 = Business-operations data, tenant configs, non-public metadata
- 1 = Low-value user data (public profile, preferences)
- 0 = No meaningful data (static content, health check, public catalog)

### Function Criticality (0-2)
- 2 = Auth flows, password reset, MFA, payments, permission/role changes, key rotation, account deletion
- 1 = Core product CRUD on user-owned resources
- 0 = Non-critical content or utility endpoints

### Security Indicators (0-2)
- 2 = Critical patterns observed: string-concatenated SQL, shell interpolation of user input, hardcoded secrets, unsafe deserialization, unvalidated path traversal, missing ownership checks on sensitive data
- 1 = Moderate concerns: weak/absent input validation, verbose error handling leaking internals, permissive CORS, missing output encoding, missing rate limiting on sensitive operations
- 0 = No observable security issues — code follows standard defensive patterns for its context

Every \`*Reasoning\` field must cite specific code (file:line). "Handler validates input" is insufficient. "Handler validates orderId via zod schema (orders.ts:40)" is required. In source-unavailable mode, cite the grounding source you read (e.g. "Endpoint description says auth required; no route table available") instead of file:line, and tag the reasoning \`[unverified: source unavailable]\`.

In \`riskScoreJustification\`, explain how the four sub-scores combine for this specific endpoint and which attacker profile from Part 2 is most concerning given that combination. Do not restate the rubric.

---

## Part 4: Adversarial Test Plan (field: \`pentestObjectives\`)

Emit 10-12 test objectives. Each is a falsifiable hypothesis a pentest agent can execute deterministically. Coverage is bounded — not every vector from Part 2 will get a test, and that's fine. Choose the 10-12 tests that give the best coverage of the highest-leverage vectors.

### Selection rules
- Every \`p0\` objective (from high-likelihood × high/critical-impact vectors) must be included.
- Fill remaining slots with \`p1\` objectives covering distinct vectors — prefer breadth across vectors over multiple payload variants of the same vector.
- Only include \`p2\` objectives if slots remain after p0 and p1 coverage.
- If a high-priority vector has multiple meaningful payload variants (e.g. time-based vs. error-based SQLi), pick the variant most likely to succeed given what you read in the code, and leave the others for future runs.

Prune aggressively toward this budget, but do not drop below 10 — if you have fewer than 10 meaningful tests, you probably under-enumerated Part 2's attack vectors; go back and expand them.

### Required fields per objective

Each objective describes a complete executable test in five fields. **prerequisites**, **setup**, and **procedure** together describe the full workflow — keep them distinct. Do not mix state, setup steps, and test steps into one field.

- **title**: short human-readable name.

- **hypothesis**: the falsifiable statement the test tries to prove true.

- **prerequisites**: the concrete application/environment state that must exist *before* the pentest agent starts. List specific accounts (email + password), pre-seeded records, env vars, signing secrets, feature flags. **Do not list generic tooling** — curl, HTTP clients, wordlists, hashcat, Python libraries, browsers are assumed. Quote concrete values from the code where the business logic exposes them (e.g. the admin credentials seeded in init.sql:42, a webhook signing secret referenced by env var). If the test needs no pre-existing state (pure public probe), write "None."

- **setup**: ordered actions the agent will take to reach the testable state, grounded in this endpoint's business logic. The pentest agent can drive a real browser — navigate, submit forms, read cookies, inspect the DOM — *and* issue raw HTTP requests. Use the business logic you documented in Part 1 to direct setup: if authentication is required, spell out the login route, credentials, and what cookie/header/localStorage value to capture. Reference captures by names the procedure can reuse (e.g. \`$TOKEN_A\`, \`$ORDER_A\`, \`$CSRF\`). If no setup is needed, write "No setup required — endpoint is reachable without authentication." Never emit generic bootstrap (installing tools, starting the dev server).

- **procedure**: the hypothesis-executing steps that operate on the state established by setup. Reference captures from setup by the names you assigned. Each step must be directly executable without the agent re-inferring context.

- **successSignal**: the observable result that confirms the vulnerability. Include common false-positive traps inline. Reference specific step numbers and captured baselines when comparing responses.

- **priority**: p0 (likely AND high/critical impact), p1 (one of: likely, high impact), p2 (speculative or low impact).

Do not emit placeholder one-liners like "Test for SQL injection". Do not emit tests for vectors that weren't named in Part 2. Do not emit tests without a concrete setup + procedure + success signal. Do not repeat the same setup verbatim across every objective — if multiple tests share setup, still include it in each (the agent consumes objectives in isolation), but avoid copy-pasting generic tooling instead of actual business-logic-grounded state preparation.

---

Call the \`response\` tool with your complete analysis: businessLogic, threatModel, risk score fields, and pentestObjectives.`;

  if (projectThreatModel) {
    prompt += `

## Additional Context — Project-Level Threat Model

The repository owner has provided a project-level threat model. Use it to inform your analysis — it may contain deployment details, compliance requirements, trust assumptions, or known concerns relevant to this endpoint. Where the project-level context conflicts with what you observe in code, trust the code and note the discrepancy under \`analysisGaps\` in Part 1.

<project-threat-model>
${projectThreatModel}
</project-threat-model>`;
  }

  return prompt;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Flatten a structured pentest objective into a single markdown block that
 * the pentest agent can consume directly as an objective string.
 */
function flattenPentestObjective(o: PentestObjective): string {
  return [
    `[${o.priority.toUpperCase()}] ${o.title}`,
    ``,
    `Hypothesis: ${o.hypothesis}`,
    ``,
    `Prerequisites: ${o.prerequisites}`,
    ``,
    `Setup:`,
    o.setup,
    ``,
    `Procedure:`,
    o.procedure,
    ``,
    `Success signal: ${o.successSignal}`,
  ].join("\n");
}

function sanitize(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9-_.]/g, "_");
}
