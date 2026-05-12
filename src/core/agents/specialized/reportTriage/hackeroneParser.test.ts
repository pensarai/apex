import { describe, expect, it } from "vitest";
import { parseHackerOneJson } from "./hackeroneParser";

/**
 * A representative HackerOne `GET /reports/{id}` payload. Modelled on the
 * canonical JSON:API response shape and the field names documented at
 * https://api.hackerone.com/customer-resources/?json#report.
 */
const REPORT_API_PAYLOAD = {
  data: {
    id: "12345",
    type: "report",
    attributes: {
      title: "Reflected XSS in /search via q parameter",
      state: "new",
      severity_rating: "high",
      vulnerability_information: [
        "## Summary",
        "The `/search` endpoint reflects the `q` query parameter back into the response",
        "body without HTML-encoding it, allowing arbitrary JavaScript injection.",
        "",
        "## Steps To Reproduce",
        "1. Open https://staging.example.com/search?q=<script>alert(1)</script>",
        "2. Observe the unencoded reflection in the rendered HTML",
        "3. The script tag executes in the victim's browser",
        "",
        "```",
        "curl 'https://staging.example.com/search?q=<script>alert(document.cookie)</script>'",
        "```",
        "",
        "## Impact",
        "An attacker can hijack the session of any authenticated user who clicks a",
        "crafted link.",
        "",
        "## Attack Scenario",
        "Unauthenticated attacker sends the crafted URL via phishing.",
      ].join("\n"),
      created_at: "2026-05-10T08:30:00Z",
      source: "hackerone",
    },
    relationships: {
      reporter: { data: { id: "u1", type: "user" } },
      weakness: { data: { id: "w79", type: "weakness" } },
      structured_scopes: {
        data: [
          { id: "s1", type: "structured-scope" },
          { id: "s2", type: "structured-scope" },
        ],
      },
    },
  },
  included: [
    {
      id: "u1",
      type: "user",
      attributes: { username: "researcher_h4x", name: "H4x" },
    },
    {
      id: "w79",
      type: "weakness",
      attributes: { name: "Cross-site Scripting (XSS) - Reflected" },
    },
    {
      id: "s1",
      type: "structured-scope",
      attributes: {
        asset_identifier: "*.example.com",
        asset_type: "URL",
        eligible_for_submission: true,
      },
    },
    {
      id: "s2",
      type: "structured-scope",
      attributes: {
        asset_identifier: "marketing.example.com",
        asset_type: "URL",
        eligible_for_submission: false,
      },
    },
  ],
};

/**
 * Representative `report_created` webhook envelope. The activity is the
 * top-level resource and the report sits inside `relationships.report.data`
 * with the full body in `included`.
 */
const WEBHOOK_ENVELOPE = {
  data: {
    id: "act-1",
    type: "activity-report-created",
    attributes: {
      message: "Hacker submitted a report",
      created_at: "2026-05-10T08:30:00Z",
      internal: false,
    },
    relationships: {
      actor: { data: { id: "u1", type: "user" } },
      report: { data: { id: "12345", type: "report" } },
    },
  },
  included: [
    REPORT_API_PAYLOAD.data,
    ...REPORT_API_PAYLOAD.included,
  ],
};

describe("parseHackerOneJson", () => {
  it("maps a canonical GET /reports/{id} payload", () => {
    const result = parseHackerOneJson(JSON.stringify(REPORT_API_PAYLOAD));
    expect(result).not.toBeNull();

    expect(result?.title).toBe("Reflected XSS in /search via q parameter");
    expect(result?.hackerOneReportId).toBe("12345");
    expect(result?.claimedSeverity).toBe("HIGH");
    expect(result?.reporterHandle).toBe("researcher_h4x");
    expect(result?.vulnerabilityClass).toBe(
      "Cross-site Scripting (XSS) - Reflected",
    );
  });

  it("extracts steps and PoC curl from the markdown body", () => {
    const result = parseHackerOneJson(JSON.stringify(REPORT_API_PAYLOAD));
    expect(result?.pocSteps.length).toBeGreaterThanOrEqual(3);
    expect(result?.pocSteps[0]).toContain("staging.example.com/search");
    expect(result?.pocCurl).toContain("curl");
    expect(result?.pocCurl).toContain("alert(document.cookie)");
  });

  it("extracts the affected URL and impact sections", () => {
    const result = parseHackerOneJson(JSON.stringify(REPORT_API_PAYLOAD));
    expect(result?.affectedUrl).toContain("staging.example.com/search");
    expect(result?.impact).toContain("hijack the session");
  });

  it("captures the attacker model from a separate section", () => {
    const result = parseHackerOneJson(JSON.stringify(REPORT_API_PAYLOAD));
    expect(result?.attackerModel).toContain("Unauthenticated attacker");
  });

  it("maps structured_scopes with eligibility preserved", () => {
    const result = parseHackerOneJson(JSON.stringify(REPORT_API_PAYLOAD));
    expect(result?.structuredScopes).toHaveLength(2);
    const wildcard = result?.structuredScopes?.find(
      (s) => s.assetIdentifier === "*.example.com",
    );
    expect(wildcard?.eligibleForSubmission).toBe(true);
    const marketing = result?.structuredScopes?.find(
      (s) => s.assetIdentifier === "marketing.example.com",
    );
    expect(marketing?.eligibleForSubmission).toBe(false);
  });

  it("unwraps a webhook envelope and resolves the report from `included`", () => {
    const result = parseHackerOneJson(JSON.stringify(WEBHOOK_ENVELOPE));
    expect(result).not.toBeNull();
    expect(result?.hackerOneReportId).toBe("12345");
    expect(result?.title).toBe("Reflected XSS in /search via q parameter");
    expect(result?.structuredScopes?.length).toBe(2);
  });

  it("maps H1 severity 'none' onto INFORMATIONAL", () => {
    const payload = JSON.parse(JSON.stringify(REPORT_API_PAYLOAD));
    payload.data.attributes.severity_rating = "none";
    const result = parseHackerOneJson(JSON.stringify(payload));
    expect(result?.claimedSeverity).toBe("INFORMATIONAL");
  });

  it("returns null for non-H1 JSON (no `type: report` and no marker fields)", () => {
    const result = parseHackerOneJson(
      JSON.stringify({ foo: "bar", baz: [1, 2, 3] }),
    );
    expect(result).toBeNull();
  });

  it("returns null for unparseable JSON", () => {
    expect(parseHackerOneJson("not json at all")).toBeNull();
    expect(parseHackerOneJson("{ partial: ")).toBeNull();
  });

  it("falls back to title-based class inference when weakness is missing", () => {
    const payload = JSON.parse(JSON.stringify(REPORT_API_PAYLOAD));
    delete payload.data.relationships.weakness;
    payload.included = payload.included.filter(
      (i: { type: string }) => i.type !== "weakness",
    );
    const result = parseHackerOneJson(JSON.stringify(payload));
    expect(result?.vulnerabilityClass).toBe("Cross-Site Scripting (XSS)");
  });

  it("does not require a reporter relationship", () => {
    const payload = JSON.parse(JSON.stringify(REPORT_API_PAYLOAD));
    delete payload.data.relationships.reporter;
    const result = parseHackerOneJson(JSON.stringify(payload));
    expect(result).not.toBeNull();
    expect(result?.reporterHandle).toBeUndefined();
  });
});
