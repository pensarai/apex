import { describe, expect, it } from "vitest";

import { formatSessionHandoffSummary } from "./sessionHandoff";

describe("formatSessionHandoffSummary", () => {
  it("includes session id, session path, findings, pocs, and report path", () => {
    expect(
      formatSessionHandoffSummary({
        sessionId: "ses_123",
        sessionPath: "/home/user/.pensar/sessions/ses_123",
        findingsPath: "/home/user/.pensar/sessions/ses_123/findings",
        pocsPath: "/home/user/.pensar/sessions/ses_123/pocs",
        reportPath: "/home/user/.pensar/sessions/ses_123/pentest-report.md",
      }),
    ).toBe(
      [
        "Session:       ses_123",
        "Session path:  /home/user/.pensar/sessions/ses_123",
        "Findings path: /home/user/.pensar/sessions/ses_123/findings",
        "POCs:          /home/user/.pensar/sessions/ses_123/pocs",
        "Report:        /home/user/.pensar/sessions/ses_123/pentest-report.md",
      ].join("\n"),
    );
  });

  it("omits report path when no report is produced", () => {
    expect(
      formatSessionHandoffSummary({
        sessionId: "ses_123",
        sessionPath: "/home/user/.pensar/sessions/ses_123",
        findingsPath: "/home/user/.pensar/sessions/ses_123/findings",
        pocsPath: "/home/user/.pensar/sessions/ses_123/pocs",
        reportPath: null,
      }),
    ).not.toContain("Report:");
  });
});
