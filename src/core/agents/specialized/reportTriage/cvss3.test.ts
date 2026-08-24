import { describe, expect, it } from "vitest";
import type { CVSSScorerResult } from "../cvssScorer";
import { convertCvss4ToHackerOneCvss3 } from "./cvss3";

describe("convertCvss4ToHackerOneCvss3", () => {
  it("converts low confidentiality-only network findings to CVSS 3.0", () => {
    const converted = convertCvss4ToHackerOneCvss3({
      score: 6.9,
      severity: "MEDIUM",
      vectorString:
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:A",
      scoreType: "CVSS-BT",
      reasoning: "Unauthenticated metadata disclosure.",
      cwes: [],
      metrics: {
        AV: "N",
        AC: "L",
        AT: "N",
        PR: "N",
        UI: "N",
        VC: "L",
        VI: "N",
        VA: "N",
        SC: "N",
        SI: "N",
        SA: "N",
        E: "A",
      },
    } satisfies CVSSScorerResult);

    expect(converted.score).toBe(5.3);
    expect(converted.severity).toBe("MEDIUM");
    expect(converted.vectorString).toBe(
      "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    );
  });
});
