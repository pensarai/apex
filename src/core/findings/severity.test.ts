import { describe, expect, it } from "vitest";
import {
  FindingSeveritySchema,
  findingSeverityFromCvssSeverity,
} from "./severity";

describe("FindingSeveritySchema", () => {
  it("accepts informational severity values below low", () => {
    const result = FindingSeveritySchema.safeParse("informational");

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toBe("INFORMATIONAL");
    }
  });

  it("normalizes prefixed severity strings", () => {
    const result = FindingSeveritySchema.safeParse("> info");

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toBe("INFORMATIONAL");
    }
  });

  it("maps CVSS NONE to informational findings", () => {
    expect(findingSeverityFromCvssSeverity("NONE")).toBe("INFORMATIONAL");
    expect(findingSeverityFromCvssSeverity("LOW")).toBe("LOW");
  });
});
