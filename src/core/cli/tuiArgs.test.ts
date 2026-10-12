import { describe, expect, it } from "vitest";
import { parseTuiArgs } from "./tuiArgs";

describe("parseTuiArgs", () => {
  it("opens the home screen without a resume request", () => {
    expect(parseTuiArgs([])).toEqual({});
  });

  it("resumes an exact session without changing its saved settings", () => {
    expect(parseTuiArgs(["--resume", "ses_abc123"])).toEqual({
      sessionId: "ses_abc123",
    });
  });

  it("preserves a provider-qualified model selection", () => {
    const args = [
      "--resume",
      "ses_abc123",
      "--model",
      "custom:local:model/name",
    ];
    expect(parseTuiArgs(args)).toEqual({
      sessionId: "ses_abc123",
      modelId: "custom:local:model/name",
    });
    expect(args).toHaveLength(4);
  });

  it("accepts the prefixed IDs used by benchmark sessions", () => {
    expect(parseTuiArgs(["--resume", "benchmark-XBEN-ses_abc123"])).toEqual({
      sessionId: "benchmark-XBEN-ses_abc123",
    });
  });

  it.each([
    ["--resume"],
    ["--resume", ""],
    ["--resume", "--model"],
    ["--resume", "ses_../other"],
    ["--resume", "ses_..\\other"],
    ["--resume", "ses_name\n"],
    ["--resume", "/tmp/session"],
  ])("rejects missing or unsafe session IDs: %j", (...args) => {
    expect(() => parseTuiArgs(args)).toThrow("saved session ID");
  });

  it.each([
    ["--resume", "ses_abc", "--model"],
    ["--resume", "ses_abc", "--model", ""],
    ["--resume", "ses_abc", "--model", "--help"],
    ["--resume", "ses_abc", "--model", "m", "--model", "n"],
    ["--resume", "ses_abc", "-p", "new task"],
    ["--resume", "ses_abc", "--auto"],
    ["pentest", "--resume", "ses_abc"],
  ])("rejects malformed or conflicting resume options: %j", (...args) => {
    expect(() => parseTuiArgs(args)).toThrow("Use pensar --resume");
  });
});
