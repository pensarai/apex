import { describe, expect, it } from "vitest";
import { resolveCliLogLevel } from "./logLevelArgs";

describe("resolveCliLogLevel", () => {
  it("--log-level sets the level and strips the flag + value (case-insensitive)", () => {
    const argv = ["pentest", "--log-level", "warn", "--target", "x"];
    expect(resolveCliLogLevel(argv)).toEqual({
      level: "WARN",
      invalid: undefined,
    });
    expect(argv).toEqual(["pentest", "--target", "x"]);
  });

  it("--verbose ⇒ DEBUG and --quiet ⇒ WARN, both stripped", () => {
    const v = ["a", "--verbose", "b"];
    expect(resolveCliLogLevel(v).level).toBe("DEBUG");
    expect(v).toEqual(["a", "b"]);

    const q = ["a", "--quiet"];
    expect(resolveCliLogLevel(q).level).toBe("WARN");
    expect(q).toEqual(["a"]);
  });

  it("--log-level wins over --verbose / --quiet", () => {
    expect(
      resolveCliLogLevel(["--verbose", "--log-level", "error"]).level,
    ).toBe("ERROR");
    expect(resolveCliLogLevel(["--log-level", "info", "--quiet"]).level).toBe(
      "INFO",
    );
  });

  it("rightmost --log-level wins on duplicates", () => {
    expect(
      resolveCliLogLevel(["--log-level", "info", "--log-level", "error"]).level,
    ).toBe("ERROR");
  });

  it("an invalid earlier --log-level is ignored when the rightmost is valid", () => {
    const argv = ["--log-level", "bogus", "--log-level", "error", "x"];
    expect(resolveCliLogLevel(argv)).toEqual({
      level: "ERROR",
      invalid: undefined,
    });
    expect(argv).toEqual(["x"]);
  });

  it("returns undefined and leaves argv intact when no log flags", () => {
    const argv = ["pentest", "--target", "https://x", "--obfuscate"];
    expect(resolveCliLogLevel(argv)).toEqual({
      level: undefined,
      invalid: undefined,
    });
    expect(argv).toEqual(["pentest", "--target", "https://x", "--obfuscate"]);
  });

  it("reports an invalid winning --log-level (no throw) and strips it", () => {
    const argv = ["pentest", "--log-level", "bogus", "--target", "x"];
    const r = resolveCliLogLevel(argv);
    expect(r.level).toBeUndefined();
    expect(r.invalid).toBe("bogus");
    expect(argv).toEqual(["pentest", "--target", "x"]);
  });

  it("reports a missing --log-level value", () => {
    expect(resolveCliLogLevel(["pentest", "--log-level"]).invalid).toBe(
      "(missing)",
    );
  });

  it("a value-less --log-level doesn't consume the following flag", () => {
    const argv = ["pentest", "--log-level", "--target", "x"];
    const r = resolveCliLogLevel(argv);
    expect(r.invalid).toBe("(missing)");
    expect(argv).toEqual(["pentest", "--target", "x"]);
  });

  it("falls back to the shorthand when the winning --log-level is invalid", () => {
    const r = resolveCliLogLevel(["--verbose", "--log-level", "bogus"]);
    expect(r.level).toBe("DEBUG");
    expect(r.invalid).toBe("bogus");
  });
});
