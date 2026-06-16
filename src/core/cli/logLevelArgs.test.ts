import { describe, expect, it } from "vitest";
import { CliLogLevelError, resolveCliLogLevel } from "./logLevelArgs";

describe("resolveCliLogLevel", () => {
  it("--log-level sets the level and strips the flag + value (case-insensitive)", () => {
    const argv = ["pentest", "--log-level", "warn", "--target", "x"];
    expect(resolveCliLogLevel(argv)).toBe("WARN");
    expect(argv).toEqual(["pentest", "--target", "x"]);
  });

  it("--verbose ⇒ DEBUG and --quiet ⇒ WARN, both stripped", () => {
    const v = ["a", "--verbose", "b"];
    expect(resolveCliLogLevel(v)).toBe("DEBUG");
    expect(v).toEqual(["a", "b"]);

    const q = ["a", "--quiet"];
    expect(resolveCliLogLevel(q)).toBe("WARN");
    expect(q).toEqual(["a"]);
  });

  it("--log-level wins over --verbose / --quiet", () => {
    expect(resolveCliLogLevel(["--verbose", "--log-level", "error"])).toBe(
      "ERROR",
    );
    expect(resolveCliLogLevel(["--log-level", "info", "--quiet"])).toBe("INFO");
  });

  it("rightmost --log-level wins on duplicates", () => {
    expect(
      resolveCliLogLevel(["--log-level", "info", "--log-level", "error"]),
    ).toBe("ERROR");
  });

  it("returns undefined and leaves argv intact when no log flags", () => {
    const argv = ["pentest", "--target", "https://x", "--obfuscate"];
    expect(resolveCliLogLevel(argv)).toBeUndefined();
    expect(argv).toEqual(["pentest", "--target", "https://x", "--obfuscate"]);
  });

  it("throws CliLogLevelError on an invalid --log-level value", () => {
    expect(() => resolveCliLogLevel(["--log-level", "BOGUS"])).toThrow(
      CliLogLevelError,
    );
  });

  it("throws CliLogLevelError when --log-level has no value", () => {
    expect(() => resolveCliLogLevel(["pentest", "--log-level"])).toThrow(
      CliLogLevelError,
    );
  });
});
