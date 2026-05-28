// Contract tests for the deprecated `offensiveHeaders` shim. Pin the
// boundary: regardless of which deprecated mode a caller passes, the
// persisted config has `headers` only and never both fields. Delete
// this file when the shim is removed.

import { describe, expect, it } from "vitest";
import { migrateLegacySessionData, type OffensiveHeadersConfig } from "./index";

// Compile-time guard that `OffensiveHeadersConfig` is still exported.
const _typeExportCheck: OffensiveHeadersConfig = {
  mode: "custom",
  headers: { "X-A": "1" },
};
void _typeExportCheck;

function wrap(config: Record<string, unknown>) {
  return {
    id: "test",
    targets: ["https://example.com"],
    config,
  };
}

function configOf(result: unknown): Record<string, unknown> {
  return (result as { config: Record<string, unknown> }).config;
}

describe("migrateLegacySessionData — offensiveHeaders shim", () => {
  it("mode 'custom' → flat headers + strips deprecated field", () => {
    const result = migrateLegacySessionData(
      wrap({
        offensiveHeaders: { mode: "custom", headers: { "X-A": "1" } },
      }),
    );
    const cfg = configOf(result);
    expect(cfg.headers).toEqual({ "X-A": "1" });
    expect("offensiveHeaders" in cfg).toBe(false);
  });

  it("mode 'default' seeds the User-Agent default", () => {
    const result = migrateLegacySessionData(
      wrap({ offensiveHeaders: { mode: "default", headers: { "X-A": "1" } } }),
    );
    const cfg = configOf(result);
    expect(cfg.headers).toEqual({
      "User-Agent": "pensar-apex",
      "X-A": "1",
    });
    expect("offensiveHeaders" in cfg).toBe(false);
  });

  it("mode 'none' yields empty headers", () => {
    const result = migrateLegacySessionData(
      wrap({ offensiveHeaders: { mode: "none" } }),
    );
    const cfg = configOf(result);
    expect(cfg.headers).toEqual({});
    expect("offensiveHeaders" in cfg).toBe(false);
  });

  it("mode 'none' overrides a populated headers field", () => {
    // Regression: `oh.headers` merge previously ran unconditionally.
    const result = migrateLegacySessionData(
      wrap({
        offensiveHeaders: { mode: "none", headers: { "X-A": "1" } },
      }),
    );
    const cfg = configOf(result);
    expect(cfg.headers).toEqual({});
    expect("offensiveHeaders" in cfg).toBe(false);
  });

  it("flat headers win when both fields are present", () => {
    const result = migrateLegacySessionData(
      wrap({
        headers: { "X-Flat": "wins" },
        offensiveHeaders: { mode: "custom", headers: { "X-Deprecated": "1" } },
      }),
    );
    const cfg = configOf(result);
    expect(cfg.headers).toEqual({ "X-Flat": "wins" });
    expect("offensiveHeaders" in cfg).toBe(false);
  });

  it("no-op when neither field is present", () => {
    const input = wrap({ mode: "auto" });
    const result = migrateLegacySessionData(input);
    // identity — nothing to migrate, no spread cost
    expect(result).toBe(input);
  });

  it("preserves unrelated config fields", () => {
    const result = migrateLegacySessionData(
      wrap({
        mode: "auto",
        outcomeGuidance: "do the thing",
        offensiveHeaders: { mode: "custom", headers: { "X-A": "1" } },
      }),
    );
    const cfg = configOf(result);
    expect(cfg.mode).toBe("auto");
    expect(cfg.outcomeGuidance).toBe("do the thing");
    expect(cfg.headers).toEqual({ "X-A": "1" });
  });

  it("safely returns input for non-object payloads", () => {
    expect(migrateLegacySessionData(null)).toBeNull();
    expect(migrateLegacySessionData("not an object")).toBe("not an object");
    expect(migrateLegacySessionData(undefined)).toBeUndefined();
  });
});
