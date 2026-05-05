import { describe, expect, it } from "vitest";
import { INTERNAL_ID_PATTERN } from "../../../core/operator";

describe("INTERNAL_ID_PATTERN", () => {
  it.each([
    "apr_1777922893504_0d385b65",
    "act_1777922893504_0d385b65",
    "tc_1777922893504_0d385b65",
    "apr_1_aaaaaaaa",
    "tc_999999999999999_ffffffff",
  ])("matches internal correlation ID %s", (id) => {
    expect(INTERNAL_ID_PATTERN.test(id)).toBe(true);
  });

  it.each([
    "Running ffuf against example.com",
    "$ ffuf -u https://example.com/FUZZ -w wordlist.txt",
    "GET https://example.com/api/users",
    "nuclei cves -> https://example.com",
    "finding: SQL injection in /login",
    "read /etc/passwd",
    "Executing",
    "Running execute_command",
    "",
    "apr_not_a_real_id",
    "apr_1777922893504_zzzzzzzz",
    "apr_1777922893504_0d385b65 plus suffix",
    "prefix apr_1777922893504_0d385b65",
    "APR_1777922893504_0d385b65",
  ])("does not match human-readable string %s", (label) => {
    expect(INTERNAL_ID_PATTERN.test(label)).toBe(false);
  });
});
