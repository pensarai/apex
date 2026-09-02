import { describe, expect, it } from "vitest";
import { AUTH_SUBAGENT_SYSTEM_PROMPT } from "./prompts";

describe("AUTH_SUBAGENT_SYSTEM_PROMPT", () => {
  it("reserves a shared Mobile OTP number before requesting a code", () => {
    expect(AUTH_SUBAGENT_SYSTEM_PROMPT).toContain(
      "sms_list_messages` with `reserve=true",
    );
    expect(AUTH_SUBAGENT_SYSTEM_PROMPT).toContain(
      "Never pass\n   a phone number to this tool",
    );
    expect(AUTH_SUBAGENT_SYSTEM_PROMPT).toContain(
      "If it returns 429, retry this reservation later",
    );
    expect(AUTH_SUBAGENT_SYSTEM_PROMPT).toContain(
      "sms_list_messages` with `sinceMs` and `claim=true",
    );
  });
});
