import { describe, expect, it } from "vitest";
import {
  type ActionId,
  mintActionId,
  mintApprovalId,
  mintToolCallId,
} from "./ids";

describe("operator ID minters", () => {
  it("mints approval IDs with the shared shape", () => {
    expect(mintApprovalId()).toMatch(/^apr_\d+_[0-9a-f]{8}$/);
  });

  it("mints action IDs with the shared shape", () => {
    expect(mintActionId()).toMatch(/^act_\d+_[0-9a-f]{8}$/);
  });

  it("mints tool-call IDs with the shared shape", () => {
    expect(mintToolCallId()).toMatch(/^tc_\d+_[0-9a-f]{8}$/);
  });

  it("produces unique IDs in a tight loop", () => {
    expect(new Set(Array.from({ length: 1_000 }, mintApprovalId)).size).toBe(
      1_000,
    );
    expect(new Set(Array.from({ length: 1_000 }, mintActionId)).size).toBe(
      1_000,
    );
    expect(new Set(Array.from({ length: 1_000 }, mintToolCallId)).size).toBe(
      1_000,
    );
  });

  it("keeps approval and action IDs nominally distinct", () => {
    // @ts-expect-error ApprovalId must not be assignable to ActionId.
    const actionId: ActionId = mintApprovalId();
    expect(actionId).toMatch(/^apr_/);
  });
});
