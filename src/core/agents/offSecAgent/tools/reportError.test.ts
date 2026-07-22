import { describe, expect, it, vi } from "vitest";
import {
  createReportErrorTool,
  PentestReportedError,
  REPORT_ERROR_TOOL_NAME,
  type ReportedError,
} from "./reportError";

describe("report_error tool", () => {
  it("uses the stable tool name", () => {
    expect(REPORT_ERROR_TOOL_NAME).toBe("report_error");
  });

  it("forwards the reason + message to the onError callback", async () => {
    const onError = vi.fn<(error: ReportedError) => void>();
    const tool = createReportErrorTool(onError);

    const result = await tool.execute?.(
      {
        reason: "authentication_failed",
        message: "Login at https://app.example.com/login returned 401",
      },
      { toolCallId: "tc_1", messages: [] },
    );

    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError).toHaveBeenCalledWith({
      reason: "authentication_failed",
      message: "Login at https://app.example.com/login returned 401",
    });
    expect(result).toEqual({
      success: true,
      message: "Blocking error reported. Ending run.",
    });
  });

  it("wraps a reported error so its reason + message survive throwing", () => {
    const err = new PentestReportedError({
      reason: "target_unreachable",
      message: "Target refused all connections",
    });

    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("PentestReportedError");
    expect(err.reason).toBe("target_unreachable");
    expect(err.message).toBe("Target refused all connections");
  });
});
