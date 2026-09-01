import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { createResponseTool } from "./response";

async function executeResponse(
  responseTool: ReturnType<typeof createResponseTool>,
  complete: boolean,
) {
  const executable = responseTool as unknown as {
    execute: (
      input: { result: { complete: boolean } },
      options: { toolCallId: string; messages: never[] },
    ) => Promise<Record<string, unknown>>;
  };
  return executable.execute(
    { result: { complete } },
    { toolCallId: "response-test", messages: [] },
  );
}

describe("createResponseTool", () => {
  const schema = z.object({ complete: z.boolean() });

  it("captures accepted responses", async () => {
    const onResult = vi.fn();
    const responseTool = createResponseTool(schema, onResult);

    await expect(executeResponse(responseTool, false)).resolves.toMatchObject({
      success: true,
      responseAccepted: true,
    });
    expect(onResult).toHaveBeenCalledWith({ complete: false });
  });

  it("rejects incomplete responses without making them terminal", async () => {
    const onResult = vi.fn();
    const responseTool = createResponseTool(schema, onResult, (result) =>
      (result as { complete: boolean }).complete
        ? undefined
        : { message: "Keep working." },
    );

    await expect(executeResponse(responseTool, false)).resolves.toMatchObject({
      success: false,
      responseRejected: true,
      rejectionCount: 1,
    });
    expect(onResult).not.toHaveBeenCalled();

    await expect(executeResponse(responseTool, true)).resolves.toMatchObject({
      success: true,
      responseAccepted: true,
    });
    expect(onResult).toHaveBeenCalledWith({ complete: true });
  });
});
