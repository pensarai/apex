import { describe, expect, it } from "vitest";
import { getContextWindow } from "./ai";

describe("getContextWindow", () => {
  it("compacts GLM below its 1M window", () => {
    expect(getContextWindow("z-ai/glm-5.3")).toBe(200_000);
    expect(getContextWindow("z-ai/glm-5.2")).toBe(200_000);
  });
});
