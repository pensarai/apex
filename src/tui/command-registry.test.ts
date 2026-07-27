import { describe, expect, it, vi } from "vitest";
import { type AppCommandContext, commands } from "./command-registry";

describe("resume command", () => {
  it("opens the existing session selector", async () => {
    const openSessionsDialog = vi.fn();
    const resume = commands.find((command) => command.name === "resume");
    if (!resume) throw new Error("Resume command is not registered");

    const context: AppCommandContext = {
      route: { type: "operator" },
      navigate: vi.fn(),
      openSessionsDialog,
    };

    await resume.handler([], context);

    expect(resume.aliases).toEqual(["sessions", "s"]);
    expect(openSessionsDialog).toHaveBeenCalledOnce();
  });
});
