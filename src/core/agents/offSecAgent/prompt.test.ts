import { describe, expect, it } from "vitest";
import { buildBaseSystemPrompt } from "./prompt";

describe("buildBaseSystemPrompt workspace management", () => {
  const prompt = buildBaseSystemPrompt();

  it("routes explicit authenticated workspace mutations to in-process tools", () => {
    expect(prompt).toContain("**create_workspace_app**");
    expect(prompt).toContain("**create_workspace_endpoint**");
    expect(prompt).toContain(
      "do not invoke a separate `pensar apps` binary through the shell",
    );
    expect(prompt).toContain(
      "An explicit request for a specific workspace mutation is confirmation",
    );
    expect(prompt).toContain(
      "do not ask for a second conversational confirmation",
    );
    expect(prompt).toContain(
      "run `/login` in Apex or the local checkout's `bun src/cli.ts login`",
    );
  });

  it("keeps session discovery tools separate from workspace mutations", () => {
    expect(prompt).toContain(
      "This does not update the authenticated Pensar workspace",
    );
    expect(prompt).toContain(
      "Do not substitute `document_app`, `document_endpoint`, shell-based `pensar apps` commands, attack-surface discovery, or threat-model generation",
    );
  });

  it("treats an imported threat model as workspace source data", () => {
    expect(prompt).toContain(
      "treat it as source data rather than a request to generate another threat model",
    );
  });
});
