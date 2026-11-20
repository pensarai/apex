import { describe, expect, it } from "vitest";
import { buildThreatModelPrompt } from "./threatModelGenerator";

describe("buildThreatModelPrompt", () => {
  const prompt = buildThreatModelPrompt({
    appName: "Tempo",
    routePath: "/agent/run",
    description: "Runs the Tempo agent",
  });

  it("models an agent surface as agent red teaming, not the web OWASP Top 10", () => {
    expect(prompt).toContain("#### Agent surfaces");
    expect(prompt).toContain("it is an **agent surface**");
    expect(prompt).toContain("does not apply");
    expect(prompt).toContain("**Goal hijack**");
    expect(prompt).toContain("**Tool misuse / confused deputy**");
    expect(prompt).toContain("**Memory poisoning**");
    expect(prompt).toContain('Do not emit "test for SQL injection"');
    expect(prompt).toContain("A thin proxy counts");
    expect(prompt).toContain("Reading the proxy is not the analysis");
    expect(prompt).toContain("Fewer than 10 is correct");
    expect(prompt).toContain(
      "Skip Step 1b on an agent surface unless the agent renders or executes that framework surface.",
    );
  });
});
