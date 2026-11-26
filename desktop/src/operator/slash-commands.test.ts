import { describe, expect, it } from "vitest";
import { commandRange, slashEntries } from "./slash-commands";

describe("composer slash catalog", () => {
  const skills = [
    { slug: "recon", name: "Recon", description: "Map the application" },
    { slug: "goal", name: "Conflicting skill", description: "override" },
  ];
  it("lists goals and discovered skills while reserving built-in names", () => {
    const entries = slashEntries("/", skills);
    expect(entries.find((entry) => entry.slug === "goal")?.kind).toBe(
      "command",
    );
    expect(entries.filter((entry) => entry.slug === "goal")).toHaveLength(1);
    expect(entries.find((entry) => entry.slug === "recon")?.kind).toBe("skill");
  });
  it("filters by command or description and leaves arguments alone", () => {
    expect(slashEntries("/rec", skills)[0].slug).toBe("recon");
    expect(slashEntries("/GOA", skills).map((entry) => entry.slug)).toEqual([
      "goal",
    ]);
    expect(
      slashEntries("/application", skills).map((entry) => entry.slug),
    ).toEqual(["recon"]);
    expect(slashEntries("/goal inspect", skills)).toEqual([]);
    expect(slashEntries("Review /goal", skills)).toEqual([]);
    expect(slashEntries("/missing", skills)).toEqual([]);
  });
});

describe("command highlighting", () => {
  const skills = [{ slug: "recon", name: "Recon", description: "Inspect" }];
  it.each([
    "/goal",
    "/goal inspect",
    "/GOAL inspect",
    "/model",
    "/tm example.test",
    "/recon",
  ])("highlights the recognized command in %s", (text) => {
    expect(commandRange(text, skills)).toEqual({
      start: 0,
      end: text.split(" ")[0].length,
    });
  });
  it.each([
    "Discuss /goal",
    "This is /recon",
    "/go",
    "/goalish",
    "/unknown",
    "`/goal`",
    "https://example.test/goal",
  ])("leaves plain text unchanged: %s", (text) => {
    expect(commandRange(text, skills)).toBeUndefined();
  });
  it("matches submission's leading whitespace handling without coloring whitespace or arguments", () => {
    expect(commandRange("  /goal inspect /recon", skills)).toEqual({
      start: 2,
      end: 7,
    });
  });
});
