import { describe, expect, it, vi } from "vitest";

vi.mock("./theme", () => ({ getAllThemeNames: () => [] }));

import {
  type AppCommandContext,
  type CommandConfig,
  commands,
} from "./command-registry";

function getCommand(name: string): CommandConfig {
  const command = commands.find((candidate) => candidate.name === name);
  if (!command) throw new Error(`Missing /${name} command`);
  return command;
}

function createContext(
  overrides: Partial<AppCommandContext> = {},
): AppCommandContext {
  return {
    route: { type: "base", path: "home" },
    navigate: vi.fn(),
    ...overrides,
  };
}

describe("advanced settings command", () => {
  it("opens the Advanced Settings dialog", async () => {
    const openAdvancedDialog = vi.fn();

    await getCommand("advanced").handler(
      [],
      createContext({ openAdvancedDialog }),
    );

    expect(openAdvancedDialog).toHaveBeenCalledOnce();
  });
});

describe("exit command", () => {
  it("uses the graceful application exit path", async () => {
    const exitApplication = vi.fn(async () => {});

    await getCommand("exit").handler([], createContext({ exitApplication }));

    expect(exitApplication).toHaveBeenCalledOnce();
  });
});

describe("autonomous workflow Strike Mode overrides", () => {
  it("keeps direct /pentest launches in standard mode", async () => {
    const navigate = vi.fn();

    await getCommand("pentest").handler(
      ["--target", "https://example.com", "--strict"],
      createContext({ navigate }),
    );

    expect(navigate).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "operator",
        initialConfig: expect.objectContaining({ strikeMode: false }),
        initialSkill: expect.objectContaining({ slug: "pentest" }),
      }),
    );
  });

  it("keeps /threat-model launches in standard mode", async () => {
    const navigate = vi.fn();

    await getCommand("threat-model").handler([], createContext({ navigate }));

    expect(navigate).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "operator",
        initialConfig: expect.objectContaining({ strikeMode: false }),
        initialSkill: expect.objectContaining({ slug: "threat-model" }),
      }),
    );
  });
});
