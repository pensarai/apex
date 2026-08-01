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

  it("launches /whitebox-recon as a new standard operator workflow", async () => {
    const navigate = vi.fn();

    await getCommand("whitebox-recon").handler(
      ["--cwd", "/tmp/example", "--workers", "3"],
      createContext({ navigate }),
    );

    expect(navigate).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "operator",
        initialConfig: expect.objectContaining({
          strikeMode: false,
          sandbox: false,
        }),
        initialSkill: {
          slug: "whitebox-recon",
          args: { cwd: "/tmp/example", workers: "3" },
        },
      }),
    );
  });
});
