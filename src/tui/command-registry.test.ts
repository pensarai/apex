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

describe("recorded runs command", () => {
  it("opens an existing recorded run without navigating or taking over legacy resume", async () => {
    const openRecordedRunsDialog = vi.fn();
    const context = createContext({ openRecordedRunsDialog });
    await getCommand("runs").handler(
      ["run_example", "--store", "custom.sqlite"],
      context,
    );
    expect(openRecordedRunsDialog).toHaveBeenCalledWith({
      runId: "run_example",
      databasePath: "custom.sqlite",
    });
    expect(context.navigate).not.toHaveBeenCalled();
    expect(getCommand("resume").handler).not.toBe(getCommand("runs").handler);
  });

  it("passes an explicit spec path to detached start", async () => {
    const openRecordedRunsDialog = vi.fn();
    await getCommand("runs").handler(
      ["--spec", "run.json"],
      createContext({ openRecordedRunsDialog }),
    );
    expect(openRecordedRunsDialog).toHaveBeenCalledWith({
      specPath: "run.json",
    });
  });

  it.each([
    ["one", "two"],
    ["one", "--spec", "run.json"],
    ["--unknown"],
  ])("rejects ambiguous or unsupported arguments: %j", async (...args) => {
    const openRecordedRunsDialog = vi.fn();
    const toast = vi.fn();
    await getCommand("runs").handler(
      args,
      createContext({ openRecordedRunsDialog, toast }),
    );
    expect(toast).toHaveBeenCalledWith(expect.any(String), "error");
    expect(openRecordedRunsDialog).not.toHaveBeenCalled();
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
