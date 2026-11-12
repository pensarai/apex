import { afterEach, describe, expect, it, vi } from "vitest";

const storage = vi.hoisted(() => ({
  createDir: vi.fn().mockResolvedValue(undefined),
  writeRaw: vi.fn().mockResolvedValue(undefined),
  write: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("../storage", () => storage);
vi.mock("../config", () => ({
  config: {
    get: vi.fn().mockResolvedValue({
      defaultHeaders: { Authorization: "ambient-header" },
    }),
  },
}));

const { create, SessionInfoObject } = await import("./index");

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();
});

describe("explicit session configuration", () => {
  it("preserves v2 and its finding policy in the session snapshot used for resume", async () => {
    const session = await create({
      name: "adaptive operator",
      targets: [],
      config: {
        mode: "operator",
        operatorSettings: {
          initialMode: "auto",
          requireApproval: false,
          enableSuggestions: true,
          defaultV2Mode: true,
          findingPolicy: "external",
        },
      },
    });
    const restored = SessionInfoObject.parse(
      JSON.parse(JSON.stringify(session)),
    );
    expect(restored.config?.operatorSettings).toMatchObject({
      defaultV2Mode: true,
      findingPolicy: "external",
    });
    expect(storage.write).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        config: expect.objectContaining({
          operatorSettings: restored.config?.operatorSettings,
        }),
      }),
    );
  });

  it("does not persist ambient SMTP or headers for an admitted configuration", async () => {
    vi.stubEnv("RESEND_API_KEY", "ambient-smtp-secret");
    const session = await create({
      name: "recorded run",
      targets: ["http://127.0.0.1"],
      inheritEnvironmentConfig: false,
    });

    expect(session.config?.smtpConfig).toBeUndefined();
    expect(session.config?.headers).toEqual({});
    expect(JSON.stringify(storage.write.mock.calls)).not.toContain("ambient-");
  });

  it("keeps existing inheritance when callers do not opt out", async () => {
    vi.stubEnv("RESEND_API_KEY", "ambient-smtp-secret");
    const session = await create({
      name: "legacy run",
      targets: ["http://127.0.0.1"],
    });

    expect(session.config?.smtpConfig?.password).toBe("ambient-smtp-secret");
    expect(session.config?.headers).toEqual({
      Authorization: "ambient-header",
    });
  });
});
