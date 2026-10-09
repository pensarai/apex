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

const { create } = await import("./index");

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();
});

describe("explicit session configuration", () => {
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
