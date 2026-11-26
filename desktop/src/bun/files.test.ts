import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { sessions } from "../../../src/core/session";
import { createFileRequests } from "./files";

vi.mock("../../../src/core/session", () => ({ sessions: { get: vi.fn() } }));

describe("opening message files", () => {
  let root: string;
  const openPath = vi.fn((_path: string) => true);
  const requireAcceptance = vi.fn();
  let requests: ReturnType<typeof createFileRequests>;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "apex-file-link-"));
    openPath.mockReset().mockReturnValue(true);
    requireAcceptance.mockReset();
    vi.mocked(sessions.get).mockResolvedValue({ rootPath: root } as Awaited<
      ReturnType<typeof sessions.get>
    >);
    requests = createFileRequests({
      cwd: () => root,
      openPath,
      requireAcceptance,
    });
  });
  afterEach(async () => {
    await rm(root, { force: true, recursive: true });
  });

  it("opens the exact local file with the system handler", async () => {
    const path = join(root, "Final report%20.csv");
    await writeFile(path, "test");
    await requests.openLocalFile({ path });
    expect(requireAcceptance).toHaveBeenCalledOnce();
    expect(openPath).toHaveBeenCalledExactlyOnceWith(path);
  });

  it("resolves relative deliverables from their session, then the agent workspace", async () => {
    const cwd = join(root, "project");
    await mkdir(cwd);
    vi.mocked(sessions.get).mockResolvedValue({
      rootPath: root,
      config: { agentCwd: cwd },
    } as Awaited<ReturnType<typeof sessions.get>>);
    await writeFile(join(root, "findings.md"), "session report");
    await writeFile(join(cwd, "source.ts"), "source");
    await requests.openLocalFile({
      path: "findings.md",
      sessionId: "ses_test",
    });
    await requests.openLocalFile({
      path: "source.ts:12",
      sessionId: "ses_test",
    });
    expect(openPath.mock.calls.map(([path]) => path)).toEqual([
      join(root, "findings.md"),
      join(cwd, "source.ts"),
    ]);
  });

  it("reports missing files, directories and system-open failures", async () => {
    await expect(
      requests.openLocalFile({ path: join(root, "missing.csv") }),
    ).rejects.toThrow("File not found");
    await mkdir(join(root, "folder.csv"));
    await expect(
      requests.openLocalFile({ path: join(root, "folder.csv") }),
    ).rejects.toThrow("File not found");
    expect(openPath).not.toHaveBeenCalled();
    await writeFile(join(root, "report.csv"), "test");
    openPath.mockReturnValue(false);
    await expect(
      requests.openLocalFile({ path: join(root, "report.csv") }),
    ).rejects.toThrow("Could not open report.csv");
  });

  it.each([
    "https://example.test/report.csv",
    "javascript:alert(1)",
    "//remote/report.csv",
  ])("rejects nonlocal destinations: %s", async (path) => {
    await expect(requests.openLocalFile({ path })).rejects.toThrow(
      "not a local file path",
    );
    expect(openPath).not.toHaveBeenCalled();
  });
});
