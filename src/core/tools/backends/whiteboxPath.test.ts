import { mkdir, mkdtemp, realpath, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import { resolveWhiteboxPath } from "./whitebox";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

it("allows explicit v2 repositories outside the launch directory while enforcing configured scopes", async () => {
  const root = await mkdtemp(join(tmpdir(), "apex-whitebox-path-"));
  roots.push(root);
  const launch = join(root, "apex");
  const repository = join(root, "postal");
  await Promise.all([mkdir(launch), mkdir(repository)]);
  const ctx = {
    mode: "default-v2",
    agentCwd: launch,
    session: { config: {} },
  } as ToolContext;
  expect(await resolveWhiteboxPath(ctx, repository)).toBe(
    await realpath(repository),
  );
  expect(await resolveWhiteboxPath(ctx)).toBe(await realpath(launch));
  await expect(
    resolveWhiteboxPath({ ...ctx, mode: undefined }, repository),
  ).rejects.toThrow("escapes codebase root");
  const scoped = {
    ...ctx,
    session: { config: { codebasePath: launch } },
  } as ToolContext;
  await expect(resolveWhiteboxPath(scoped, repository)).rejects.toThrow(
    "escapes file workspace",
  );
  await expect(
    resolveWhiteboxPath({ ...ctx, fileWorkspaceRoot: launch }, repository),
  ).rejects.toThrow("escapes file workspace");
  await symlink(repository, join(launch, "escape"));
  await expect(resolveWhiteboxPath(scoped, "escape")).rejects.toThrow(
    "escapes file workspace",
  );
});
