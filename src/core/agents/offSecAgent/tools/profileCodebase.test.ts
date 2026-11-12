import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { profileCodebase } from "./profileCodebase";
import type { ToolContext } from "./types";

it("returns repository facts in v2 without attaching a methodology or follow-on workflow", async () => {
  const root = await mkdtemp(join(tmpdir(), "apex-profile-inventory-"));
  const repository = join(root, "repository");
  try {
    await mkdir(repository);
    await writeFile(
      join(repository, "Gemfile"),
      'source "https://rubygems.org"\ngem "rails"\n',
    );
    await writeFile(join(repository, "server.rb"), "class Server; end\n");
    const ctx = {
      mode: "default-v2",
      agentCwd: repository,
      session: {
        id: "profile-inventory",
        rootPath: root,
        logsPath: join(root, "logs"),
        scratchpadPath: join(root, "scratchpad"),
        config: {},
      },
    } as ToolContext;
    const options = { context: {}, toolCallId: "profile", messages: [] };
    const tool = profileCodebase(ctx);
    expect(tool.description).not.toContain("Use this early");
    const result = await tool.execute?.(
      { path: repository, toolCallDescription: "Inspect repository structure" },
      options,
    );
    assert(result && "data" in result && result.success);
    expect(result.data.languages).toContain("ruby");
    expect(result).not.toHaveProperty("nextActions");
    expect(result.data).not.toHaveProperty("recommendedPasses");
    expect(result.data).not.toHaveProperty("relevantCatalog");
    const artifact = JSON.parse(
      await readFile(join(root, result.artifactPaths[0]), "utf8"),
    );
    expect(artifact.profile.languages).toContain("ruby");
    expect(artifact).not.toHaveProperty("catalog");

    const legacy = await profileCodebase({ ...ctx, mode: "default" }).execute?.(
      { path: repository, toolCallDescription: "Profile legacy assessment" },
      options,
    );
    expect(legacy).toHaveProperty("data.recommendedPasses");
    expect(legacy).toHaveProperty("nextActions");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
