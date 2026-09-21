import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { PersistentShell } from "../agents/offSecAgent/tools/persistentShell";
import type { ToolContext } from "../agents/offSecAgent/tools/types";
import type { SessionInfo } from "../session";
import { LocalBackends } from "../tools/backends";
import type { CommandBackend, CommandEvent } from "../tools/backends/types";
import { DEFAULT_WHITEBOX_EXCLUDED_DIRS } from "./profiles";
import { profileCodebase } from "./repoProfile";

const HERE = dirname(fileURLToPath(import.meta.url));

// Same purity check as `fileToolBackendPurity.test.ts`: no direct fs/process I/O.
describe("repoProfile.ts contains no direct fs/child_process I/O", () => {
  it("only calls the resolved CommandBackend", () => {
    const source = readFileSync(join(HERE, "repoProfile.ts"), "utf-8");
    for (const pattern of [
      /from ["']node:fs/,
      /from ["']node:child_process/,
      /\bspawn\(/,
      /\bexecFile\(/,
    ]) {
      expect(
        pattern.test(source),
        `repoProfile.ts matched forbidden pattern ${pattern}`,
      ).toBe(false);
    }
  });
});

async function tempDir(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

function mockSession(rootPath: string): SessionInfo {
  return {
    id: "ses_test",
    version: "1.0.0",
    targets: [],
    time: { created: Date.now(), updated: Date.now() },
    rootPath,
    logsPath: join(rootPath, "logs"),
    findingsPath: join(rootPath, "findings"),
    scratchpadPath: join(rootPath, "scratchpad"),
    pocsPath: join(rootPath, "pocs"),
    config: {},
  };
}

describe("profileCodebase via LocalBackends", () => {
  let shell: PersistentShell | undefined;

  afterEach(() => {
    shell?.dispose();
    shell = undefined;
  });

  it("matches today's host walk for a fixture tree: languages, manifests, entry hints, IaC/CI, git info, and pruning", async () => {
    const root = await tempDir("apex-repoprofile-fixture-");
    const outside = await tempDir("apex-repoprofile-outside-");

    await writeFile(
      join(root, "package.json"),
      JSON.stringify({
        scripts: {
          build: "tsc",
          test: "vitest",
          dev: "tsx watch src/index.ts",
        },
      }),
    );
    await writeFile(join(root, "package-lock.json"), "{}");
    await mkdir(join(root, "src"), { recursive: true });
    await writeFile(join(root, "src", "routes.ts"), "app.get('/x', handler);");
    await mkdir(join(root, "node_modules", "left-pad"), { recursive: true });
    await writeFile(
      join(root, "node_modules", "left-pad", "index.js"),
      "module.exports = () => {};",
    );
    await mkdir(join(root, ".github", "workflows"), { recursive: true });
    await writeFile(join(root, ".github", "workflows", "ci.yml"), "on: push\n");
    await mkdir(join(root, "infra"), { recursive: true });
    await writeFile(join(root, "infra", "main.tf"), 'resource "x" {}\n');
    await writeFile(join(outside, "secret.txt"), "outside the root");
    await symlink(outside, join(root, "escaped-link"));

    const gitEnv = {
      ...process.env,
      GIT_AUTHOR_NAME: "apex-test",
      GIT_AUTHOR_EMAIL: "apex-test@example.com",
      GIT_COMMITTER_NAME: "apex-test",
      GIT_COMMITTER_EMAIL: "apex-test@example.com",
    };
    execFileSync("git", ["init", "-q"], { cwd: root, env: gitEnv });
    execFileSync("git", ["add", "-A"], { cwd: root, env: gitEnv });
    execFileSync("git", ["commit", "-q", "-m", "init"], {
      cwd: root,
      env: gitEnv,
    });
    const expectedCommit = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: root,
      env: gitEnv,
    })
      .toString()
      .trim();

    shell = new PersistentShell({ cwd: root });
    const ctx = {
      agentCwd: root,
      session: mockSession(root),
      persistentShell: shell,
    } as ToolContext;
    const { command } = LocalBackends(ctx);

    const profile = await profileCodebase(root, command);

    expect(profile.rootPath).toBe(root);
    expect(profile.currentCommit).toBe(expectedCommit);
    // Only "typescript" — if node_modules/left-pad's .js leaked through the
    // prune, "javascript" would show up here too.
    expect(profile.languages).toEqual(["typescript"]);
    expect(profile.packageManagers).toEqual(["npm"]);
    expect([...profile.manifestFiles].sort()).toEqual([
      "package-lock.json",
      "package.json",
    ]);
    expect(profile.lockfiles).toEqual(["package-lock.json"]);
    expect(profile.buildCommands).toEqual(["npm run build"]);
    expect(profile.testCommands).toEqual(["npm run test"]);
    expect(profile.runCommands).toEqual(["npm run dev"]);
    expect(profile.entryPointHints).toEqual(["src/routes.ts"]);
    expect(profile.iacFiles).toEqual(["infra/main.tf"]);
    expect(profile.ciFiles).toEqual([".github/workflows/ci.yml"]);
    expect(profile.nativeCode).toBe(false);
    expect(profile.submodules).toEqual([]);
    expect(profile.excludedDirs).toEqual(DEFAULT_WHITEBOX_EXCLUDED_DIRS);
    expect(profile.toolAvailability).toHaveLength(22);
    for (const tool of profile.toolAvailability) {
      expect(typeof tool.name).toBe("string");
      expect(typeof tool.available).toBe("boolean");
      if (tool.available) expect(typeof tool.path).toBe("string");
    }

    // The symlinked escape hatch is walked into by neither `-type d` nor
    // `-type f`, matching the old Dirent-based skip.
    const serialized = JSON.stringify(profile);
    expect(serialized).not.toContain("escaped-link");
    expect(serialized).not.toContain("secret.txt");
  });
});

describe("profileCodebase via a synthetic command backend", () => {
  it("never touches the host filesystem — profiles purely from the backend's responses", async () => {
    const calls: string[] = [];
    const packageJson = JSON.stringify({
      scripts: { build: "tsc", test: "vitest" },
      packageManager: "bun@1.2.3",
    });
    const files = ["src/handler.py", "requirements.txt", "Dockerfile"].join(
      "\n",
    );

    function respond(cmd: string): { stdout: string; exitCode: number } {
      if (cmd.includes("'-d'")) return { stdout: "", exitCode: 0 };
      if (cmd.includes("find .")) return { stdout: files, exitCode: 0 };
      if (cmd.includes("package.json"))
        return { stdout: packageJson, exitCode: 0 };
      if (cmd.includes("rev-parse"))
        return { stdout: "deadbeefcafe\n", exitCode: 0 };
      if (cmd.includes("submodule")) return { stdout: "", exitCode: 0 };
      if (cmd.includes("'which' 'semgrep'"))
        return { stdout: "/usr/bin/semgrep\n", exitCode: 0 };
      if (cmd.includes("'which'")) return { stdout: "", exitCode: 1 };
      return { stdout: "", exitCode: 1 };
    }

    const spyCommand: CommandBackend = {
      async *run(cmd: string): AsyncIterable<CommandEvent> {
        calls.push(cmd);
        const { stdout, exitCode } = respond(cmd);
        yield { type: "start" };
        if (stdout) yield { type: "stdout", seq: 0, bytes: stdout };
        yield { type: "end", exitCode, timedOut: false };
      },
    };

    const root = "/apex-nonexistent-profile-root-xyz";
    const profile = await profileCodebase(root, spyCommand);

    expect(profile.rootPath).toBe(root);
    expect(profile.currentCommit).toBe("deadbeefcafe");
    expect(profile.languages).toEqual(["python"]);
    expect(profile.packageManagers).toEqual(["pip"]);
    expect(profile.manifestFiles).toEqual(["requirements.txt", "Dockerfile"]);
    expect(profile.lockfiles).toEqual([]);
    expect(profile.buildCommands).toEqual(["bun run build"]);
    expect(profile.testCommands).toEqual(["bun run test"]);
    expect(profile.runCommands).toEqual([]);
    expect(profile.entryPointHints).toEqual(["src/handler.py"]);
    expect(profile.nativeCode).toBe(false);
    expect(profile.submodules).toEqual([]);

    const semgrep = profile.toolAvailability.find((t) => t.name === "semgrep");
    expect(semgrep).toEqual({
      name: "semgrep",
      available: true,
      path: "/usr/bin/semgrep",
    });
    expect(
      profile.toolAvailability.filter((t) => t.name !== "semgrep"),
    ).toSatisfy((tools: typeof profile.toolAvailability) =>
      tools.every((t) => t.available === false),
    );

    // Every read went through the backend — none of it hit a real path.
    expect(calls.some((c) => c.includes("find ."))).toBe(true);
    expect(calls.some((c) => c.includes("package.json"))).toBe(true);
    expect(calls.some((c) => c.includes("rev-parse"))).toBe(true);
    expect(calls.some((c) => c.includes("submodule"))).toBe(true);
    expect(calls.filter((c) => c.includes("'which'"))).toHaveLength(22);
  });
});
