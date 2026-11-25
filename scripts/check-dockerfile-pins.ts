#!/usr/bin/env bun
/**
 * Fails when a Dockerfile builds from something that can change under it: a
 * base image without a digest, a download without a checksum, a script piped
 * into a shell, or a package tool that fetches whatever version is current.
 */
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { GATED_LOCKFILES } from "./osv-gate";

export interface Violation {
  path: string;
  line: number;
  problem: string;
  fix: string;
}

interface Instruction {
  line: number;
  keyword: string;
  args: string;
}

const DIGEST = /@sha256:[0-9a-f]{64}$/;
const DOCKERFILE = /(^|\/)(Dockerfile(\.[^/]+)?|[^/]+\.Dockerfile)$/;
// A command at the start of a shell statement, not a package name in a list.
const COMMAND_START = String.raw`(?:^|&&|\|\||[;|(]|\bthen\b|\bdo\b|\belse\b)\s*(?:sudo\s+)?`;
const DOWNLOAD = new RegExp(`${COMMAND_START}(curl|wget)\\b`);
const PIPE_TO_SHELL =
  /\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:\/usr)?(?:\/bin\/)?(?:ba|da|z|k)?sh\b/;
const SHELL_FROM_DOWNLOAD =
  /\b(?:ba|da|z|k)?sh\b[^|;&]*(?:<\(|\$\()\s*(?:curl|wget)\b/;
const CHECKSUM = /\bsha(?:256|512)sum\b[^;&|]*(?:\s-c\b|\s--check\b)/;
const AUTO_INSTALL = new RegExp(`${COMMAND_START}(npx|bunx)\\b([^;&|]*)`, "g");
const NPM_INSTALL = new RegExp(
  `${COMMAND_START}(?:npm\\s+(?:install|i|add)|yarn\\s+add|pnpm\\s+(?:add|install))\\b`,
);
const GLOBAL_INSTALL = new RegExp(
  `${COMMAND_START}bun\\s+(?:install|add|i)\\s+(?:\\S+\\s+)*?(?:-g|--global)\\b([^;&|]*)`,
);
const EXACT_PACKAGE =
  /^(?:@[^/@\s]+\/)?[^/@\s]+@\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

/** Joins continuation lines and drops comments, keeping each start line. */
export function parseDockerfile(text: string): Instruction[] {
  const out: Instruction[] = [];
  const lines = text.split("\n");
  let start = 0;
  let buf = "";
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    if (!buf && !raw.trim()) continue;
    if (raw.trim().startsWith("#")) continue;
    if (!buf) start = i + 1;
    const continued = /\\\s*$/.test(raw);
    buf += `${continued ? raw.replace(/\\\s*$/, "") : raw} `;
    if (continued) continue;
    const match = /^\s*(\w+)\s*(.*)$/s.exec(buf.trim());
    if (match)
      out.push({
        line: start,
        keyword: (match[1] ?? "").toUpperCase(),
        args: (match[2] ?? "").trim(),
      });
    buf = "";
  }
  return out;
}

/** Replaces `$NAME` and `${NAME}` with the ARG defaults declared so far. */
function substitute(text: string, args: Map<string, string>): string {
  return text.replace(
    /\$\{(\w+)\}|\$(\w+)/g,
    (whole, braced: string | undefined, bare: string | undefined) =>
      args.get(braced ?? bare ?? "") ?? whole,
  );
}

function withoutFlags(args: string): string[] {
  return args.split(/\s+/).filter((t) => t && !t.startsWith("--"));
}

export function checkDockerfile(path: string, text: string): Violation[] {
  const violations: Violation[] = [];
  const stages = new Set<string>();
  const args = new Map<string, string>();
  const report = (line: number, problem: string, fix: string) =>
    violations.push({ path, line, problem, fix });
  const checkImage = (line: number, image: string, what: string) => {
    if (image === "scratch" || stages.has(image.toLowerCase())) return;
    if (!DIGEST.test(image))
      report(
        line,
        `${what} \`${image}\` has no digest`,
        "pin it as `name:tag@sha256:<digest>`",
      );
  };

  for (const { line, keyword, args: rawArgs } of parseDockerfile(text)) {
    if (keyword === "ARG") {
      const decl = /^(\w+)=(\S*)/.exec(rawArgs);
      if (decl)
        args.set(decl[1] ?? "", decl[2]?.replace(/^"(.*)"$/, "$1") ?? "");
      continue;
    }
    const body = substitute(rawArgs, args);
    if (keyword === "FROM") {
      const [image = "", as, name] = withoutFlags(body);
      checkImage(line, image, "base image");
      if (as?.toLowerCase() === "as" && name) stages.add(name.toLowerCase());
      continue;
    }
    if (keyword === "COPY" || keyword === "ADD") {
      const from = /--from=(\S+)/.exec(body)?.[1];
      if (from && !/^\d+$/.test(from))
        checkImage(line, from, "COPY --from image");
    }
    if (keyword === "ADD") {
      const remote = withoutFlags(body).some((t) =>
        /^(https?|git):\/\/|^git@/.test(t),
      );
      if (remote && !/--checksum=sha256:[0-9a-f]{64}/.test(body))
        report(
          line,
          "`ADD` of a URL without `--checksum`",
          "download in a `RUN` step and check it with `sha256sum -c`",
        );
      continue;
    }
    if (keyword !== "RUN") continue;

    for (const mount of body.matchAll(/--mount=\S*\bfrom=([^,\s]+)/g)) {
      const from = mount[1] ?? "";
      if (!/^\d+$/.test(from)) checkImage(line, from, "RUN --mount image");
    }
    if (PIPE_TO_SHELL.test(body) || SHELL_FROM_DOWNLOAD.test(body))
      report(
        line,
        "a script is piped into a shell",
        "download a pinned release and check it with `sha256sum -c`",
      );
    else if (DOWNLOAD.test(body) && !CHECKSUM.test(body))
      report(
        line,
        "a `curl`/`wget` download has no checksum check in the same `RUN`",
        'add `echo "<sha256>  <file>" | sha256sum -c -` after it',
      );
    for (const call of body.matchAll(AUTO_INSTALL)) {
      if (!/(?:^|\s)--no-install\b/.test(call[2] ?? ""))
        report(
          line,
          `\`${call[1]}\` can download a package that is not installed`,
          `install it from a lockfile first and run \`${call[1]} --no-install\``,
        );
    }
    if (NPM_INSTALL.test(body))
      report(
        line,
        "a package install with no lockfile",
        "commit a lockfile and install with `npm ci`",
      );
    const global = GLOBAL_INSTALL.exec(body);
    if (global) {
      const pkgs = withoutFlags(global[1] ?? "")
        .filter((t) => !t.startsWith("-"))
        .map((t) => t.replace(/^(["'])(.*)\1$/, "$2"));
      for (const pkg of pkgs.length ? pkgs : [""])
        if (!EXACT_PACKAGE.test(pkg))
          report(
            line,
            `global install of \`${pkg || "(nothing named)"}\` without an exact version`,
            "name it as `<package>@<exact version>`",
          );
    }
  }
  return violations;
}

/** npm lockfiles the osv gate does not scan; images install from them. */
export function ungatedLockfiles(tracked: string[], gated: string[]): string[] {
  return tracked.filter(
    (p) => /(^|\/)package-lock\.json$/.test(p) && !gated.includes(p),
  );
}

// --- CLI (Bun-only below this line) -----------------------------------------

function trackedFiles(root: string): string[] {
  const res = spawnSync("git", ["ls-files", "-z"], {
    cwd: root,
    encoding: "utf8",
  });
  if (res.status !== 0) throw new Error(`git ls-files failed: ${res.stderr}`);
  return res.stdout.split("\0").filter(Boolean).sort();
}

async function main() {
  const root = resolve(import.meta.dir, "..");
  const tracked = trackedFiles(root);
  const files = tracked.filter((p) => DOCKERFILE.test(p));
  const violations: Violation[] = [];
  for (const path of ungatedLockfiles(tracked, GATED_LOCKFILES))
    violations.push({
      path,
      line: 1,
      problem: "this lockfile is not scanned by the vulnerable-dependency gate",
      fix: "add it to `GATED_LOCKFILES` in scripts/osv-gate.ts",
    });
  for (const path of files)
    violations.push(
      ...checkDockerfile(path, await Bun.file(resolve(root, path)).text()),
    );
  if (!violations.length) {
    console.log(
      `check-dockerfile-pins: OK — ${files.length} Dockerfiles pin their images and downloads.`,
    );
    return;
  }
  for (const v of violations)
    console.log(
      `::error file=${v.path},line=${v.line}::${v.problem}; ${v.fix}.`,
    );
  console.error(
    `check-dockerfile-pins: ${violations.length} problems. See "Docker images" in AGENTS.md.`,
  );
  process.exit(1);
}

if (import.meta.main) await main();
