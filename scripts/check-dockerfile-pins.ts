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
const COMMAND_START = String.raw`(?:^|\n|&&|\|\||[;|(]|\bthen\b|\bdo\b|\belse\b)\s*(?:sudo\s+)?`;
const DOWNLOAD = new RegExp(`${COMMAND_START}(curl|wget)\\b([^;&|\\n]*)`, "g");
const PIPE_TO_SHELL =
  /\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:\/usr)?(?:\/bin\/)?(?:ba|da|z|k)?sh\b/;
const SHELL_FROM_DOWNLOAD =
  /\b(?:ba|da|z|k)?sh\b[^|;&]*(?:<\(|\$\()\s*(?:curl|wget)\b/;
// `echo "<hash>  <file>" | sha256sum -c -`: the form that names the file it checks.
const CHECKED_FILE =
  /echo\s+(["']?)\S+\s+\*?([^\s"']+)\1\s*\|\s*sha(?:256|512)sum\s+(?:-c|--check)\b/g;
const AUTO_INSTALL = new RegExp(
  `${COMMAND_START}(npx|bunx)\\b([^;&|\\n]*)`,
  "g",
);
const NPM_INSTALL = new RegExp(
  `${COMMAND_START}(?:npm\\s+(?:install|i|add)|yarn\\s+add|pnpm\\s+(?:add|install))\\b`,
);
const GLOBAL_INSTALL = new RegExp(
  `${COMMAND_START}bun\\s+(?:install|add|i)\\s+(?:\\S+\\s+)*?(?:-g|--global)\\b([^;&|\\n]*)`,
);
const EXACT_PACKAGE =
  /^(?:@[^/@\s]+\/)?[^/@\s]+@\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

/**
 * Joins continuation lines, drops comments and appends heredoc bodies to their
 * instruction, keeping each start line.
 */
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
    for (const doc of buf.matchAll(/<<-?(["']?)(\w+)\1/g)) {
      const body: string[] = [];
      while (++i < lines.length && (lines[i] ?? "").trim() !== doc[2])
        body.push(lines[i] ?? "");
      buf += `\n${body.join("\n")}`;
    }
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

/** Leading `--flag` options, then the command; an exec-form JSON array is joined. */
function splitFlags(args: string): { flags: string; rest: string } {
  const m = /^((?:--\S+\s+)*)(.*)$/s.exec(args);
  const flags = m?.[1] ?? "";
  let rest = (m?.[2] ?? "").trim();
  if (rest.startsWith("[")) {
    try {
      const parsed: unknown = JSON.parse(rest);
      if (Array.isArray(parsed)) rest = parsed.map(String).join(" ");
    } catch {
      // Not valid JSON, so Docker runs it as a shell command too.
    }
  }
  return { flags, rest };
}

function unquote(token: string): string {
  return token.replace(/^(["'])(.*)\1$/, "$2");
}

/** The file a curl/wget call writes, or undefined when it streams or names none. */
function downloadTarget(tool: string, args: string): string | undefined {
  const m =
    tool === "curl"
      ? /(?:^|\s)(?:-[A-Za-z]*o|--output)(?:\s+|=)(\S+)/.exec(args)
      : /(?:^|\s)(?:-[A-Za-z]*O|--output-document)(?:\s+|=)?(\S+)/.exec(args);
  const target = m?.[1] ? unquote(m[1]) : undefined;
  return target === "-" ? undefined : target;
}

export function checkDockerfile(path: string, text: string): Violation[] {
  const violations: Violation[] = [];
  const stages = new Set<string>();
  // FROM sees only ARGs declared before the first FROM; a stage sees only the
  // ARGs it declares itself, defaulting to the global value.
  const globalArgs = new Map<string, string>();
  let stageArgs: Map<string, string> | undefined;
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
      for (const decl of rawArgs.matchAll(
        /(\w+)(?:=("[^"]*"|'[^']*'|\S*))?/g,
      )) {
        const name = decl[1] ?? "";
        const value =
          decl[2] !== undefined ? unquote(decl[2]) : globalArgs.get(name);
        if (value === undefined) continue;
        (stageArgs ?? globalArgs).set(name, value);
      }
      continue;
    }
    if (keyword === "FROM") {
      const [image = "", as, name] = withoutFlags(
        substitute(rawArgs, globalArgs),
      );
      checkImage(line, image, "base image");
      if (as?.toLowerCase() === "as" && name) stages.add(name.toLowerCase());
      stageArgs = new Map();
      continue;
    }
    const body = substitute(rawArgs, stageArgs ?? globalArgs);
    const { flags, rest } = splitFlags(body);
    if (keyword === "COPY" || keyword === "ADD") {
      const from = /--from=(\S+)/.exec(flags)?.[1];
      if (from && !/^\d+$/.test(from))
        checkImage(line, from, "COPY --from image");
    }
    if (keyword === "ADD") {
      const remote = rest
        .split(/\s+/)
        .some((t) => /^(https?|git):\/\/|^git@/.test(unquote(t)));
      if (remote && !/--checksum=sha256:[0-9a-f]{64}/.test(flags))
        report(
          line,
          "`ADD` of a URL without `--checksum`",
          "download in a `RUN` step and check it with `sha256sum -c`",
        );
      continue;
    }
    if (keyword !== "RUN") continue;

    for (const mount of flags.matchAll(/--mount=\S*\bfrom=([^,\s]+)/g)) {
      const from = mount[1] ?? "";
      if (!/^\d+$/.test(from)) checkImage(line, from, "RUN --mount image");
    }
    const command = rest;
    if (PIPE_TO_SHELL.test(command) || SHELL_FROM_DOWNLOAD.test(command)) {
      report(
        line,
        "a script is piped into a shell",
        "download a pinned release and check it with `sha256sum -c`",
      );
    } else {
      const checked = new Set(
        [...command.matchAll(CHECKED_FILE)].map((m) => m[2] ?? ""),
      );
      for (const call of command.matchAll(DOWNLOAD)) {
        const target = downloadTarget(call[1] ?? "", call[2] ?? "");
        if (target === undefined)
          report(
            line,
            `a \`${call[1]}\` download writes no named file, so no checksum can cover it`,
            'write it to a file with `-o`/`-O` and check it with `echo "<sha256>  <file>" | sha256sum -c -`',
          );
        else if (!checked.has(target))
          report(
            line,
            `\`${target}\` is downloaded without a \`sha256sum -c\` check of that file in the same \`RUN\``,
            `add \`echo "<sha256>  ${target}" | sha256sum -c -\` after it`,
          );
      }
    }
    for (const call of command.matchAll(AUTO_INSTALL)) {
      if (!/(?:^|\s)--no-install\b/.test(call[2] ?? ""))
        report(
          line,
          `\`${call[1]}\` can download a package that is not installed`,
          `install it from a lockfile first and run \`${call[1]} --no-install\``,
        );
    }
    if (NPM_INSTALL.test(command))
      report(
        line,
        "a package install with no lockfile",
        "commit a lockfile and install with `npm ci`",
      );
    const global = GLOBAL_INSTALL.exec(command);
    if (global) {
      const pkgs = withoutFlags(global[1] ?? "")
        .filter((t) => !t.startsWith("-"))
        .map(unquote);
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
