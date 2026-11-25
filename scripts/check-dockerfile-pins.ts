#!/usr/bin/env bun
/**
 * Fails when a Dockerfile builds from something that can change under it.
 *
 * The rules are structural, so the check never has to interpret shell:
 * images are literal and digest-pinned, a URL appears only in an
 * `ADD --checksum` inside a `FROM scratch` download stage, and that stage is
 * used only through `RUN --mount`. The legacy builder ignores `--checksum`
 * but cannot run `RUN --mount`, so it fails instead of skipping the check.
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
const CHECKSUM = /(?:^|\s)--checksum=sha256:[0-9a-f]{64}(?:\s|$)/;
const URL = /:\/\/|\bgit@/;
const DOCKERFILE = /(^|\/)(Dockerfile(\.[^/]+)?|[^/]+\.Dockerfile)$/;
// A command word, not part of a path such as /usr/local/bin/bunx.
const AUTO_INSTALL = /(?<![\w/.-])(npx|bunx)\b(?!\s+--no-install\b)/g;
const NPM_INSTALL =
  /\b(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+(?:add|install))\b/;
const GLOBAL_INSTALL =
  /\bbun\s+(?:install|add|i)\s+(?:-\S+\s+)*?(?:-g|--global)\s+([^;&|\n]*)/g;
const EXACT_PACKAGE =
  /^(?:@[^/@\s$]+\/)?[^/@\s$]+@\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

/**
 * Joins continuation lines and drops comment lines, keeping each start line.
 * Heredoc bodies stay part of their instruction, so a URL in one counts.
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
      while (++i < lines.length && (lines[i] ?? "").trim() !== doc[2])
        buf += `\n${lines[i] ?? ""}`;
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

/** An exec-form `RUN ["cmd", "arg"]` as space-separated words; shell form as is. */
function execFormAsWords(args: string): string {
  const exec = /^((?:--\S+\s+)*)(\[.*\])\s*$/s.exec(args);
  if (!exec) return args;
  try {
    const words: unknown = JSON.parse(exec[2] ?? "");
    if (Array.isArray(words)) return `${exec[1] ?? ""}${words.join(" ")}`;
  } catch {
    // Not a JSON array, so Docker runs it with a shell as written.
  }
  return args;
}

export function checkDockerfile(path: string, text: string): Violation[] {
  const violations: Violation[] = [];
  const report = (line: number, problem: string, fix: string) =>
    violations.push({ path, line, problem, fix });
  const stages = new Set<string>();
  const downloadStages = new Set<string>();
  // A `FROM scratch AS <name>` stage still being read; it is a download stage
  // when its first instruction is an `ADD` of a URL.
  let downloading: string | undefined;

  const checkImage = (line: number, image: string, what: string) => {
    const name = image.toLowerCase();
    if (image.includes("$"))
      report(
        line,
        `${what} \`${image}\` is not a literal`,
        "write the image or stage name out in full",
      );
    else if (name !== "scratch" && !stages.has(name) && !DIGEST.test(image))
      report(
        line,
        `${what} \`${image}\` has no digest`,
        "pin it as `name:tag@sha256:<digest>`",
      );
  };
  const noDownloadStage = (line: number, name: string, what: string) => {
    if (downloadStages.has(name.toLowerCase()))
      report(
        line,
        `download stage \`${name}\` is used through ${what}`,
        "use its files only through `RUN --mount=type=bind,from=<stage>`, which the legacy builder cannot skip",
      );
  };

  for (const { line, keyword, args } of parseDockerfile(text)) {
    if (keyword === "FROM") {
      const tokens = args.split(/\s+/).filter((t) => !t.startsWith("--"));
      const [image = "", as, name] = tokens;
      checkImage(line, image, "base image");
      noDownloadStage(line, image, "`FROM`");
      downloading =
        image === "scratch" && as?.toLowerCase() === "as" && name
          ? name.toLowerCase()
          : undefined;
      if (as?.toLowerCase() === "as" && name) stages.add(name.toLowerCase());
      continue;
    }
    if (keyword === "ADD" && URL.test(args)) {
      if (!CHECKSUM.test(args))
        report(
          line,
          "`ADD` of a URL without a literal `--checksum=sha256:<hash>`",
          "add `--checksum=sha256:<hash>` from the release's published checksums",
        );
      if (downloading) downloadStages.add(downloading);
      else
        report(
          line,
          "`ADD` of a URL outside a download stage",
          "move it into a `FROM scratch AS <name>` stage that only holds such `ADD`s",
        );
      continue;
    }
    if (downloading && downloadStages.has(downloading))
      report(
        line,
        `download stage \`${downloading}\` runs \`${keyword}\``,
        "keep download stages to `ADD --checksum` lines only",
      );
    downloading = undefined;
    if (URL.test(args))
      report(
        line,
        `a URL in \`${keyword}\``,
        "download it with `ADD --checksum` in a download stage; a URL may appear nowhere else",
      );
    if (keyword === "COPY") {
      const from = /(?:^|\s)--from=(\S+)/.exec(args)?.[1];
      if (from && !/^\d+$/.test(from)) {
        checkImage(line, from, "COPY --from image");
        noDownloadStage(line, from, "`COPY --from`");
      }
      continue;
    }
    if (keyword !== "RUN") continue;
    for (const mount of args.matchAll(/--mount=\S*\bfrom=([^,\s]+)/g)) {
      const from = mount[1] ?? "";
      if (!/^\d+$/.test(from)) checkImage(line, from, "RUN --mount image");
    }
    const command = execFormAsWords(args);
    for (const call of command.matchAll(AUTO_INSTALL))
      report(
        line,
        `\`${call[1]}\` without \`--no-install\` can download a package`,
        `install it from a lockfile first and run \`${call[1]} --no-install\``,
      );
    if (NPM_INSTALL.test(command))
      report(
        line,
        "a package install with no lockfile",
        "commit a lockfile and install with `npm ci`",
      );
    for (const global of command.matchAll(GLOBAL_INSTALL)) {
      const pkgs = (global[1] ?? "")
        .split(/\s+/)
        .filter(Boolean)
        .map((p) => p.replace(/^(["'])(.*)\1$/, "$2"));
      for (const pkg of pkgs.length ? pkgs : [""])
        if (!EXACT_PACKAGE.test(pkg))
          report(
            line,
            `global install of \`${pkg || "(nothing named)"}\` without a literal exact version`,
            "name it as `<package>@<x.y.z>`",
          );
    }
  }
  if (downloading && downloadStages.has(downloading))
    report(
      text.split("\n").length,
      `download stage \`${downloading}\` is the last stage`,
      "add the stage that uses it through `RUN --mount`",
    );
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
