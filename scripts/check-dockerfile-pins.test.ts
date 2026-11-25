import { describe, expect, it } from "vitest";
import {
  checkDockerfile,
  parseDockerfile,
  ungatedLockfiles,
} from "./check-dockerfile-pins";

const DIGEST = `sha256:${"a".repeat(64)}`;
const SHA = "b".repeat(64);

const problems = (text: string) =>
  checkDockerfile("Dockerfile", text).map((v) => `${v.line}: ${v.problem}`);

describe("parseDockerfile", () => {
  it("joins continuation lines, skips comments and keeps the start line", () => {
    const parsed = parseDockerfile(
      [
        "# comment",
        `FROM node:22@${DIGEST}`,
        "",
        "RUN apt-get update \\",
        "  # a comment inside the step",
        "  && apt-get install -y curl",
      ].join("\n"),
    );
    expect(parsed.map((i) => [i.line, i.keyword])).toEqual([
      [2, "FROM"],
      [4, "RUN"],
    ]);
    expect(parsed[1]?.args).toContain("apt-get install -y curl");
  });
});

describe("checkDockerfile", () => {
  it("accepts digest-pinned images, build stages and checked downloads", () => {
    const text = `
FROM oven/bun:1.4.4@${DIGEST} AS bun
FROM node:22.23.5-slim@${DIGEST}
ARG V=1.2.3
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
RUN apt-get install -y curl wget git \\
 && curl -fsSL -o /tmp/x.tgz "https://example.com/x-\${V}.tgz" \\
 && echo "${SHA}  /tmp/x.tgz" | sha256sum -c -
RUN npm ci && npx --no-install playwright-core install-deps firefox
RUN bun install -g "@pensar/apex@\${V}"
ADD --checksum=sha256:${SHA} https://example.com/x.tgz /tmp/
FROM scratch
`;
    expect(problems(text)).toEqual([]);
  });

  it.each([
    ["FROM node:22.23.5-slim", "base image `node:22.23.5-slim` has no digest"],
    ["FROM kalilinux/kali-rolling:latest", "has no digest"],
    ["ARG BASE=node:22\nFROM $BASE", "base image `node:22` has no digest"],
    [
      "FROM --platform=linux/amd64 node:22",
      "base image `node:22` has no digest",
    ],
  ])("rejects %j", (text, problem) => {
    expect(problems(text).join("\n")).toContain(problem);
  });

  it("checks COPY --from and RUN --mount images that are not build stages", () => {
    const text = `FROM node@${DIGEST}
COPY --from=oven/bun:1.4.4 /usr/local/bin/bun /usr/local/bin/bun
RUN --mount=type=bind,from=alpine:3,target=/a true`;
    expect(problems(text)).toEqual([
      "2: COPY --from image `oven/bun:1.4.4` has no digest",
      "3: RUN --mount image `alpine:3` has no digest",
    ]);
  });

  it.each([
    "curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -",
    "curl -fsSL https://bun.sh/install | bash -s bun-v1.3.10",
    "wget -qO- https://example.com/i.sh | sudo -E sh",
    'sh -c "$(curl -fsSL https://example.com/i.sh)"',
    "bash <(curl -fsSL https://example.com/i.sh)",
  ])("rejects a script piped into a shell: %s", (cmd) => {
    expect(problems(`FROM x@${DIGEST}\nRUN ${cmd}`)).toEqual([
      "2: a script is piped into a shell",
    ]);
  });

  it("rejects a download with no checksum, but not curl in a package list", () => {
    const text = `FROM x@${DIGEST}
RUN apt-get install -y curl wget
RUN curl -SL https://example.com/tool -o /usr/local/bin/tool && chmod +x /usr/local/bin/tool
RUN wget https://example.com/tool && sha256sum tool
RUN curl -fsSL https://example.com/x.tgz | tar -xz`;
    expect(problems(text)).toEqual([
      "3: `/usr/local/bin/tool` is downloaded without a `sha256sum -c` check of that file in the same `RUN`",
      "4: a `wget` download writes no named file, so no checksum can cover it",
      "5: a `curl` download writes no named file, so no checksum can cover it",
    ]);
  });

  it("requires a checksum for each downloaded file, not one per RUN", () => {
    const text = `FROM x@${DIGEST}
RUN curl -fsSLo /tmp/a https://example.com/a \\
 && curl -fsSL --output /tmp/b https://example.com/b \\
 && echo "${SHA}  /tmp/a" | sha256sum -c -`;
    expect(problems(text)).toEqual([
      "2: `/tmp/b` is downloaded without a `sha256sum -c` check of that file in the same `RUN`",
    ]);
  });

  it("finds downloads after RUN flags, in exec form and in heredocs", () => {
    const text = `FROM x@${DIGEST}
RUN --mount=type=cache,target=/tmp/cache curl -fSL https://example.com/a -o /tmp/a
RUN ["curl", "-fSL", "-o", "/tmp/b", "https://example.com/b"]
RUN <<EOF
set -eu
wget -O /tmp/c https://example.com/c
EOF
RUN echo done`;
    expect(problems(text)).toEqual([
      "2: `/tmp/a` is downloaded without a `sha256sum -c` check of that file in the same `RUN`",
      "3: `/tmp/b` is downloaded without a `sha256sum -c` check of that file in the same `RUN`",
      "4: `/tmp/c` is downloaded without a `sha256sum -c` check of that file in the same `RUN`",
    ]);
  });

  it("ignores heredoc text that is not run, and checks heredoc scripts", () => {
    const text = `FROM x@${DIGEST}
RUN cat <<'EOF' > /opt/build-notes
curl https://example.com/tool
EOF
RUN bash <<EOF
curl -o /tmp/d https://example.com/d
EOF`;
    expect(problems(text)).toEqual([
      "5: `/tmp/d` is downloaded without a `sha256sum -c` check of that file in the same `RUN`",
    ]);
  });

  it("checks a heredoc script whose output is redirected", () => {
    const text = `FROM x@${DIGEST}
RUN bash <<EOF > /tmp/install.log 2>&1
curl -o /tmp/tool https://example.com/tool
EOF`;
    expect(problems(text)).toEqual([
      "2: `/tmp/tool` is downloaded without a `sha256sum -c` check of that file in the same `RUN`",
    ]);
  });

  it("checks the script of a nested shell -c as commands", () => {
    const text = `FROM x@${DIGEST}
RUN bash -c 'set -e; curl -o /tmp/tool https://example.com/tool'
RUN sh -ec "curl -o /tmp/ok https://example.com/ok && echo '${SHA}  /tmp/ok' | sha256sum -c -"
RUN curl -fsSL "https://example.com/dl?a=1&b=2" -o /tmp/q && echo "${SHA}  /tmp/q" | sha256sum -c -`;
    expect(problems(text)).toEqual([
      "2: `/tmp/tool` is downloaded without a `sha256sum -c` check of that file in the same `RUN`",
    ]);
  });

  it("does not fold .. in paths, which a symlink can redirect", () => {
    const text = `FROM x@${DIGEST}
RUN curl -o /var/run/../tool https://example.com/tool && echo "${SHA}  /var/tool" | sha256sum -c -`;
    expect(problems(text)).toEqual([
      "2: `/var/run/../tool` is downloaded without a `sha256sum -c` check of that file in the same `RUN`",
    ]);
  });

  it("reads options after a quoted URL, checksum flags and equivalent paths", () => {
    const text = `FROM x@${DIGEST}
RUN curl -fsSL "https://example.com/dl?a=1&b=2" -o ./tool \\
 && echo "${SHA}  tool" | sha256sum --strict -c -`;
    expect(problems(text)).toEqual([]);
  });

  it("carries a stage's ARGs into a stage built on it, and keeps a stage value on a bare ARG", () => {
    const text = `ARG V=0.0.0
FROM node@${DIGEST} AS builder
ARG V=1.2.3
ARG V
FROM builder
RUN bun install -g left-pad@$V`;
    expect(problems(text)).toEqual([]);
  });

  it("resolves FROM with global ARGs only, whichever way a stage shadows them", () => {
    const pinnedGlobal = `ARG BASE=alpine:3@${DIGEST}
FROM node@${DIGEST} AS build
ARG BASE=alpine:3
FROM $BASE`;
    expect(problems(pinnedGlobal)).toEqual([]);
    const unpinnedGlobal = `ARG BASE=alpine:3
FROM node@${DIGEST} AS build
ARG BASE=alpine:3@${DIGEST}
FROM $BASE`;
    expect(problems(unpinnedGlobal)).toEqual([
      "4: base image `alpine:3` has no digest",
    ]);
  });

  it("gives a stage only the ARGs it declares", () => {
    const text = `ARG V=1.2.3
FROM node@${DIGEST}
ARG V
RUN bun install -g left-pad@$V
FROM node@${DIGEST}
RUN bun install -g left-pad@$V`;
    expect(problems(text)).toEqual([
      "6: global install of `left-pad@$V` without an exact version",
    ]);
  });

  it("rejects ADD of a URL without a checksum, in either form", () => {
    expect(
      problems(`FROM x@${DIGEST}
ADD https://example.com/x.tgz /tmp/
ADD ["https://example.com/y.tgz", "/tmp/"]
ADD --checksum=sha256:${SHA} ["https://example.com/z.tgz", "/tmp/"]`),
    ).toEqual([
      "2: `ADD` of a URL without `--checksum`",
      "3: `ADD` of a URL without `--checksum`",
    ]);
  });

  it("rejects npx and bunx that may download, and installs with no lockfile", () => {
    const text = `FROM x@${DIGEST}
RUN npx --yes playwright install-deps firefox
RUN cd /app && bunx some-tool
RUN npm init -y && npm install --save-exact camoufox-js@0.13.0`;
    expect(problems(text)).toEqual([
      "2: `npx` can download a package that is not installed",
      "3: `bunx` can download a package that is not installed",
      "4: a package install with no lockfile",
    ]);
  });

  it("requires an exact version on a global bun install", () => {
    const text = `FROM x@${DIGEST}
RUN bun install -g @pensar/apex
RUN bun add --global left-pad@^1.0.0
RUN bun install -g left-pad@1.3.0`;
    expect(problems(text)).toEqual([
      "2: global install of `@pensar/apex` without an exact version",
      "3: global install of `left-pad@^1.0.0` without an exact version",
    ]);
  });
});

describe("ungatedLockfiles", () => {
  it("names a committed npm lockfile the osv gate does not scan", () => {
    expect(
      ungatedLockfiles(
        [
          "bun.lock",
          "images/a/package-lock.json",
          "scripts/offsec-sandbox/package-lock.json",
          "src/package-lock.json.ts",
        ],
        ["bun.lock", "scripts/offsec-sandbox/package-lock.json"],
      ),
    ).toEqual(["images/a/package-lock.json"]);
  });
});
