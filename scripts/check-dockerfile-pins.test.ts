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

const DOWNLOAD_STAGE = `FROM scratch AS tool
ADD --checksum=sha256:${SHA} https://example.com/tool-x86_64 /
ADD --checksum=sha256:${SHA} https://example.com/tool-aarch64 /`;

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

  it("keeps heredoc bodies in their instruction", () => {
    const parsed = parseDockerfile(
      ["FROM x", "RUN <<EOF", "echo one", "EOF", "RUN true"].join("\n"),
    );
    expect(parsed.map((i) => i.keyword)).toEqual(["FROM", "RUN", "RUN"]);
    expect(parsed[1]?.args).toContain("echo one");
  });
});

describe("parseDockerfile heredocs", () => {
  const later = `FROM alpine:3`;

  it.each([
    ["a hyphenated delimiter", "RUN <<BUILD-SCRIPT\necho hi\nBUILD-SCRIPT"],
    ["a quoted delimiter", "RUN <<'END.X'\necho hi\nEND.X"],
    ["a <<- delimiter with an indented end", "RUN <<-EOF\n\techo hi\n\tEOF"],
  ])("ends the heredoc at %s, so a later FROM is still checked", (_, run) => {
    expect(problems(`${run}\n${later}`)).toEqual([
      "4: base image `alpine:3` has no digest",
    ]);
  });

  it("does not read a heredoc inside an exec-form RUN", () => {
    expect(
      parseDockerfile(`RUN ["sh", "-c", "cat <<EOF"]\n${later}`).map(
        (i) => i.keyword,
      ),
    ).toEqual(["RUN", "FROM"]);
    expect(problems(`RUN ["sh", "-c", "cat <<EOF"]\n${later}`)).toEqual([
      "2: base image `alpine:3` has no digest",
    ]);
  });
});

describe("checkDockerfile", () => {
  it("accepts the pinned pattern: digests, a download stage used by RUN --mount, locked installs", () => {
    const text = `FROM oven/bun:1.4.4@${DIGEST} AS bun
${DOWNLOAD_STAGE}
FROM node:22.23.5-slim@${DIGEST}
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
RUN apt-get install -y curl wget git
RUN --mount=type=bind,from=tool,target=/tool \\
    install -m 0755 "/tool/tool-$(uname -m)" /usr/local/bin/tool
RUN npm ci && npx --no-install playwright-core install-deps firefox
RUN bun install -g @pensar/apex@2.7.0
FROM scratch AS export
COPY --from=bun /usr/local/bin/bun /
`;
    expect(problems(text)).toEqual([]);
  });

  describe("image references are literal and digest-pinned", () => {
    it.each([
      [
        "FROM node:22.23.5-slim",
        "1: base image `node:22.23.5-slim` has no digest",
      ],
      [
        "FROM kalilinux/kali-rolling:latest",
        "1: base image `kalilinux/kali-rolling:latest` has no digest",
      ],
      [
        "FROM --platform=linux/amd64 node:22",
        "1: base image `node:22` has no digest",
      ],
      [
        "ARG BASE=node:22\nFROM $BASE",
        "2: base image `$BASE` is not a literal",
      ],
    ])("rejects %j", (text, problem) => {
      expect(problems(text)).toEqual([problem]);
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
  });

  describe("a URL appears only in ADD --checksum", () => {
    it.each([
      "curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -",
      "curl -fsSL -o /tmp/tool https://example.com/tool && sha256sum -c tool.sha256",
      "wget -qO- https://example.com/i.sh | sh",
      "git clone https://github.com/example/repo",
      "pip install https://example.com/pkg.tar.gz",
      "bash -c 'set -e; curl -o /tmp/tool https://example.com/tool'",
    ])("rejects a URL in RUN: %s", (cmd) => {
      expect(problems(`FROM x@${DIGEST}\nRUN ${cmd}`)).toEqual([
        "2: a URL in `RUN`",
      ]);
    });

    it("finds a URL in exec form, after RUN flags and in heredocs, whatever the shell does", () => {
      const text = `FROM x@${DIGEST}
RUN ["curl", "-o", "/tmp/b", "https://example.com/b"]
RUN --mount=type=cache,target=/c curl -o /tmp/a https://example.com/a
RUN bash <<EOF > /tmp/install.log
cd /opt && curl -o tool https://example.com/tool
EOF`;
      expect(problems(text)).toEqual([
        "2: a URL in `RUN`",
        "3: a URL in `RUN`",
        "4: a URL in `RUN`",
      ]);
    });

    it("rejects a URL in ENV or ARG, so it cannot reach RUN through a variable", () => {
      const text = `FROM x@${DIGEST}
ARG NODE_URL=https://nodejs.org/dist/node.tar.xz
ENV MIRROR=http://mirror.example.com`;
      expect(problems(text)).toEqual([
        "2: a URL in `ARG`",
        "3: a URL in `ENV`",
      ]);
    });

    it("allows curl as a package name", () => {
      expect(
        problems(`FROM x@${DIGEST}\nRUN apt-get install -y curl wget`),
      ).toEqual([]);
    });
  });

  describe("ADD of a URL", () => {
    it("needs a literal --checksum", () => {
      const text = `FROM scratch AS dl
ADD https://example.com/a /
ADD --checksum=sha256:$HASH https://example.com/b /
ADD ["https://example.com/c", "/"]
FROM x@${DIGEST}
RUN --mount=type=bind,from=dl,target=/dl true`;
      expect(problems(text)).toEqual([
        "2: `ADD` of a URL without a literal `--checksum=sha256:<hash>`",
        "3: `ADD` of a URL without a literal `--checksum=sha256:<hash>`",
        "4: `ADD` of a URL without a literal `--checksum=sha256:<hash>`",
      ]);
    });

    it("must sit in a FROM scratch stage that holds only such ADDs", () => {
      const text = `FROM x@${DIGEST}
ADD --checksum=sha256:${SHA} https://example.com/a /tmp/a
FROM scratch AS dl
ADD --checksum=sha256:${SHA} https://example.com/b /
COPY local.txt /
FROM x@${DIGEST}
RUN --mount=type=bind,from=dl,target=/dl true`;
      expect(problems(text)).toEqual([
        "2: `ADD` of a URL outside a download stage",
        "5: download stage `dl` runs `COPY`",
      ]);
    });

    it("is used only through RUN --mount, which the legacy builder cannot skip", () => {
      const text = `${DOWNLOAD_STAGE}
FROM x@${DIGEST}
COPY --from=tool /tool-x86_64 /usr/local/bin/tool
FROM tool`;
      expect(problems(text)).toEqual([
        "5: download stage `tool` is used through `COPY --from`",
        "6: download stage `tool` is used through `FROM`",
      ]);
    });

    it("is not the last stage", () => {
      expect(problems(DOWNLOAD_STAGE)).toEqual([
        "3: download stage `tool` is the last stage",
      ]);
    });
  });

  describe("package tools", () => {
    it("rejects npx and bunx that may download, and installs with no lockfile", () => {
      const text = `FROM x@${DIGEST}
RUN npx --yes playwright install-deps firefox
RUN cd /app && bunx some-tool && ln -s bun /usr/local/bin/bunx
RUN npm init -y && npm install --save-exact camoufox-js@0.13.0`;
      expect(problems(text)).toEqual([
        "2: `npx` without `--no-install` can download a package",
        "3: `bunx` without `--no-install` can download a package",
        "4: a package install with no lockfile",
      ]);
    });

    it("reads exec-form RUN as its words", () => {
      const text = `FROM x@${DIGEST}
RUN ["npx", "--no-install", "playwright-core", "install-deps", "firefox"]
RUN ["npx", "--yes", "playwright", "install-deps", "firefox"]`;
      expect(problems(text)).toEqual([
        "3: `npx` without `--no-install` can download a package",
      ]);
    });

    it("matches the words anywhere in a RUN, including quoted text", () => {
      expect(
        problems(
          `FROM x@${DIGEST}\nRUN echo 'Install locally with npm install'`,
        ),
      ).toEqual(["2: a package install with no lockfile"]);
    });

    it("requires a literal exact version on a global bun install", () => {
      const text = `FROM x@${DIGEST}
RUN bun install -g @pensar/apex
RUN bun add --global left-pad@^1.0.0
RUN bun install -g "@pensar/apex@$APEX_VERSION"
RUN bun install -g left-pad@1.3.0 "is-odd@3.0.1" --ignore-scripts
RUN ["bun", "install", "-g", "@pensar/apex@2.7.0", "--ignore-scripts"]`;
      expect(problems(text)).toEqual([
        "2: global install of `@pensar/apex` without a literal exact version",
        "3: global install of `left-pad@^1.0.0` without a literal exact version",
        "4: global install of `@pensar/apex@$APEX_VERSION` without a literal exact version",
      ]);
    });
  });
});

describe("checkDockerfile numeric COPY --from", () => {
  it("rejects a copy from a download stage named by its index", () => {
    expect(
      problems(
        `${DOWNLOAD_STAGE}\nFROM node:22@${DIGEST} AS app\nCOPY --from=0 /tool-x86_64 /tool`,
      ),
    ).toEqual(["5: download stage `tool` is used through `COPY --from=0`"]);
  });

  it("accepts a copy from an ordinary stage named by its index", () => {
    expect(
      problems(
        `FROM node:22@${DIGEST} AS build\nRUN true\nFROM node:22@${DIGEST}\nCOPY --from=0 /app /app`,
      ),
    ).toEqual([]);
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
