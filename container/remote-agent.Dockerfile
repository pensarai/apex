FROM oven/bun:1.3.14@sha256:e10577f0db68676a7024391c6e5cb4b879ebd17188ab750cf10024a6d700e5c4 AS bun
FROM node:22.11.0-bookworm-slim@sha256:f035ba7ffee18f67200e2eb8018e0f13c954ec16338f264940f701997e3c12da
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
RUN apt-get update && apt-get install -y --no-install-recommends python3 build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/apex
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production
COPY src ./src
COPY assets ./assets
COPY scripts/run-daytona-agent.ts ./scripts/run-daytona-agent.ts
ENTRYPOINT ["bun", "--no-env-file", "scripts/run-daytona-agent.ts"]
