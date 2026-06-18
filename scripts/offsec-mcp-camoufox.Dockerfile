# MCP-path Camoufox sandbox image — mirrors console's production browser
# provisioning (packages/cluster-services/gen-purpose/Dockerfile), which runs
# apex INSIDE the Daytona sandbox and drives the browser via the local
# @playwright/mcp path (playwrightMcp.ts) — NOT the in-sandbox path.
#
# Prod installs `bunx playwright install --with-deps chrome`. This is the
# Camoufox analog: it bakes the Firefox runtime libs + the Camoufox browser
# build, plus bun + git so the smoke orchestrator can clone & install apex and
# run its REAL MCP browser code inside the sandbox.

FROM node:20.18.1-slim

# Same base apt set style as the prod deps layer. build-essential + python3:
# camoufox-js pulls in native better-sqlite3 (no node-20 prebuilt → node-gyp).
# git: clone the apex branch at runtime. unzip/curl/wget: tooling.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 build-essential \
    git curl wget ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

# Bun, pinned to match console's prod base (packageManager).
ARG BUN_VERSION=1.3.10
RUN curl -fsSL https://bun.sh/install | bash -s "bun-v${BUN_VERSION}"
ENV PATH="/root/.bun/bin:$PATH"
RUN bun --version

# Analog of prod's `playwright install --with-deps chrome`: install the Firefox
# system libraries (GTK3, X, nss, fonts…). Camoufox is a patched Firefox.
RUN npx --yes playwright install-deps firefox

# Bake the Camoufox browser build into the image so the agent's ensureCamoufox()
# finds it cached at /root/.cache/camoufox instead of fetching ~662MB on the
# first pentest (the runtime fetch is the step that stalls).
RUN npx --yes camoufox-js fetch
