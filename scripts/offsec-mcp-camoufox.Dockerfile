# MCP-path Camoufox sandbox image — mirrors console's production browser
# provisioning (packages/cluster-services/gen-purpose/Dockerfile), which runs
# apex INSIDE the Daytona sandbox and drives the browser via the local
# @playwright/mcp path (playwrightMcp.ts) — NOT the in-sandbox path.
#
# Prod installs `bunx playwright install --with-deps chrome`. This is the
# Camoufox analog: it bakes the Firefox runtime libs + the Camoufox browser
# build, plus bun + git so the smoke orchestrator can clone & install apex and
# run its REAL MCP browser code inside the sandbox.

FROM oven/bun:1.4.4@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d AS bun

FROM node:22.23.5-slim@sha256:be979e5523c76fa4d5ca4ebd3099078f220aa47ec39c48ad5b5df9314debd6eb

# Same base apt set style as the prod deps layer. build-essential + python3: a
# fallback for native modules without a prebuild (better-sqlite3 13, which
# camoufox-js pulls in, ships prebuilt binaries and needs Node 22).
# git: clone the apex branch at runtime. unzip/curl/wget: tooling.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 build-essential \
    git curl wget ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

# Bun, the same release as console's (packageManager), copied from the
# digest-pinned official image above.
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
RUN ln -s bun /usr/local/bin/bunx && bun --version

# Install the locked browser packages (scripts/offsec-sandbox, scanned by the
# osv gate) to a scratch directory, then use them below.
WORKDIR /tmp/camoufox-fetch
COPY offsec-sandbox/package.json offsec-sandbox/package-lock.json ./
RUN npm ci --no-audit --no-fund

# Analog of prod's `playwright install --with-deps chrome`: install the Firefox
# system libraries (GTK3, X, nss, fonts…). Camoufox is a patched Firefox.
# Runs the locked playwright-core.
RUN npx --no-install playwright-core install-deps firefox

# Bake the Camoufox browser build into the image so the agent's ensureCamoufox()
# finds it cached at /root/.cache/camoufox instead of fetching ~700MB on the
# first pentest (the runtime fetch is the step that stalls). Use the locked
# camoufox-js binary (not npx, which could resolve a different build) — mirrors
# the sandbox Dockerfile and ensureCamoufox().
# camoufox-js pins the browser build and checks the zip against the SHA-256
# GitHub publishes for it. It only warns when no SHA-256 is published, so fail
# the build on that warning rather than install an unverified browser.
RUN node node_modules/camoufox-js/dist/__main__.js fetch > /tmp/camoufox-fetch.log 2>&1; \
    status=$?; cat /tmp/camoufox-fetch.log; \
    if grep -q "skipping verification" /tmp/camoufox-fetch.log; then \
      echo "camoufox fetch did not verify the browser download" >&2; exit 1; \
    fi; \
    [ "$status" -eq 0 ] && cd / && rm -rf /tmp/camoufox-fetch /tmp/camoufox-fetch.log
