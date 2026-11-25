# Offsec Camoufox sandbox image — mirrors the production build pattern in
# console at packages/cluster-services/gen-purpose/Dockerfile, which bakes the
# browser + its system deps at BUILD time (`bunx playwright install --with-deps
# chrome`) instead of installing them at sandbox boot.
#
# This is the Camoufox analog: it bakes everything apex's offSec sandbox browser
# path (src/core/agents/offSecAgent/tools/sandboxPlaywright.ts) needs, so
# `installSandboxPlaywright` finds it all present and never apt/npm/fetches at
# runtime. Daytona builds this into a cached snapshot; sandboxes boot in seconds.
#
# Built via the Daytona SDK's Image.fromDockerfile() in smoke-daytona-camoufox.ts.

FROM node:22.23.5-slim@sha256:be979e5523c76fa4d5ca4ebd3099078f220aa47ec39c48ad5b5df9314debd6eb

# Same base apt style as the prod deps layer, trimmed to what the browser path
# needs. build-essential + python3: a fallback for native modules without a
# prebuild (better-sqlite3 13, which camoufox-js pulls in, ships prebuilt
# binaries and needs Node 22).
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 build-essential \
    ca-certificates curl wget git \
    && rm -rf /var/lib/apt/lists/*

# apex's sandboxPlaywright.ts resolves camoufox-js/playwright-core from
# SANDBOX_PW_DIR (/opt/sandbox-playwright). Bake them here from the lockfile in
# scripts/offsec-sandbox, which the osv gate scans:
#   - camoufox-js 0.13.0 matches apex's pinned version
#   - playwright-core 1.53.1 is the version camoufox-js is built against
#     (its own devDep). The default tree resolves 1.58.0-alpha via
#     @playwright/mcp, whose newer Juggler protocol the Camoufox build rejects
#     ("Browser.setDefaultViewport ... isMobile not described in this scheme").
WORKDIR /opt/sandbox-playwright
COPY offsec-sandbox/package.json offsec-sandbox/package-lock.json ./
RUN npm ci --no-audit --no-fund

# Analog of prod's `playwright install --with-deps chrome`: install the Firefox
# system libraries (GTK3, X, nss, fonts…). Camoufox is a patched Firefox and
# won't launch without them, even headless. Runs the locked playwright-core.
RUN npx --no-install playwright-core install-deps firefox

# Bake the Camoufox browser build into the image so the runtime fetch (the
# ~700MB step that stalls at sandbox boot) is skipped. Fetch via the pinned
# camoufox-js installed above (not `npx`, which would pull a different version)
# so the baked build matches the runtime camoufox-js — mirrors ensureCamoufox.
# Cached at /root/.cache/camoufox, where the agent (running as root) looks.
# camoufox-js pins the browser build and checks the zip against the SHA-256
# GitHub publishes for it. It only warns when no SHA-256 is published, so fail
# the build on that warning rather than install an unverified browser.
RUN node node_modules/camoufox-js/dist/__main__.js fetch > /tmp/camoufox-fetch.log 2>&1; \
    status=$?; cat /tmp/camoufox-fetch.log; \
    if grep -q "skipping verification" /tmp/camoufox-fetch.log; then \
      echo "camoufox fetch did not verify the browser download" >&2; exit 1; \
    fi; \
    rm /tmp/camoufox-fetch.log; exit $status
