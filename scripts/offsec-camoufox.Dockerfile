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

FROM node:20.18.1-slim

# Same base apt style as the prod deps layer, trimmed to what the browser path
# needs. build-essential + python3: camoufox-js pulls in the native
# better-sqlite3, which has no prebuilt for node 20 and falls back to node-gyp.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 build-essential \
    ca-certificates curl wget git \
    && rm -rf /var/lib/apt/lists/*

# apex's sandboxPlaywright.ts resolves camoufox-js/playwright-core from
# SANDBOX_PW_DIR (/opt/sandbox-playwright). Bake them here, PINNED:
#   - camoufox-js 0.11.1 matches the change on the branch
#   - playwright-core 1.53.1 is the version camoufox-js is built against
#     (its own devDep). The default tree resolves 1.58.0-alpha via
#     @playwright/mcp, whose newer Juggler protocol the Camoufox build rejects
#     ("Browser.setDefaultViewport ... isMobile not described in this scheme").
WORKDIR /opt/sandbox-playwright
RUN npm init -y --silent \
 && npm install --no-audit --no-fund camoufox-js@0.11.1 playwright-core@1.53.1

# Analog of prod's `playwright install --with-deps chrome`: install the Firefox
# system libraries (GTK3, X, nss, fonts…). Camoufox is a patched Firefox and
# won't launch without them, even headless.
RUN npx --yes playwright install-deps firefox

# Bake the Camoufox browser build into the image so the runtime fetch (the
# ~700MB step that stalls at sandbox boot) is skipped. Fetch via the pinned
# camoufox-js installed above (not `npx`, which would pull a different version)
# so the baked build matches the runtime camoufox-js — mirrors ensureCamoufox.
# Cached at /root/.cache/camoufox, where the agent (running as root) looks.
RUN node node_modules/camoufox-js/dist/__main__.js fetch
