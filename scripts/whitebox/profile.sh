#!/usr/bin/env bash
# Profile a codebase for whitebox security assessment.
#
# Usage: profile.sh <codebase_path>
#
# Emits a single JSON object on stdout describing:
#   - languages detected (heuristic file-extension scan)
#   - package managers and lockfiles present
#   - build / test commands (extracted from package.json scripts, best effort)
#   - which security scanners are installed and on $PATH
#   - entry-point hints (common server / CLI / web framework files)
#   - git metadata (HEAD sha, branch, remote)
#
# The output is *advisory* — the agent uses it to decide which scanners
# to run and which sink patterns to query. A profile that misses a niche
# language is fine; the agent can fall back to `spawn_coding_agent` with
# a profile responseSchema for deeper inspection.

set -euo pipefail

CODEBASE="${1:?codebase path required}"

if [ ! -d "$CODEBASE" ]; then
  printf '{"error":"codebase path does not exist","path":"%s"}\n' "$CODEBASE"
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  printf '{"error":"python3 is required for profile.sh JSON encoding"}\n'
  exit 0
fi

has_cmd() { command -v "$1" >/dev/null 2>&1; }

ext_has_files() {
  # Cheap "any file with this glob exists" check that ignores common
  # vendor / build dirs so a node_modules artifact doesn't classify a
  # repo as JS when it isn't.
  find "$CODEBASE" -type f -name "$1" \
    -not -path '*/node_modules/*' \
    -not -path '*/.git/*' \
    -not -path '*/dist/*' \
    -not -path '*/build/*' \
    -not -path '*/.next/*' \
    -not -path '*/target/*' \
    -not -path '*/vendor/*' \
    -print -quit 2>/dev/null | grep -q .
}

# -- Languages --------------------------------------------------------------

LANGS=()
ext_has_files '*.py' && LANGS+=("python")
if ext_has_files '*.js' || ext_has_files '*.mjs' || ext_has_files '*.cjs'; then
  LANGS+=("javascript")
fi
if ext_has_files '*.ts' || ext_has_files '*.tsx'; then
  LANGS+=("typescript")
fi
ext_has_files '*.go' && LANGS+=("go")
ext_has_files '*.rs' && LANGS+=("rust")
ext_has_files '*.java' && LANGS+=("java")
ext_has_files '*.kt' && LANGS+=("kotlin")
ext_has_files '*.rb' && LANGS+=("ruby")
ext_has_files '*.php' && LANGS+=("php")
ext_has_files '*.cs' && LANGS+=("csharp")
ext_has_files '*.swift' && LANGS+=("swift")
if ext_has_files '*.c' || ext_has_files '*.h'; then LANGS+=("c"); fi
if ext_has_files '*.cpp' || ext_has_files '*.cc' || ext_has_files '*.hpp'; then
  LANGS+=("cpp")
fi

# -- Package managers + lockfiles -------------------------------------------

PKG_MGRS=()
LOCKFILES=()

if [ -f "$CODEBASE/package.json" ]; then
  if [ -f "$CODEBASE/bun.lock" ] || [ -f "$CODEBASE/bun.lockb" ]; then
    PKG_MGRS+=("bun"); LOCKFILES+=("bun.lock")
  elif [ -f "$CODEBASE/pnpm-lock.yaml" ]; then
    PKG_MGRS+=("pnpm"); LOCKFILES+=("pnpm-lock.yaml")
  elif [ -f "$CODEBASE/yarn.lock" ]; then
    PKG_MGRS+=("yarn"); LOCKFILES+=("yarn.lock")
  elif [ -f "$CODEBASE/package-lock.json" ]; then
    PKG_MGRS+=("npm"); LOCKFILES+=("package-lock.json")
  else
    PKG_MGRS+=("npm")
  fi
fi
[ -f "$CODEBASE/Cargo.toml" ] && PKG_MGRS+=("cargo")
[ -f "$CODEBASE/Cargo.lock" ] && LOCKFILES+=("Cargo.lock")
[ -f "$CODEBASE/go.mod" ] && PKG_MGRS+=("go-modules")
[ -f "$CODEBASE/go.sum" ] && LOCKFILES+=("go.sum")
[ -f "$CODEBASE/pyproject.toml" ] && PKG_MGRS+=("python/pyproject")
[ -f "$CODEBASE/requirements.txt" ] && { PKG_MGRS+=("pip"); LOCKFILES+=("requirements.txt"); }
[ -f "$CODEBASE/Pipfile" ] && PKG_MGRS+=("pipenv")
[ -f "$CODEBASE/Pipfile.lock" ] && LOCKFILES+=("Pipfile.lock")
[ -f "$CODEBASE/poetry.lock" ] && LOCKFILES+=("poetry.lock")
[ -f "$CODEBASE/Gemfile" ] && PKG_MGRS+=("bundler")
[ -f "$CODEBASE/Gemfile.lock" ] && LOCKFILES+=("Gemfile.lock")
[ -f "$CODEBASE/composer.json" ] && PKG_MGRS+=("composer")
[ -f "$CODEBASE/composer.lock" ] && LOCKFILES+=("composer.lock")
[ -f "$CODEBASE/pom.xml" ] && PKG_MGRS+=("maven")
if [ -f "$CODEBASE/build.gradle" ] || [ -f "$CODEBASE/build.gradle.kts" ]; then
  PKG_MGRS+=("gradle")
fi

# -- Installed scanners -----------------------------------------------------

SCANNERS=()
for tool in semgrep gitleaks osv-scanner trivy bandit gosec cargo-audit pip-audit npm trufflehog; do
  has_cmd "$tool" && SCANNERS+=("$tool")
done

# -- Entry-point hints ------------------------------------------------------

ENTRYPOINTS=()
for hint in \
  "src/index.ts" "src/main.ts" "src/cli.ts" "src/app.ts" "src/server.ts" \
  "src/index.js" "src/main.js" "src/cli.js" "src/app.js" "src/server.js" \
  "main.py" "app.py" "manage.py" "wsgi.py" "asgi.py" \
  "main.go" "cmd/main.go" \
  "src/main.rs" "src/lib.rs" \
  "main.rb" "app.rb" "config.ru" \
  "index.php"; do
  [ -f "$CODEBASE/$hint" ] && ENTRYPOINTS+=("$hint")
done

# -- Git metadata -----------------------------------------------------------

GIT_SHA=""
GIT_BRANCH=""
GIT_REMOTE=""
if [ -d "$CODEBASE/.git" ] && has_cmd git; then
  GIT_SHA="$(git -C "$CODEBASE" rev-parse HEAD 2>/dev/null || true)"
  GIT_BRANCH="$(git -C "$CODEBASE" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  GIT_REMOTE="$(git -C "$CODEBASE" config --get remote.origin.url 2>/dev/null || true)"
fi

# -- JSON encode -----------------------------------------------------------
#
# Pass the bash-collected buckets to a sibling python helper via stdin.
# We can't use a `python3 - <<HEREDOC` pattern here because the heredoc
# replaces stdin and clobbers the pipe — `_profile_json.py` lives next
# to this script and reads the buckets normally from stdin.

HELPER="$(dirname "$0")/_profile_json.py"

{
  printf '%s\n' "---LANGS---"
  for v in ${LANGS[@]+"${LANGS[@]}"}; do printf '%s\n' "$v"; done
  printf '%s\n' "---PKG_MGRS---"
  for v in ${PKG_MGRS[@]+"${PKG_MGRS[@]}"}; do printf '%s\n' "$v"; done
  printf '%s\n' "---LOCKFILES---"
  for v in ${LOCKFILES[@]+"${LOCKFILES[@]}"}; do printf '%s\n' "$v"; done
  printf '%s\n' "---SCANNERS---"
  for v in ${SCANNERS[@]+"${SCANNERS[@]}"}; do printf '%s\n' "$v"; done
  printf '%s\n' "---ENTRYPOINTS---"
  for v in ${ENTRYPOINTS[@]+"${ENTRYPOINTS[@]}"}; do printf '%s\n' "$v"; done
  printf '%s\n' "---END---"
} | CODEBASE="$CODEBASE" GIT_SHA="$GIT_SHA" GIT_BRANCH="$GIT_BRANCH" GIT_REMOTE="$GIT_REMOTE" \
  python3 "$HELPER"
