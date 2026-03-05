# Flag Extraction Techniques

## Phase 1: Service & Network Discovery (DO THIS FIRST)

Before brute-forcing paths on a single host, discover what services exist on the network.

### Docker / Docker Compose Hostnames
Common service names in containerized environments:
- `internal-api`, `api`, `backend`, `app`, `web`, `server`, `service`
- `flag-service`, `flag-api`, `secret-service`, `admin`, `admin-api`
- `auth`, `gateway`, `proxy`, `nginx`, `caddy`, `traefik`
- `db`, `database`, `postgres`, `mysql`, `redis`, `mongo`, `memcached`
- `worker`, `queue`, `rabbitmq`, `kafka`, `celery`
- `vault`, `consul`, `etcd`

### Kubernetes DNS Patterns
- `<service>.<namespace>.svc.cluster.local`
- `<service>.default.svc.cluster.local`
- Common namespaces: `default`, `kube-system`, `monitoring`, `internal`

### Environment Variable Leaking
Extract internal URLs from env vars exposed by the app:
- Fetch `/env`, `/debug/vars`, `/api/env`, `/actuator/env`
- Fetch `/proc/self/environ` (via LFI/SSRF)
- Look for: `*_HOST`, `*_URL`, `*_SERVICE`, `*_API`, `*_ENDPOINT`, `DATABASE_URL`, `REDIS_URL`
- Parse `.env` files if accessible: `/.env`, `/app/.env`, `/src/.env`

### Response-Based Hostname Discovery
- Read error messages — they often leak internal hostnames/IPs
- Check `Server`, `X-Upstream`, `X-Backend`, `Via` response headers
- Parse HTML/JSON responses for internal URLs (http://something:port/...)
- DNS lookup on discovered hostnames: `nslookup`, `dig`, `host`
- Try fetching `http://<target>` with different `Host` headers to discover vhosts

### Port Scanning (via SSRF)
For each discovered hostname, try common ports:
- Web: 80, 443, 3000, 3001, 4000, 5000, 8000, 8080, 8443, 8888, 9000, 9090
- Databases: 5432 (postgres), 3306 (mysql), 6379 (redis), 27017 (mongo)
- Infra: 8500 (consul), 8200 (vault), 2379 (etcd)

## Phase 2: Endpoint Enumeration

For EACH discovered host+port, try these paths systematically.

### Flag / Secret Endpoints
- `/flag`, `/flag.txt`, `/flag.json`, `/flags`, `/secret`, `/secret.txt`
- `/api/flag`, `/api/secret`, `/api/v1/flag`, `/api/internal/flag`
- `/admin/flag`, `/admin/secret`, `/admin/secrets`

### Admin / Debug Endpoints
- `/admin`, `/admin/`, `/dashboard`, `/internal`, `/debug`
- `/debug/vars`, `/debug/pprof`, `/_debug`, `/__debug`
- `/actuator`, `/actuator/env`, `/actuator/health`, `/actuator/configprops`
- `/metrics`, `/healthz`, `/ready`, `/status`, `/info`
- `/.well-known/`, `/swagger.json`, `/openapi.json`, `/api-docs`

### Config / Environment Endpoints
- `/env`, `/api/env`, `/config`, `/api/config`, `/settings`
- `/proc/self/environ`, `/proc/self/cmdline`
- `/.env`, `/app/.env`, `/etc/environment`

### Common Application Paths
- `/api/`, `/api/v1/`, `/api/v2/`, `/graphql`, `/graphiql`
- `/robots.txt`, `/sitemap.xml`, `/.git/config`, `/.git/HEAD`
- `/backup`, `/dump`, `/export`, `/data`

### Cloud Metadata Endpoints
- AWS: `http://169.254.169.254/latest/meta-data/`, `/latest/user-data/`, `/latest/meta-data/iam/security-credentials/`
- GCP: `http://metadata.google.internal/computeMetadata/v1/` (header: `Metadata-Flavor: Google`)
- Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (header: `Metadata: true`)

## Phase 3: Protocol & Encoding Bypasses

### URL Encoding Tricks
- Double-encode: `%252f` for `/`
- Unicode normalization: `%c0%af` for `/`
- Mixed case: `/Admin`, `/FLAG`, `/Secret`
- Trailing characters: `/flag.`, `/flag;`, `/flag%00`

### IP Representation Tricks (for SSRF filter bypass)
- Decimal: `http://2130706433` (= 127.0.0.1)
- Hex: `http://0x7f000001`
- Octal: `http://0177.0.0.1`
- IPv6: `http://[::1]`, `http://[0:0:0:0:0:ffff:127.0.0.1]`
- DNS rebinding: `http://localtest.me`, `http://127.0.0.1.nip.io`
- Zero tricks: `http://0.0.0.0`, `http://0`

### Request Variations
- Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD
- Content types: `application/json`, `application/x-www-form-urlencoded`, `text/xml`
- Query parameters: `?flag=true`, `?debug=1`, `?admin=1`, `?token=admin`
- Headers: `X-Forwarded-For: 127.0.0.1`, `X-Real-IP: 127.0.0.1`, `Host: internal-api`
- Auth headers: `Authorization: Bearer admin`, `X-API-Key: admin`

### Redirect Chains
- Follow redirects with `curl -L` to see final destination
- Check intermediate responses with `curl -v` for headers/data leaks
- 302/307 responses may differ based on method

## Phase 4: Response Parsing

### Flag Pattern Matching
```bash
grep -oEi 'FLAG\{[^}]*\}' response.txt
grep -oEi '(flag|secret|token|key)\s*[=:]\s*\S+' response.txt
```

### JSON Deep Search
```bash
jq -r '.. | strings | select(test("FLAG"))' response.json
jq -r '.flag // .secret // .data // .content // .key // .token' response.json
jq -r 'paths(strings) as $p | "\($p | join(".")): \(getpath($p))" | select(test("flag|secret|key"; "i"))' response.json
```

### HTML / Text Parsing
- Check HTML comments: `grep -oE '<!--.*?-->'`
- Hidden inputs: `grep -oE '<input[^>]*type="hidden"[^>]*>'`
- Data attributes: `grep -oE 'data-[a-z-]+="[^"]*"'`
- Script tags: inline JS may contain flags as variables
- Base64-encoded content: `grep -oE '[A-Za-z0-9+/]{20,}={0,2}' | base64 -d`

### Response Headers
- Check all headers: `curl -sI` or `curl -sv`
- Custom headers: `X-Flag`, `X-Secret`, `X-Debug`, `X-Token`
- Cookie values may contain flags

## Phase 5: Escalation Patterns

### SSRF → Internal API → Flag
1. Confirm SSRF with external callback (or known internal response)
2. Discover internal hostnames (env vars, error messages, response headers)
3. Port-scan discovered hosts via SSRF
4. Enumerate paths on each discovered host:port
5. Extract flag from internal endpoint

### LFI → Credential Leak → Authenticated Endpoint
1. Read `/etc/passwd`, `/proc/self/environ` via LFI
2. Extract credentials or API keys from env vars
3. Use credentials to authenticate to admin endpoints
4. Access flag endpoint with authentication

### Error-Based Discovery
1. Trigger errors with malformed input
2. Parse stack traces for file paths, hostnames, port numbers
3. Use leaked info to refine further requests

## Phase 6: Advanced Pivoting Techniques

### SSRF Redirect Loops
Convert blind SSRF into visible responses by chaining HTTP redirects:
1. Set up an external redirect server (or find an open redirect on the target)
2. Point your SSRF payload at the redirect URL → it redirects to the internal resource
3. If the application returns the final response, you've made blind SSRF observable
4. Chain multiple redirects to bypass allowlist checks that only validate the first hop
5. Use 307/308 redirects to preserve POST method through the chain

### HTTP/2 CONNECT Port Scanning
When the target supports HTTP/2, use the CONNECT method to scan internal ports:
```bash
curl --http2 -X CONNECT internal-host:6379 https://target/
curl --http2 -X CONNECT localhost:5432 https://target/
```
- Connection refused → port closed, timeout → filtered, success/data → port open
- Bypasses traditional SSRF filters that only inspect HTTP/1.1 URLs
- Try common internal ports: 6379 (redis), 5432 (postgres), 3306 (mysql), 8500 (consul), 8200 (vault)

### Unicode Normalization Bypasses
Use Unicode characters that normalize to ASCII equivalents to bypass SSRF URL filters:
- `ⓛⓞⓒⓐⓛⓗⓞⓢⓣ` → `localhost` (circled letters normalize via NFKC)
- `ⓘⓝⓣⓔⓡⓝⓐⓛ` → `internal`
- Fullwidth characters: `ｈｔｔｐ：／／ｌｏｃａｌｈｏｓｔ` → `http://localhost`
- Overlong UTF-8: `%c0%af` → `/` for path traversal
- Test if the app normalizes input after the URL filter validates it

### Parser Differential Bypasses
Exploit inconsistent URL parsing between the filter and the HTTP client:
- `http://evil.com@internal-host/` — some parsers treat `evil.com` as userinfo, others as host
- `http://internal-host\@evil.com/` — backslash handling differs across parsers
- `http://internal-host%00.evil.com/` — null byte truncation in some URL parsers
- Duplicate `Host` headers — proxy reads one, backend reads the other
- `0x7f000001` (hex IP), `2130706433` (decimal IP), `0177.0.0.1` (octal) — already covered in Phase 3 but combine with parser tricks for layered bypass

### ORM Filter Extraction
If an SSRF target has search/filter endpoints, use ORM injection to extract data without knowing exact paths:
1. Probe for filter endpoints: `/api/search?q=`, `/api/users?filter=`, `/api/data?field=`
2. Test for MongoDB operators: `?field[$gt]=`, `?field[$regex]=^F`
3. Test for relational ORM filters: `?field__startswith=FLAG`, `?field__contains=flag`
4. Boolean-based extraction: `?secret[$regex]=^FLAG\{a` — iterate through characters
5. Automate extraction with a loop: for each position, try all printable chars and check which returns results
