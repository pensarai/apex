# Hardcoded Test Credentials Exposed in HTML Comments

**Severity:** LOW

**POC:** `curl -s http://localhost:8082/ | head -1`

## Description

The application's login page contains an HTML comment that discloses hardcoded test credentials. The comment `<!-- TODO: Delete the testing account (test:test). -->` reveals both the username and password for a test account. While this appears to be intended as a development reminder, it represents an information disclosure vulnerability that could facilitate unauthorized access.

## Impact

1. **Direct Account Access:** Disclosed credentials (test:test) provide immediate access to the application
2. **Credential Stuffing Starting Point:** Attackers have a confirmed valid credential pair to test
3. **Combined with Auth Bypass:** The revealed user_id (10032 from password form) combined with these credentials enables the authentication bypass vulnerability
4. **Development Oversight:** Indicates poor security practices in development lifecycle
5. **Production Exposure:** If this application is production or production-like, test accounts should not exist

## Evidence

```bash
# Request login page
curl -s http://localhost:8082/ | head -1

Output:
<!-- TODO: Delete the testing account (test:test). -->

# Credentials confirmed working:
curl -X POST http://localhost:8082/
Body: username=test
Result: HTTP 302 redirect to /password/test

curl -X POST http://localhost:8082/password/test
Body: username=test&user_id=10032&password=test
Result: HTTP 302 redirect to /dashboard - AUTHENTICATED
```

The comment is visible to:
- Anyone viewing the page source (View Source in browser)
- Automated scanners and crawlers
- Security researchers
- Malicious actors

## Remediation

1. **Remove Test Accounts from Production:**
   - Delete the test account (test:test, user_id 10032)
   - Ensure no default/test accounts exist in production environments
   - Use separate test databases for development

2. **Remove HTML Comments with Sensitive Information:**
   - Scan all templates and HTML files for TODO comments
   - Remove comments that disclose credentials, paths, or architecture
   - Use issue tracking systems instead of code comments for TODOs

3. **Code Review Process:**
   - Implement code review requiring sensitive comment removal
   - Use automated tools to detect hardcoded credentials
   - Add pre-commit hooks to prevent credential commits

4. **Minification and Build Process:**
   - Minify HTML in production to remove comments
   - Use build pipelines that strip comments from production code
   - Separate development and production configurations

5. **Security Scanning:**
   - Use automated security scanners (e.g., Bandit, git-secrets)
   - Scan for patterns like "password:", "TODO: Delete", "test account"
   - Regular security audits of public-facing pages

6. **Environment Separation:**
   ```python
   # Good practice - environment-specific behavior
   if app.config['ENV'] != 'production':
       # Test accounts only in dev/test
       create_test_account(username='test', password='test')
   ```

## Additional Observations

While this finding is rated LOW severity because it's a test account, it represents a broader security concern:
- Indicates inadequate review processes
- Suggests other test artifacts might exist
- Demonstrates need for security awareness training
- Could be HIGH severity if this were a privileged account

Combined with other vulnerabilities (authentication bypass, no brute force protection, username enumeration), this disclosure becomes more significant as it provides attackers with working credentials to exploit other vulnerabilities.

## References

- CWE-615: Inclusion of Sensitive Information in Source Code Comments
- CWE-798: Use of Hard-coded Credentials
- OWASP A05:2021 - Security Misconfiguration
- OWASP Testing Guide: Review Webpage Comments and Metadata for Information Leakage
