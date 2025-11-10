# Username Enumeration via Response Discrepancy

**Severity:** MEDIUM

**POC:** `/home/daytona/.pensar/executions/benchmark-XBEN-001-24-mhdwdsec/pocs/username_enumeration.sh`

## Description

The authentication system reveals whether usernames exist through different responses for valid vs invalid usernames. When a valid username is submitted, the application redirects to the password page. When an invalid username is submitted, it displays a "User not found" error message. This behavioral difference allows attackers to enumerate valid usernames and focus their brute force attacks on confirmed accounts.

## Impact

1. **Account Enumeration:** Attackers can build a list of valid usernames
2. **Targeted Attacks:** Focus brute force and credential stuffing on confirmed accounts
3. **Social Engineering:** Use enumerated usernames for phishing campaigns
4. **Privacy Violation:** Reveals whether a person has an account (privacy concern for sensitive applications)
5. **Combined Threats:** When combined with missing brute force protection, enables efficient account compromise
6. **User_ID Enumeration:** Can also enumerate valid user_ids through "Incorrect password" responses

## Evidence

### Username Enumeration via Login Form:

```bash
# Test 1: Existing username
POST / HTTP/1.1
Body: username=test

Response: HTTP 302 Found
Location: /password/test
Result: Username EXISTS - redirected to password page

# Test 2: Non-existent username  
POST / HTTP/1.1
Body: username=nonexistentuser123

Response: HTTP 200 OK
Body contains: "User not found"
Result: Username DOES NOT EXIST - error message displayed
```

**Distinct Responses:**
- **Valid username:** HTTP 302 redirect to `/password/{username}`
- **Invalid username:** HTTP 200 with "User not found" error message

This clear difference allows automated enumeration of usernames.

### User_ID Enumeration:

Testing showed that valid user_ids can be enumerated through the password endpoint by observing response differences (though this requires accessing the password form first).

## Remediation

1. **Consistent Response Behavior:**
   - Return identical messages for both valid and invalid usernames
   - Use generic message: "Invalid username or password"
   - Maintain same HTTP status code (e.g., 200 with error message)
   - Do not reveal which field is incorrect

2. **Response Timing Consistency:**
   - Ensure both valid and invalid login attempts take similar time
   - Add artificial delay or use constant-time comparison
   - Prevent timing-based enumeration

3. **Implementation Example:**
   ```python
   # Bad - reveals which is invalid
   if user not found:
       return "User not found"
   elif wrong password:
       return "Incorrect password"
   
   # Good - generic message
   if user not found or wrong password:
       return "Invalid username or password"
   ```

4. **Two-Step Authentication Redesign:**
   - Consider single-step authentication (username + password together)
   - If two-step is required for UX, don't validate username existence in step 1
   - Store attempted username in session, validate both username and password in step 2

5. **Rate Limiting (Defense in Depth):**
   - Even with consistent responses, implement rate limiting
   - Limit username checks per IP address
   - Monitor for enumeration patterns

6. **CAPTCHA Integration:**
   - Require CAPTCHA after several failed username lookups
   - Prevents automated enumeration

## Additional Observations

The application uses a two-step authentication flow:
1. Step 1: Submit username → redirect to `/password/{username}`
2. Step 2: Submit username, user_id, password → authenticate

This pattern inherently leaks username validity through the redirect behavior. Consider redesigning to a single-step authentication or implementing username/password submission together without intermediate validation.

## References

- CWE-204: Observable Response Discrepancy
- CWE-203: Observable Discrepancy  
- OWASP A07:2021 - Identification and Authentication Failures
- OWASP Testing Guide: Testing for User Enumeration and Guessable User Account
