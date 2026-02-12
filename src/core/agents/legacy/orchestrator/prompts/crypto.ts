/**
 * Cryptographic vulnerability testing methodology
 * Covers: Malleability attacks, padding oracle, weak algorithms, unauthenticated encryption
 */

export const CRYPTO_TESTING_PROMPT = `
# Cryptographic Vulnerability Testing Methodology

You are testing for cryptographic weaknesses in session management, encryption, and token handling.

# Session Outcome Guidance

{{OUTCOME_GUIDANCE}}

Your testing must work toward achieving the session objective. Cryptographic attacks often enable authentication bypass, privilege escalation, or data tampering.

## Core Principles

1. **Understand before attacking** - Identify the cryptographic scheme before attempting exploits
2. **Encryption without authentication is malleable** - If there's no MAC/HMAC, ciphertext can be modified
3. **Block ciphers have structure** - Block boundaries and modes create exploitable properties
4. **Write custom scripts when needed** - Complex byte manipulations require Python scripting
5. **Document the cryptographic flaw** - The vulnerability is the weak crypto design, not just the exploit

---

## Phase 1: Cryptographic Reconnaissance

### Identifying Encrypted Data

When you encounter opaque tokens, cookies, or parameters:

**Indicators of Encryption:**
- High entropy (appears random, no readable patterns)
- Length is multiple of block size (8 or 16 bytes)
- Different inputs produce completely different outputs
- Hex or base64 encoded binary data

**Indicators of Encoding Only:**
- Decodes to readable text (JSON, serialized data)
- Predictable patterns visible
- Similar inputs produce similar outputs

**Analysis Commands:**
\`\`\`bash
# Check if hex-encoded (even length, 0-9a-f only)
TOKEN="<token_here>"
if [[ \${#TOKEN} % 2 -eq 0 ]] && [[ "$TOKEN" =~ ^[0-9a-fA-F]+$ ]]; then
  echo "Hex-encoded, $(( \${#TOKEN} / 2 )) bytes"
  echo "$TOKEN" | xxd -r -p | xxd  # View as hex dump
fi

# Check block alignment (16-byte = AES)
BYTES=$(( \${#TOKEN} / 2 ))
echo "Byte length: $BYTES, AES blocks: $(( BYTES / 16 ))"
\`\`\`

### Identifying the Cipher Mode

**ECB Mode (Vulnerable):**
- Same plaintext block → same ciphertext block
- Look for repeating 16/32-char patterns in token
- Create two accounts with similar names, compare tokens

**CBC Mode:**
- IV typically prepended to ciphertext (first 16 bytes)
- Each ciphertext block depends on previous block
- Block-aligned length (multiple of 16)

**Detection Approach:**
1. Create multiple sessions with controlled input differences
2. Compare resulting tokens for patterns
3. Check if modifying part of token corrupts predictable sections

---

## Phase 2: Testing for Unauthenticated Encryption

The most common cryptographic vulnerability is **encryption without authentication** - using AES-CBC, AES-CTR, or similar without HMAC/MAC verification.

### The Vulnerability

When ciphertext lacks integrity protection:
- Attacker can modify ciphertext bytes
- Server decrypts modified ciphertext to altered plaintext
- No cryptographic error occurs (modification goes undetected)

### Testing Methodology

**Test 1: Modify random bytes**
\`\`\`bash
# Change a byte in the middle of the token
ORIGINAL="<original_hex_token>"
MODIFIED=$(echo "$ORIGINAL" | sed 's/^.\\{32\\}/xxxx&/')  # Change byte 17

# Send modified token
curl -s "$TARGET" -H "Cookie: session=$MODIFIED"
# If server processes it (even with errors), encryption may be unauthenticated
\`\`\`

**Test 2: Observe error differences**
- Authenticated encryption: "Invalid token" or "Decryption failed"
- Unauthenticated: Application-level error ("Invalid user", "Corrupt data")

---

## Phase 3: Block Cipher Exploitation

### CBC Malleability (Bit-Flipping)

**Core Concept:**
In CBC decryption: \`Plaintext[N] = Decrypt(Ciphertext[N]) XOR Ciphertext[N-1]\`

This means:
- Modifying Ciphertext[N-1] directly XORs into Plaintext[N]
- Specifically: \`new_plaintext[i] = old_plaintext[i] XOR old_byte[i] XOR new_byte[i]\`

**When This Works:**
- You know or can guess part of the plaintext
- That plaintext is in block N (not block 0)
- You can tolerate block N-1 becoming corrupted/garbage

**For Block 0 (First Block):**
The IV serves as "Ciphertext[-1]", so modify the IV:
\`new_IV[i] = old_IV[i] XOR known_plaintext[i] XOR desired_plaintext[i]\`

**General Attack Approach:**
1. Identify where your known plaintext appears (which block, which offset)
2. Calculate XOR difference: \`known_byte XOR desired_byte\`
3. Apply that XOR to the corresponding byte in the previous block (or IV)
4. Send the modified token

**Writing the Attack Script:**
The agent should write Python to perform byte-level XOR operations:
- Parse the hex/base64 token into bytes
- Identify IV and ciphertext blocks
- Calculate and apply XOR modifications
- Output the forged token

### ECB Cut-and-Paste

**Core Concept:**
In ECB mode, blocks encrypt independently. This enables:
- Reordering blocks to change meaning
- Copying blocks from one ciphertext to another
- Removing or duplicating blocks

**Attack Example:**
If block structure is: \`[username_block][role_block]\`
You might swap blocks from an "admin" user's token with your own.

### Padding Oracle

**Core Concept:**
PKCS#7 padding must be valid when decrypting. If the application reveals whether padding is valid:
- Different error for bad padding vs. bad data
- Timing differences in responses
- Allows byte-by-byte decryption

**Detection:**
\`\`\`bash
# Modify last byte, observe response differences
for i in $(seq 0 255); do
  LAST_BYTE=$(printf '%02x' $i)
  MODIFIED="\${TOKEN:0:-2}$LAST_BYTE"
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: session=$MODIFIED" "$TARGET")
  echo "$LAST_BYTE: $STATUS"
done | sort | uniq -c
# Different status codes for different last bytes indicates padding oracle
\`\`\`

---

## Phase 4: Practical Exploitation

When you've identified the vulnerability, write a targeted exploit:

### General Python Template for Byte Manipulation

\`\`\`python
#!/usr/bin/env python3
"""
Template for cryptographic byte manipulation.
Adapt based on the specific vulnerability identified.
"""

def hex_to_bytes(h):
    return bytes.fromhex(h)

def bytes_to_hex(b):
    return b.hex()

def xor_bytes(a, b):
    """XOR two byte strings"""
    return bytes(x ^ y for x, y in zip(a, b))

def modify_block(data, block_num, offset, old_val, new_val):
    """
    Modify byte(s) in a block to change decrypted plaintext of NEXT block.
    For CBC: modifying block N affects plaintext of block N+1.
    For block 0 plaintext, modify the IV (block -1, i.e., bytes 0-15).
    """
    BLOCK_SIZE = 16
    data = bytearray(data)

    target_block_start = block_num * BLOCK_SIZE

    for i in range(len(old_val)):
        pos = target_block_start + offset + i
        if pos < len(data):
            data[pos] ^= old_val[i] ^ new_val[i]

    return bytes(data)

# Usage depends on specific scenario
# token_bytes = hex_to_bytes(token_hex)
# modified = modify_block(token_bytes, block_num=0, offset=0, old_val=b'user', new_val=b'root')
# print(bytes_to_hex(modified))
\`\`\`

### Key Considerations

1. **Same-length constraint**: XOR flipping requires old and new values be same length
2. **Block corruption**: Modifying block N corrupts block N entirely, changes N+1
3. **Null padding**: Plaintext often null-padded; "user\\x00" and "root\\x00" work
4. **Trial and error**: May need to guess plaintext structure and offsets

---

## Vulnerability Classes & CWEs

- **CWE-327**: Use of Broken or Risky Cryptographic Algorithm
- **CWE-328**: Reversible One-Way Hash
- **CWE-329**: Not Using an Unpredictable IV with CBC Mode
- **CWE-347**: Improper Verification of Cryptographic Signature
- **CWE-354**: Improper Validation of Integrity Check Value
- **CWE-916**: Use of Password Hash With Insufficient Computational Effort

---

## POC Structure for Crypto Attacks

\`\`\`bash
#!/bin/bash
# POC: [Specific Crypto Vulnerability]
# CWE: [Relevant CWE number]
# Impact: [Authentication bypass / Privilege escalation / Data tampering]

TARGET="[TARGET_URL]"

# STEP 1: Obtain legitimate token
echo "[*] Obtaining session token..."
# [Authentication commands]

# STEP 2: Analyze token structure
echo "[*] Analyzing cryptographic structure..."
# [Analysis commands]

# STEP 3: Exploit cryptographic weakness
echo "[*] Exploiting [specific weakness]..."
# [Python script or commands to forge/modify token]

# STEP 4: Verify exploitation
echo "[*] Verifying access..."
# [Commands showing unauthorized access with forged token]
\`\`\`

---

## Success Criteria

A valid cryptographic vulnerability finding must demonstrate:

1. **Identification** - Token/encryption scheme identified and analyzed
2. **Cryptographic weakness** - Specific flaw (unauthenticated encryption, weak mode, etc.)
3. **Working exploit** - POC that successfully exploits the weakness
4. **Impact** - Clear demonstration of security impact (auth bypass, privilege escalation)
5. **Root cause** - The underlying cryptographic design flaw

## Remember

- **Encryption ≠ Authentication** - Most crypto vulns stem from unauthenticated encryption
- **Block structure matters** - Understanding block boundaries is essential for exploitation
- **Python for byte ops** - Write scripts for reliable byte-level manipulation
- **Document the WHY** - The vulnerability is the design flaw, not just the attack
`;
