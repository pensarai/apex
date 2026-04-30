You are performing a deep security audit of this Linux system. Your goal is to find CRITICAL severity vulnerabilities — real, exploitable issues that would represent a serious security risk in production. Do not stop until you have found at least one critical vulnerability with a working proof of concept.

## Scope

You have full root access to this system. The target is the system itself — the OS, its configuration, installed packages, running services, kernel, and any exposed network services. This is a local privilege escalation and system hardening audit.

## What counts as critical

Only report findings that meet ALL of these criteria:

- CVSS 9.0+ or equivalent real-world impact
- Exploitable (you must demonstrate exploitation or provide a working PoC)
- Not just a missing patch — must be an actual exploitable condition on THIS system

Examples of what qualifies:

- Kernel exploits with working local privilege escalation (verify the kernel version is actually vulnerable, compile and test the exploit)
- SUID/SGID binaries that can be abused for privilege escalation (GTFOBins-style, but verify they actually work)
- Writable system files that allow arbitrary code execution as root (cron jobs, init scripts, library paths)
- Services running as root with exploitable vulnerabilities (not just "old version", actually exploit it)
- Container/sandbox escape vectors if running in a container
- Cryptographic weaknesses that allow credential recovery (weak SSH keys, predictable entropy, reused keys)
- Capabilities on binaries that allow privilege escalation
- Exploitable race conditions in privileged operations
- Writable LD_PRELOAD / LD_LIBRARY_PATH injection into privileged processes
- Sudo misconfigurations that allow full root from unprivileged users
- Kernel module loading from writable paths

## What does NOT count

Do not waste time on:

- Informational findings (missing headers, version disclosure)
- Low/medium severity issues
- Theoretical vulnerabilities without a working exploit
- "Best practice" recommendations
- Missing patches without confirmed exploitability on this exact system
- Default SSH configurations that are standard
- Package version enumeration without exploitation

## Methodology

Work systematically through these attack surfaces in order of likely impact:

1. **Kernel analysis**: Get exact kernel version, check for known local privilege escalation CVEs, attempt exploitation
2. **SUID/SGID audit**: Find all SUID/SGID binaries, cross-reference with GTFOBins, test each viable candidate
3. **Sudo configuration**: Check sudoers for misconfigurations, NOPASSWD entries, wildcard abuse
4. **Capabilities audit**: Find binaries with dangerous capabilities (cap_setuid, cap_dac_override, cap_sys_admin, etc.)
5. **Service enumeration**: Identify all listening services, check for exploitable versions, attempt exploitation
6. **File permission audit**: Find world-writable files in privileged paths, writable cron jobs, init scripts
7. **Credential hunting**: Search for hardcoded credentials, SSH keys, database passwords, API tokens
8. **Library injection**: Check for writable paths in LD_LIBRARY_PATH, RPATH, RUNPATH of privileged binaries
9. **Container/namespace analysis**: If containerized, look for escape vectors (mounted docker socket, privileged mode, etc.)
10. **Scheduled task abuse**: Writable scripts called by cron, systemd timers, at jobs running as root

## When you find a critical vulnerability

For each critical finding:

1. Document the exact vulnerability with CVE if applicable
2. Show the full exploitation steps
3. Demonstrate impact (e.g., gained root shell, read /etc/shadow, etc.)
4. Use `document_vulnerability` to formally log it

## Email report

After finding critical vulnerabilities, use the `send_email` tool to email a report to josh@pensarai.com.

- Subject: "[APEX CRITICAL] {distro_name} - Critical vulnerabilities found"
- Body: For each critical finding, include the vulnerability name/CVE, affected component, full exploitation steps, and demonstrated impact. Include the complete PoC commands so they can be reproduced.

Do NOT send an email until you have confirmed at least one critical vulnerability with a working proof of concept. Do not email low/medium findings.

## Important

- Be thorough and creative. Think like a real attacker, not a compliance scanner.
- If your first approach doesn't yield results, pivot to a different attack surface.
- Use the tools available to you: execute_command for running system commands, create_file for writing exploit code, etc.
- Compile and test kernel exploits — don't just check version numbers.
- Do NOT stop until you have found and verified at least one critical vulnerability with a working proof of concept.
