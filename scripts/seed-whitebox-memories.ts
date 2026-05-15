// Seed `~/.pensar/memories/` with whitebox playbook entries.
// Run: `bun run scripts/seed-whitebox-memories.ts [--force]`
// Skips existing entries by stable slug unless --force is passed.

import {
  addMemoryWithId,
  getMemory,
  type MemoryCategory,
} from "../src/core/memory";

interface Seed {
  id: string;
  category: MemoryCategory;
  title: string;
  tags: string[];
  content: string;
}

const SEEDS: Seed[] = [
  {
    id: "wb-sink-sqli-python",
    category: "framework",
    title: "SQL injection sinks (Python)",
    tags: ["whitebox-seed", "sink", "sqli", "python"],
    content: `Common SQL-injection sink patterns to grep for in Python:

- raw cursor.execute() with string concatenation or f-strings:
  \`cursor\\.execute\\(.*\\+\` and \`cursor\\.execute\\(f["']\`
- Django ORM .raw(): \`\\.raw\\(.*\\+\` (concatenation), \`\\.raw\\(f["']\`
- SQLAlchemy textual queries: \`text\\(f["']\`, \`session\\.execute\\(text\\(.*\\+\`
- psycopg2/asyncpg execute() with % formatting outside parameters

Mitigation: parameterized queries (positional/named bind params), SQLAlchemy expression construction, ORM filters.

Tactics to verify:
1. Locate the sink (above patterns).
2. Trace inputs back to a request boundary (Flask view, Django view, FastAPI handler).
3. Confirm no escaping / parameterization between source and sink.
4. Craft a PoC payload via http_request.`,
  },
  {
    id: "wb-sink-sqli-node",
    category: "framework",
    title: "SQL injection sinks (Node / JavaScript)",
    tags: ["whitebox-seed", "sink", "sqli", "node", "javascript", "typescript"],
    content: `Common SQL-injection sink patterns in Node:

- node-postgres pg.query with concatenated SQL: \`pool\\.query\\(\`...\${\`, \`client\\.query\\(.*\\+\`
- mysql / mysql2: \`connection\\.query\\(.*\\+\`, template-literal interpolation
- raw Knex: \`knex\\.raw\\(.*\\+\`, \`knex\\.raw\\(\`...\${\`
- Prisma raw: \`\\$queryRaw\` without \`Prisma.sql\` tagged template (the safe form)
- TypeORM: \`getRepository\\(.*\\)\\.query\\(.*\\+\`, \`createQueryBuilder.*\\.where\\(.*\\+\`

Mitigation: parameterized queries (\\$1, ?, named placeholders), Prisma.sql tagged template, query builders without string concat.`,
  },
  {
    id: "wb-sink-sqli-go",
    category: "framework",
    title: "SQL injection sinks (Go)",
    tags: ["whitebox-seed", "sink", "sqli", "go"],
    content: `Sink patterns:

- database/sql: \`db\\.Query\\(.*\\+\`, \`db\\.Exec\\(.*\\+\`, \`fmt\\.Sprintf.*SELECT\`
- gorm raw: \`db\\.Raw\\(.*\\+\` and similar with Exec
- sqlx: \`Get\\(.*\\+\`, \`Select\\(.*\\+\` with concat
- text/template into SQL strings (rare but dangerous)

Mitigation: parameterized queries with ? / \\$n placeholders, query builders (squirrel, goqu), gorm Where with map / struct conditions.`,
  },

  {
    id: "wb-sink-cmd-exec-node",
    category: "framework",
    title: "Command-exec sinks (Node)",
    tags: ["whitebox-seed", "sink", "command-exec", "node", "javascript"],
    content: `Sinks:

- child_process.exec / execSync with concatenated input
- shell-quote / shelljs invocations with unsanitized template literals
- spawn(\`sh -c\`, [cmd]) — bypasses argv safety
- vm / new Function() called on attacker-influenced strings

Mitigation: prefer spawn(bin, [arg1, arg2]) WITHOUT shell, escape via shell-quote.escape only when shell is unavoidable, avoid eval / new Function.

Tactics: trace from req.body / req.query / req.params to the sink across middleware / service layers.`,
  },
  {
    id: "wb-sink-cmd-exec-python",
    category: "framework",
    title: "Command-exec sinks (Python)",
    tags: ["whitebox-seed", "sink", "command-exec", "python"],
    content: `Sinks:

- os.system, subprocess.Popen(..., shell=True), subprocess.run(..., shell=True)
- os.popen, commands.getoutput (legacy)
- Plumbum local["cmd"][arg + tainted] when shell is invoked
- eval, exec, compile on attacker-influenced strings

Mitigation: subprocess.run([cmd, arg1, arg2]) WITHOUT shell=True; shlex.split for safe argv construction; avoid eval/exec.`,
  },

  {
    id: "wb-sink-path-traversal",
    category: "framework",
    title: "Path traversal sinks (general)",
    tags: ["whitebox-seed", "sink", "path-traversal"],
    content: `Common sinks:

- open / fs.readFile / fs.createReadStream with user-supplied filename
- path.join(base, userInput) WITHOUT canonicalization (still allows ../)
- Express res.sendFile(req.params.path)
- Django HttpResponse with FileResponse(open(user_path))

Mitigation: canonicalize via realpath / path.resolve + assert the result starts with the allowed base directory; reject inputs containing "..", "/", or null bytes; use opaque IDs that map to file paths server-side.`,
  },

  {
    id: "wb-sink-ssrf",
    category: "framework",
    title: "SSRF sinks (general)",
    tags: ["whitebox-seed", "sink", "ssrf"],
    content: `Sinks:

- fetch(userUrl), axios.get(userUrl), urllib.request.urlopen(userUrl), http.get(userUrl)
- Webhook integrations, link previewers, screenshotting services
- Image / file fetchers, "fetch from URL" upload endpoints
- Server-side OAuth callbacks that fetch profile URLs

Tactics: target metadata endpoints first (169.254.169.254 AWS/GCP, 100.100.100.200 Alibaba). Probe loopback (127.0.0.1, localhost, [::1]) and internal IP ranges. Try DNS-rebinding when the validator checks only the initial resolution.

Mitigation: allowlist of approved hosts; reject private IP ranges (RFC1918, loopback, link-local) AFTER DNS resolution; disallow redirects to disallowed targets; consider egress filtering at the network layer.`,
  },

  {
    id: "wb-sink-deserialization",
    category: "framework",
    title: "Unsafe deserialization sinks",
    tags: ["whitebox-seed", "sink", "deserialization"],
    content: `Sinks:

- Python: pickle.loads, marshal.loads, yaml.load (without SafeLoader), shelve
- Java: ObjectInputStream.readObject, XMLDecoder, Apache Commons InvokerTransformer
- Ruby: Marshal.load, YAML.load (pre-Psych safe-mode)
- PHP: unserialize() on user input
- .NET: BinaryFormatter, NetDataContractSerializer, ObjectStateFormatter

Verification: the sink alone is the bug; reach is everything. Trace inputs from HTTP body / cookies / file uploads to the sink.`,
  },

  {
    id: "wb-sink-ssti",
    category: "framework",
    title: "SSTI sinks (server-side template injection)",
    tags: ["whitebox-seed", "sink", "ssti"],
    content: `Sinks:

- Jinja2: render_template_string(user_input), Template(user_input)
- Django: Template(user_input).render — rare but devastating
- Mustache/Handlebars: compiling templates from user input
- Jinja2-equivalents in Go (text/template parsed from user input)

Test payloads (start small): \`{{7*7}}\`, \`\${7*7}\`, \`#{7*7}\` — escalate to language-specific RCE primitives only after confirming basic interpolation.`,
  },

  {
    id: "wb-sink-xxe",
    category: "framework",
    title: "XXE sinks (XML external entities)",
    tags: ["whitebox-seed", "sink", "xxe"],
    content: `Sinks:

- Python lxml.etree.parse / xml.etree.ElementTree.fromstring without disable_entities
- Java DocumentBuilderFactory without setFeature("...disallow-doctype-decl", true)
- libxml2 in PHP / Ruby / Node without LIBXML_NOENT cleared

Verification: send a payload with a SYSTEM entity referencing file:///etc/passwd or an attacker-controlled URL.`,
  },
  {
    id: "wb-sink-dom-xss",
    category: "framework",
    title: "DOM-XSS sinks (frontend)",
    tags: ["whitebox-seed", "sink", "xss", "dom", "frontend"],
    content: `Sinks in client-side code:

- innerHTML / outerHTML / document.write with user-supplied data
- React dangerouslySetInnerHTML, Vue v-html, Angular bypassSecurityTrust*
- jQuery .html() with user input
- eval / Function constructor / setTimeout(stringArg) / setInterval(stringArg)

Sources: location.search, location.hash, postMessage, localStorage, sessionStorage, cookies, fetch responses that originate from user input.`,
  },
  {
    id: "wb-sink-weak-crypto",
    category: "framework",
    title: "Weak crypto / secrets handling",
    tags: ["whitebox-seed", "sink", "crypto"],
    content: `Patterns:

- MD5/SHA1 used for password hashing or signature verification
- Hard-coded keys / IVs / salts in source
- ECB mode block cipher usage
- Predictable randomness (Math.random for security, time-based seeds)
- bcrypt cost factor < 10, scrypt with low N/r/p, PBKDF2 with low iterations

Mitigation: bcrypt cost ≥ 12, scrypt N ≥ 2^15, PBKDF2 ≥ 600k iterations (OWASP 2023); use libsodium / WebCrypto when possible; never roll your own.`,
  },
  {
    id: "wb-sink-jwt-misuse",
    category: "framework",
    title: "JWT misuse",
    tags: ["whitebox-seed", "sink", "jwt", "auth"],
    content: `Patterns:

- jwt.verify(token, secret, { algorithms: undefined }) — accepts any algorithm including \`none\`
- HS256 secret stored in source, .env files committed, or short low-entropy strings
- Algorithm-confusion: backend that accepts BOTH RS256 and HS256, plus key confusion using the RSA public key as the HMAC secret
- Missing exp / nbf validation, missing aud / iss validation
- Long-lived refresh tokens with no rotation, no revocation list

Verification: try \`{ "alg": "none" }\`, try algorithm-switch RS256→HS256 with the published public key as the HMAC secret, check token expiry, check signature reuse across users.`,
  },

  {
    id: "wb-scanner-semgrep",
    category: "framework",
    title: "Scanner recipe — semgrep",
    tags: ["whitebox-seed", "scanner-recipe", "semgrep"],
    content: `Detect installed: \`which semgrep\`
Default ruleset: \`p/security-audit\` (broad). Alternatives: \`p/owasp-top-ten\`, \`p/ci\`, \`p/r2c-security-audit\`, language-specific: \`p/python\`, \`p/javascript\`, \`p/go\`.
Run: \`bun <scripts>/scanners.ts --tool semgrep --codebase <repo> --output <output.json> --config <ruleset>\`
Output: JSON. Normalize via \`bun <scripts>/parse-results.ts --tool semgrep --input <output.json>\`.

Tips: semgrep is fast but noisy on large repos. Filter to a single language ruleset when the codebase is single-language, then run \`p/security-audit\` on the full tree once for breadth.`,
  },
  {
    id: "wb-scanner-gitleaks",
    category: "framework",
    title: "Scanner recipe — gitleaks",
    tags: ["whitebox-seed", "scanner-recipe", "gitleaks", "secrets"],
    content: `Detect installed: \`which gitleaks\`
Run: \`bun <scripts>/scanners.ts --tool gitleaks --codebase <repo> --output <output.json> --config -\`
Pass a path to a gitleaks config (custom rules) instead of \`-\` to extend defaults.
Output: JSON array of findings with RuleID, File, StartLine, Secret.
Normalize via \`bun <scripts>/parse-results.ts --tool gitleaks --input <output.json>\`.

Tip: gitleaks scans BOTH worktree and git history. For pure source-snapshot scans use \`--no-git\`.`,
  },
  {
    id: "wb-scanner-osv-scanner",
    category: "framework",
    title: "Scanner recipe — osv-scanner",
    tags: ["whitebox-seed", "scanner-recipe", "osv-scanner", "deps", "cve"],
    content: `Detect installed: \`which osv-scanner\`
Covers: npm, pnpm, yarn, pip, poetry, Cargo, Go modules, Maven, Gradle, Bundler, Composer, Pub.
Run: \`bun <scripts>/scanners.ts --tool osv-scanner --codebase <repo> --output <output.json> --config -\`
Output: JSON. Normalize via \`bun <scripts>/parse-results.ts --tool osv-scanner --input <output.json>\`.

Tip: lockfiles are required for high-precision results. If only a manifest exists (no lockfile), the scan still runs but is less reliable.`,
  },
  {
    id: "wb-scanner-trivy-fs",
    category: "framework",
    title: "Scanner recipe — trivy fs",
    tags: ["whitebox-seed", "scanner-recipe", "trivy", "deps", "cve", "iac"],
    content: `Detect installed: \`which trivy\`
Covers: dependency CVEs across most ecosystems, plus IaC (Dockerfile, Kubernetes, Terraform) and secrets in one tool.
Run: \`bun <scripts>/scanners.ts --tool trivy-fs --codebase <repo> --output <output.json> --config -\`
Normalize via \`bun <scripts>/parse-results.ts --tool trivy-fs --input <output.json>\`.

Tip: trivy is broader than osv-scanner (IaC + secrets) but slower; use both when both are installed and reconcile overlap downstream.`,
  },
  {
    id: "wb-scanner-bandit",
    category: "framework",
    title: "Scanner recipe — bandit",
    tags: ["whitebox-seed", "scanner-recipe", "bandit", "python"],
    content: `Detect installed: \`which bandit\`
Python-focused SAST. Catches: subprocess shell=True, eval, weak crypto, hard-coded passwords, SQL string formatting.
Run: \`bun <scripts>/scanners.ts --tool bandit --codebase <repo> --output <output.json> --config -\`
Normalize via \`bun <scripts>/parse-results.ts --tool bandit --input <output.json>\`.`,
  },
  {
    id: "wb-scanner-gosec",
    category: "framework",
    title: "Scanner recipe — gosec",
    tags: ["whitebox-seed", "scanner-recipe", "gosec", "go"],
    content: `Detect installed: \`which gosec\`
Go-focused SAST. Catches: SQL string concat, command injection, weak random, hard-coded credentials, path traversal.
Run: \`bun <scripts>/scanners.ts --tool gosec --codebase <repo> --output <output.json> --config -\`
Normalize via \`bun <scripts>/parse-results.ts --tool gosec --input <output.json>\`.`,
  },
  {
    id: "wb-scanner-cargo-audit",
    category: "framework",
    title: "Scanner recipe — cargo audit",
    tags: ["whitebox-seed", "scanner-recipe", "cargo-audit", "rust", "cve"],
    content: `Detect installed: \`which cargo-audit\` (or \`cargo audit\`)
Requires \`Cargo.lock\`. Cross-references RustSec advisory DB.
Run: \`bun <scripts>/scanners.ts --tool cargo-audit --codebase <repo> --output <output.json> --config -\`
Normalize via \`bun <scripts>/parse-results.ts --tool cargo-audit --input <output.json>\`.`,
  },
  {
    id: "wb-scanner-pip-audit",
    category: "framework",
    title: "Scanner recipe — pip-audit",
    tags: ["whitebox-seed", "scanner-recipe", "pip-audit", "python", "cve"],
    content: `Detect installed: \`which pip-audit\`
Auditing of installed Python packages or a requirements.txt against the PyPA Advisory DB.
Run: \`bun <scripts>/scanners.ts --tool pip-audit --codebase <repo> --output <output.json> --config -\`
Normalize via \`bun <scripts>/parse-results.ts --tool pip-audit --input <output.json>\`.`,
  },
  {
    id: "wb-scanner-npm-audit",
    category: "framework",
    title: "Scanner recipe — npm audit",
    tags: ["whitebox-seed", "scanner-recipe", "npm-audit", "node", "cve"],
    content: `Detect installed: \`which npm\`
Built into npm. Cross-references the npm advisory DB.
Run: \`bun <scripts>/scanners.ts --tool npm-audit --codebase <repo> --output <output.json> --config -\`
Normalize via \`bun <scripts>/parse-results.ts --tool npm-audit --input <output.json>\`.

Tip: npm audit returns non-zero on findings — the recipe wraps that so the agent doesn't see it as a tool failure.`,
  },
  {
    id: "wb-scanner-trufflehog",
    category: "framework",
    title: "Scanner recipe — trufflehog",
    tags: ["whitebox-seed", "scanner-recipe", "trufflehog", "secrets"],
    content: `Detect installed: \`which trufflehog\`
High-confidence secrets scanner with active verification (validates AWS keys, GitHub tokens, etc. against the actual provider — only for the verified=true subset).
Run: \`bun <scripts>/scanners.ts --tool trufflehog --codebase <repo> --output <output.ndjson> --config -\`
Output: NDJSON. Normalize via \`bun <scripts>/parse-results.ts --tool trufflehog --input <output.ndjson>\`.

Tip: trufflehog's defaults disable active verification when offline; that's the safer choice during a static review.`,
  },

  {
    id: "wb-review-auth",
    category: "framework",
    title: "Review pass — authentication",
    tags: ["whitebox-seed", "review-pass", "auth"],
    content: `Questions to answer during an auth review:

1. Where are credentials checked? Find the verify-password / verify-token code.
2. What hashing is used and at what cost? (bcrypt < 10, PBKDF2 < 600k → finding)
3. Is constant-time comparison used? (== / strcmp on hashes = timing attack)
4. What session mechanism? (JWT, server-side store, signed cookies)
5. JWT: what algorithms are accepted? Any \`none\` / algorithm-confusion risk?
6. MFA: present? Bypassable via SMS / recovery codes?
7. Password reset: token entropy, expiration, single-use enforcement
8. Account enumeration: timing / response-shape differences in login responses
9. Brute force: rate limiting / account lockout policy
10. OAuth/OIDC: state parameter, PKCE, redirect URI validation, token storage

Don't review in isolation — confirm with PoC: actual login flow, actual JWT generation.`,
  },
  {
    id: "wb-review-authz",
    category: "framework",
    title: "Review pass — authorization / business logic",
    tags: ["whitebox-seed", "review-pass", "authz"],
    content: `Questions:

1. For each route, who CAN access it? (anonymous / authenticated / role X / owner-of-resource)
2. Where is the authz check? (middleware / decorator / inline)
3. Does every state-changing route check ownership of the affected resource?
4. Are there \`is_admin\` flags that can be set via mass-assignment from request bodies?
5. Cross-tenant access: do tenant IDs come from the path/body or from the session?
6. Race conditions in checks (TOCTOU): is the check + use atomic?
7. Step-up auth missing for high-privilege actions (password change, payment, admin)?

PoC: switch session to a low-privilege user, hit the high-privilege endpoint by craft.`,
  },
  {
    id: "wb-review-parser",
    category: "framework",
    title: "Review pass — parsers / input handling",
    tags: ["whitebox-seed", "review-pass", "parser", "input"],
    content: `Look at every untrusted-input parser:

- JSON: deeply nested or huge payloads → DoS? Prototype pollution?
- XML: external entity processing enabled? See XXE sinks.
- YAML: SafeLoader vs default Loader.
- File uploads: extension check vs content-type vs magic-byte check; allowed extensions; size limits.
- Image processing: ImageMagick / libpng version + known CVEs; bomb files.
- ZIP / archive extraction: path traversal (zip slip), zip bombs, decompression ratios.
- Multipart: missing size limits, missing per-field count limits.

For each: does the parser run BEFORE auth/authorization? If yes, every anonymous request can DoS or attack the parser.`,
  },
  {
    id: "wb-review-crypto-secrets",
    category: "framework",
    title: "Review pass — crypto and secrets",
    tags: ["whitebox-seed", "review-pass", "crypto", "secrets"],
    content: `1. Run gitleaks/trufflehog as a baseline.
2. Grep for: \`API_KEY\`, \`SECRET\`, \`PASSWORD\`, \`BEGIN PRIVATE KEY\`, common AWS key prefixes (AKIA, ASIA).
3. Check .env.example for accidentally-real values.
4. Audit crypto primitives (see weak-crypto sink entry).
5. Where are secrets at runtime? (env vars / KMS / Vault). Are they logged or echoed in error responses?
6. TLS cert pinning / TLS version constraints? (TLS 1.0/1.1 still allowed = finding)
7. Key rotation: documented? Possible?
8. Backup encryption?`,
  },
  {
    id: "wb-review-storage",
    category: "framework",
    title: "Review pass — storage / data layer",
    tags: ["whitebox-seed", "review-pass", "storage"],
    content: `1. SQL: parameterization across all queries (see SQLi sink entries).
2. NoSQL injection: query-object injection in MongoDB / Couch / Elasticsearch (\`$where\`, \`$regex\`, \`$ne\`).
3. Encryption-at-rest for PII / credentials? Field-level encryption where needed?
4. Backup access controls?
5. Object storage (S3 / GCS): bucket / object ACLs reviewed? Public-write somewhere?
6. Multi-tenancy: tenant isolation enforced at the DB layer (row-level security) or only at the app layer?
7. Soft-delete: are tombstoned records leaked via search endpoints or backups?`,
  },
  {
    id: "wb-review-infra",
    category: "framework",
    title: "Review pass — infra / runtime / supply chain",
    tags: ["whitebox-seed", "review-pass", "infra", "supply-chain"],
    content: `1. Dockerfile: running as root? COPY of .env / .git into the image?
2. CI/CD: workflows that echo secrets? Use of \`pull_request_target\` with checkout of attacker code?
3. Dependency provenance: package-lock or equivalent committed? Any \`*\` / \`latest\` ranges in production deps?
4. Postinstall hooks in npm packages — auditable?
5. Kubernetes / Helm: hostNetwork, hostPath, privileged: true, capabilities: ALL?
6. Terraform: open security groups (0.0.0.0/0:22), public S3 buckets, IAM:* policies?
7. GitHub Actions third-party actions pinned by SHA, not tag?`,
  },

  {
    id: "wb-fuzzer-atheris",
    category: "framework",
    title: "Fuzzer — atheris (Python)",
    tags: ["whitebox-seed", "fuzzer", "python", "atheris"],
    content: `atheris is a Python wrapping of libFuzzer.

Usage:
\`\`\`python
import atheris, sys
@atheris.instrument_func
def TestOneInput(data):
    target_function(data)
atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
\`\`\`

Run: \`python fuzz_target.py -max_total_time=60\`

Use cases: parsers (JSON/YAML/XML/protobuf), template engines, deserializers.`,
  },
  {
    id: "wb-fuzzer-cargo-fuzz",
    category: "framework",
    title: "Fuzzer — cargo fuzz (Rust)",
    tags: ["whitebox-seed", "fuzzer", "rust", "cargo-fuzz"],
    content: `cargo-fuzz wraps libFuzzer for Rust.

Init: \`cargo fuzz init && cargo fuzz add target_1\`
Write a fuzz_target! macro that calls the function under test.
Run: \`cargo fuzz run target_1 -- -max_total_time=60\`

Use cases: parsers, sandboxed eval, anything with \`unsafe\` blocks, ffi boundaries.`,
  },
  {
    id: "wb-fuzzer-go-fuzz",
    category: "framework",
    title: "Fuzzer — go test -fuzz",
    tags: ["whitebox-seed", "fuzzer", "go"],
    content: `Native to Go 1.18+. Write a FuzzXxx(f *testing.F) test that adds seed corpus via f.Add and calls the target inside f.Fuzz.

Run: \`go test -fuzz=FuzzXxx -fuzztime=60s ./pkg/...\`

Use cases: parsers (encoding/json, encoding/xml), input validators, network protocol handlers.`,
  },
  {
    id: "wb-fuzzer-jazzer",
    category: "framework",
    title: "Fuzzer — Jazzer (JVM)",
    tags: ["whitebox-seed", "fuzzer", "java", "jvm", "jazzer"],
    content: `Jazzer is a libFuzzer-style fuzzer for the JVM (Java, Kotlin, Scala).

Add com.code-intelligence:jazzer-junit, write @FuzzTest methods. Bug detectors catch SQLi, command injection, deserialization, SSRF without needing manual oracle code.

Use cases: parsers, deserializers, anything that processes external data formats.`,
  },
];

async function main(): Promise<void> {
  const force = process.argv.includes("--force");
  const results = await Promise.all(
    SEEDS.map(async (seed) => {
      const existing = await getMemory(seed.category, seed.id);
      if (existing && !force) return "skipped" as const;
      await addMemoryWithId({
        id: seed.id,
        category: seed.category,
        title: seed.title,
        content: seed.content,
        tags: seed.tags,
      });
      return existing ? ("updated" as const) : ("added" as const);
    }),
  );
  const added = results.filter((r) => r === "added").length;
  const updated = results.filter((r) => r === "updated").length;
  const skipped = results.filter((r) => r === "skipped").length;
  console.log(
    `Seeded whitebox memories: ${added} added, ${updated} updated, ${skipped} skipped (use --force to overwrite). Total catalog size: ${SEEDS.length}.`,
  );
}

if (/seed-whitebox-memories\.(ts|js)$/.test(process.argv[1] ?? "")) {
  main().catch((e) => {
    console.error("Failed to seed whitebox memories:", e);
    process.exit(1);
  });
}

export { SEEDS };
