import type { CatalogRecord } from "./types";

export const WHITEBOX_CATALOG: CatalogRecord[] = [
  {
    id: "repo.day-one-recon",
    kind: "review-pass",
    title: "Day-one repository recon",
    tags: ["repo", "recon", "orientation"],
    tools: ["tokei", "git", "tree", "rg"],
    guidance:
      "Profile languages, manifests, current commit, submodules, generated/vendor exclusions, build/test/run commands, recent security-sensitive changes, and local runtime hints before deep analysis.",
  },
  {
    id: "entry.http-routes",
    kind: "entry-point",
    title: "HTTP route definitions",
    languages: [
      "typescript",
      "javascript",
      "python",
      "go",
      "rust",
      "java",
      "kotlin",
      "ruby",
    ],
    tags: ["entrypoint", "http", "routes"],
    patterns: [
      "@(app|router|blueprint)\\.(get|post|put|patch|delete)",
      "app\\.(get|post|put|patch|delete)\\(",
      "http\\.HandleFunc|mux\\.Handle|chi\\.Route",
      "Router::new\\(\\)\\.route|actix_web::web::resource",
      "@(Get|Post|Put|Delete|Patch|Request)Mapping",
      "resources :|namespace .* do",
    ],
    guidance:
      "Map route -> handler -> auth middleware -> downstream sink. Consolidate methods per route and keep file/line/handler evidence.",
  },
  {
    id: "entry.async-handlers",
    kind: "entry-point",
    title: "Async, webhook, serverless, and realtime entry points",
    tags: ["entrypoint", "queues", "webhooks", "serverless", "websocket"],
    patterns: [
      "SQS|Kafka|Celery|Bull|Sidekiq|RabbitMQ",
      "webhook|signature|X-Hub-Signature|stripe-signature",
      "exports\\.handler|lambda\\.Handler|APIGatewayProxy",
      "WebSocket|SSE|EventSource|socket\\.io",
      "cron|schedule|watch\\(",
    ],
    guidance:
      "Treat queue consumers, webhooks, Lambda handlers, WebSockets, CLIs, cron jobs, file watchers, and signal handlers as attacker-controlled entry points when inputs cross trust boundaries.",
  },
  {
    id: "boundary.trust-map",
    kind: "trust-boundary",
    title: "Trust-boundary map",
    tags: ["trust-boundary", "tenant", "internal-services"],
    guidance:
      "Identify user-to-app, frontend-to-backend, app-to-DB, app-to-internal-service, app-to-third-party, tenant-to-tenant, background job tenant context, and internal/admin surfaces.",
  },
  {
    id: "sink.command-exec",
    kind: "sink",
    title: "Command execution",
    languages: [
      "typescript",
      "javascript",
      "python",
      "go",
      "java",
      "kotlin",
      "rust",
    ],
    tags: ["rce", "command-injection", "sink"],
    patterns: [
      "child_process\\.exec\\(",
      "subprocess\\..*shell\\s*=\\s*True",
      "\\b(exec|eval|system|popen)\\(",
      "os/exec|Runtime\\.exec|ProcessBuilder",
      "Command::new\\([^)]*sh|sh\\s+-c",
    ],
    guidance:
      "Trace command arguments backward to route, queue, webhook, config, archive, or tenant-controlled input. Prefer execFile/argument arrays and allowlists.",
  },
  {
    id: "sink.injection",
    kind: "sink",
    title: "SQL and NoSQL injection",
    tags: ["sqli", "nosql", "sink"],
    patterns: [
      "\\.raw\\(|\\.extra\\(|RawSQL|text\\(f",
      "\\$queryRawUnsafe|knex\\.raw|fmt\\.Sprintf.*SELECT",
      "db\\.Query\\(fmt\\.Sprintf|execute\\([^,]+\\+",
      "\\$where|req\\.body.*\\$",
    ],
    guidance:
      "Find raw query APIs, dynamic identifiers, template literals/format strings, raw Mongo filters, and second-order injection paths.",
  },
  {
    id: "sink.deserialization",
    kind: "sink",
    title: "Unsafe deserialization",
    languages: [
      "python",
      "java",
      "kotlin",
      "typescript",
      "javascript",
      "php",
      "rust",
    ],
    tags: ["deserialization", "rce", "sink"],
    patterns: [
      "pickle\\.loads|cPickle|dill|shelve|marshal",
      "yaml\\.load\\(|yaml\\.full_load",
      "ObjectInputStream|readObject",
      "SnakeYAML|@JsonTypeInfo|enableDefaultTyping",
      "node-serialize|unserialize\\(",
      "bincode|rmp_serde",
    ],
    guidance:
      "Assume attacker-controlled object formats are high-risk. Verify reachable parser paths, gadget availability, and resource-exhaustion vectors.",
  },
  {
    id: "sink.ssrf-path-files",
    kind: "sink",
    title: "SSRF and filesystem access",
    tags: [
      "ssrf",
      "node",
      "javascript",
      "typescript",
      "path-traversal",
      "file-read",
      "file-write",
      "zip-slip",
      "sink",
    ],
    patterns: [
      "requests\\.(get|post)|urllib|http\\.Get|fetch\\(|axios\\.|got\\(",
      "open\\(|fs\\.readFile|fs\\.writeFile|path\\.join|os\\.path\\.join",
      "ZipFile|tarfile|archive|extractall|unzip",
    ],
    guidance:
      "Trace URL/file/archive inputs to network clients, redirects, metadata endpoints, path joins, upload destinations, and archive extraction.",
  },
  {
    id: "sink.template-xxe-xss",
    kind: "sink",
    title: "Template, XML, and client-side injection",
    tags: ["ssti", "xxe", "xss", "frontend", "sink"],
    patterns: [
      "render_template_string|Template\\(|compile\\(",
      "resolve_entities|XmlDocument|DocumentBuilderFactory|lxml",
      "dangerouslySetInnerHTML|innerHTML|outerHTML|document\\.write|v-html|\\[innerHTML\\]",
      "postMessage|Access-Control-Allow-Origin|Content-Security-Policy",
    ],
    guidance:
      "Check output context, parser configuration, origin checks, CORS/CSP, stored payload flows, SVG/Markdown/CSV renderers, and production source maps.",
  },
  {
    id: "sink.crypto-auth",
    kind: "sink",
    title: "Crypto, token, and auth bypass primitives",
    tags: ["crypto", "auth", "jwt", "secrets", "sink"],
    patterns: [
      "MD5|SHA1|ECB|Math\\.random|random\\.random|rand\\(",
      "verify\\s*=\\s*False|InsecureSkipVerify|rejectUnauthorized\\s*:\\s*false",
      "algorithm.*none|jwt\\.decode|kid|jku|x5u",
      "compare\\(|==.*token|==.*secret",
    ],
    guidance:
      "Review custom crypto, password hashing, token entropy, constant-time comparison, key storage, TLS verification, JWT algorithm confusion, and claim-use-before-signature verification.",
  },
  {
    id: "review.auth-session",
    kind: "review-pass",
    title: "Authentication and session review",
    tags: ["auth", "session", "oauth", "saml", "mfa"],
    guidance:
      "Read auth code end-to-end. Cover session cookies, JWTs, API keys, OAuth, SAML, mTLS, HMAC, password reset, registration, MFA, logout, and impersonation flows before hunting isolated bugs.",
  },
  {
    id: "review.authorization-business-logic",
    kind: "review-pass",
    title: "Authorization, tenancy, and business logic",
    tags: ["authz", "idor", "tenant", "business-logic", "graphql"],
    guidance:
      "Look for resource-level authz gaps, tenant context from request data, GraphQL field/mutation auth, mass assignment, state-machine skips, quota/payment/coupon races, webhook replay, and weak rate limits.",
  },
  {
    id: "review.parsers-uploads",
    kind: "review-pass",
    title: "Parsers, uploads, and output encoding",
    tags: ["parser", "upload", "encoding", "redos"],
    guidance:
      "Map JSON, XML, YAML, multipart, protobuf, MessagePack, CSV, Markdown, SVG, archive, image parser, Unicode normalization, double encoding, and ReDoS surfaces.",
  },
  {
    id: "review.storage-data",
    kind: "review-pass",
    title: "Storage, ORMs, and data layer",
    tags: ["orm", "storage", "cache", "search", "export"],
    guidance:
      "Review ORM raw APIs, dynamic identifiers, second-order injection, sensitive data at rest, CSV formula injection, cache poisoning/key collisions, and Elasticsearch/Lucene query injection.",
  },
  {
    id: "review.infra-supply-chain",
    kind: "review-pass",
    title: "Infrastructure, runtime, and supply chain",
    tags: ["iac", "docker", "kubernetes", "ci", "supply-chain"],
    guidance:
      "Review Docker root/secrets/latest tags, Kubernetes privileged/host/RBAC/network policy/service accounts, IaC public resources/IAM wildcards/encryption, GitHub Actions pull_request_target/unpinned actions/OIDC, reverse proxy normalization, debug/log leaks, dependency confusion, install scripts, vendored binaries, and image provenance.",
  },
  {
    id: "scanner.static",
    kind: "scanner",
    title: "Static analysis tools",
    tags: ["scanner", "sast"],
    tools: [
      "semgrep",
      "codeql",
      "bandit",
      "gosec",
      "cargo-geiger",
      "clippy",
      "brakeman",
      "spotbugs",
      "find-sec-bugs",
    ],
    guidance:
      "Run installed SAST tools opportunistically. Normalize results into candidates; verify exploitability before documenting findings.",
  },
  {
    id: "scanner.secrets-deps",
    kind: "scanner",
    title: "Secrets, dependency, and supply-chain scanners",
    tags: ["scanner", "secrets", "dependencies", "supply-chain"],
    tools: [
      "gitleaks",
      "trufflehog",
      "noseyparker",
      "osv-scanner",
      "trivy",
      "grype",
      "pip-audit",
      "npm",
      "govulncheck",
      "cargo-audit",
    ],
    guidance:
      "Run secrets and dependency scans with bounded output. Prefer direct dependencies and attack-path relevance over raw vulnerability counts.",
  },
  {
    id: "scanner.repo-intelligence",
    kind: "scanner",
    title: "Repo intelligence and history",
    tags: ["scanner", "git", "history", "code-query"],
    tools: ["rg", "ast-grep", "comby", "git"],
    guidance:
      "Use ripgrep, ast-grep, comby, git pickaxe, and git history on auth/crypto/session/admin/permission/tenant files to locate risky changes and incomplete fixes.",
  },
  {
    id: "fuzzer.runtime",
    kind: "fuzzer",
    title: "Runtime fuzzing and crash triage",
    languages: ["python", "go", "rust", "java", "kotlin", "c", "cpp"],
    tags: ["fuzzing", "rce", "memory-corruption", "parser"],
    tools: [
      "atheris",
      "cargo-fuzz",
      "go test -fuzz",
      "jazzer",
      "asan",
      "ubsan",
    ],
    guidance:
      "Generate harnesses in session scratch space, bound runtime, keep logs/crashes as artifacts, and minimize reproducers before promoting candidates.",
  },
];

export const DEFAULT_WHITEBOX_EXCLUDED_DIRS = [
  ".git",
  "node_modules",
  "vendor",
  "third_party",
  "dist",
  "build",
  "coverage",
  ".next",
  "target",
  "__pycache__",
];
