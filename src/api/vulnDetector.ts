/**
 * Vulnerability Class Detector
 *
 * Analyzes source code to automatically detect relevant vulnerability classes
 * for whitebox penetration testing.
 */

import { spawn } from "child_process";
import type { VulnerabilityClass } from "../core/agent/subagent/types";

/**
 * Pattern definition for detecting vulnerability classes
 */
interface VulnPattern {
  /** Regex pattern to search for */
  pattern: string;
  /** File glob pattern to search in */
  fileGlob?: string;
  /** Weight for this pattern (higher = more confident) */
  weight: number;
}

/**
 * Patterns for detecting each vulnerability class
 */
const VULN_PATTERNS: Record<VulnerabilityClass, VulnPattern[]> = {
  sql_injection: [
    { pattern: "\\b(query|execute|raw|exec)\\s*\\(", weight: 3 },
    { pattern: "SELECT\\s+.*\\s+FROM", weight: 2 },
    { pattern: "INSERT\\s+INTO", weight: 2 },
    { pattern: "UPDATE\\s+.*\\s+SET", weight: 2 },
    { pattern: "DELETE\\s+FROM", weight: 2 },
    { pattern: "\\$\\{.*\\}.*(?:SELECT|INSERT|UPDATE|DELETE)", weight: 4 },
    { pattern: "\\+\\s*['\"]\\s*(?:SELECT|INSERT|UPDATE|DELETE)", weight: 4 },
    { pattern: "sequelize|typeorm|prisma|knex|pg|mysql2?|sqlite", weight: 1 },
  ],
  nosql_injection: [
    { pattern: "\\.(find|findOne|aggregate|update)\\s*\\(", weight: 2 },
    { pattern: "mongodb|mongoose|dynamodb", weight: 1 },
    { pattern: "\\$where|\\$regex|\\$gt|\\$lt|\\$ne", weight: 3 },
  ],
  xss: [
    { pattern: "innerHTML|outerHTML|document\\.write", weight: 3 },
    { pattern: "dangerouslySetInnerHTML", weight: 4 },
    { pattern: "v-html|\\[innerHTML\\]", weight: 3 },
    { pattern: "<%=.*%>|\\{\\{\\{.*\\}\\}\\}", weight: 2 },
    { pattern: "res\\.(send|render|write)\\s*\\(", weight: 1 },
  ],
  command_injection: [
    { pattern: "child_process|exec|spawn|execSync|spawnSync", weight: 3 },
    { pattern: "\\bexec\\s*\\(|\\beval\\s*\\(", weight: 4 },
    { pattern: "subprocess|os\\.system|os\\.popen", weight: 3, fileGlob: "*.py" },
    { pattern: "shell_exec|system|passthru|proc_open", weight: 3, fileGlob: "*.php" },
    { pattern: "Runtime\\.getRuntime\\(\\)\\.exec", weight: 3, fileGlob: "*.java" },
    { pattern: "`.*\\$\\{.*\\}`", weight: 4 },
  ],
  ssti: [
    { pattern: "render_template|jinja|nunjucks|ejs|pug|handlebars", weight: 2 },
    { pattern: "template\\.render|env\\.from_string", weight: 3 },
    { pattern: "\\{\\{.*\\}\\}|\\{%.*%\\}", weight: 1 },
    { pattern: "Velocity|FreeMarker|Thymeleaf", weight: 2, fileGlob: "*.java" },
    { pattern: "Twig|Blade|Smarty", weight: 2, fileGlob: "*.php" },
  ],
  path_traversal: [
    { pattern: "fs\\.(read|write|access|stat|unlink)", weight: 2 },
    { pattern: "path\\.join|path\\.resolve", weight: 1 },
    { pattern: "open\\s*\\(|file\\s*\\(|fopen", weight: 2 },
    { pattern: "sendFile|download|readFile", weight: 3 },
    { pattern: "\\.\\./|\\.\\.\\\\", weight: 4 },
    { pattern: "include|require|include_once|require_once", weight: 2, fileGlob: "*.php" },
  ],
  ssrf: [
    { pattern: "fetch\\s*\\(|axios\\.|request\\(|urllib|requests\\.", weight: 2 },
    { pattern: "http\\.get|https\\.get|http\\.request", weight: 2 },
    { pattern: "curl_exec|file_get_contents.*http", weight: 3, fileGlob: "*.php" },
    { pattern: "URL\\s*\\(|HttpClient|RestTemplate", weight: 2, fileGlob: "*.java" },
    { pattern: "redirect|proxy|forward|url=|uri=|path=", weight: 1 },
  ],
  idor: [
    { pattern: "params\\.(id|userId|user_id|accountId)", weight: 2 },
    { pattern: "req\\.params\\.|req\\.query\\.|req\\.body\\.", weight: 1 },
    { pattern: "/users?/:\\w+|/accounts?/:\\w+|/orders?/:\\w+", weight: 2 },
    { pattern: "findById|getById|findOne.*id", weight: 2 },
  ],
  authentication_bypass: [
    { pattern: "passport|jwt|jsonwebtoken|bcrypt|auth", weight: 1 },
    { pattern: "login|logout|register|authenticate|session", weight: 1 },
    { pattern: "isAuthenticated|isLoggedIn|requireAuth", weight: 2 },
    { pattern: "compareSync|compare\\s*\\(.*password", weight: 2 },
    { pattern: "verify\\s*\\(.*token|decode\\s*\\(.*token", weight: 2 },
  ],
  jwt_vulnerabilities: [
    { pattern: "jsonwebtoken|jose|jwt-decode|pyjwt", weight: 3 },
    { pattern: "jwt\\.sign|jwt\\.verify|jwt\\.decode", weight: 4 },
    { pattern: "algorithm.*none|alg.*none", weight: 5 },
    { pattern: "HS256|RS256|ES256", weight: 2 },
  ],
  deserialization: [
    { pattern: "serialize|unserialize|pickle|yaml\\.load", weight: 3 },
    { pattern: "JSON\\.parse|eval\\s*\\(.*JSON", weight: 2 },
    { pattern: "ObjectInputStream|readObject", weight: 4, fileGlob: "*.java" },
    { pattern: "Marshal\\.load|YAML\\.load", weight: 3, fileGlob: "*.rb" },
    { pattern: "__reduce__|__getstate__|__setstate__", weight: 4, fileGlob: "*.py" },
  ],
  xxe: [
    { pattern: "xml|DOMParser|XMLParser|parseXML", weight: 2 },
    { pattern: "libxml|lxml|xml\\.etree|xml\\.dom", weight: 2 },
    { pattern: "DocumentBuilder|SAXParser|XMLReader", weight: 2, fileGlob: "*.java" },
    { pattern: "<!ENTITY|SYSTEM|PUBLIC", weight: 4 },
    { pattern: "simplexml_load|DOMDocument", weight: 2, fileGlob: "*.php" },
  ],
  crypto: [
    { pattern: "crypto|bcrypt|argon2|scrypt|pbkdf2", weight: 1 },
    { pattern: "MD5|SHA1|sha1|md5", weight: 3 },
    { pattern: "DES|RC4|ECB", weight: 4 },
    { pattern: "createCipher|createDecipher", weight: 2 },
    { pattern: "Math\\.random|random\\(\\)", weight: 3 },
  ],
  business_logic: [
    { pattern: "price|amount|total|discount|quantity", weight: 1 },
    { pattern: "transfer|withdraw|deposit|balance", weight: 2 },
    { pattern: "admin|role|permission|privilege", weight: 1 },
    { pattern: "coupon|promo|voucher|credit", weight: 2 },
  ],
  generic: [],
};

/**
 * Always include these vulnerability classes regardless of detection
 */
const ALWAYS_INCLUDE: VulnerabilityClass[] = ["xss", "idor"];

/**
 * Result of vulnerability class detection
 */
export interface DetectedVulnerabilities {
  /** Detected vulnerability classes */
  classes: VulnerabilityClass[];
  /** Evidence for each detected class (file paths with matching patterns) */
  evidence: Partial<Record<VulnerabilityClass, string[]>>;
  /** Confidence scores for each class (0-100) */
  confidence: Partial<Record<VulnerabilityClass, number>>;
}

/**
 * Run ripgrep to search for a pattern in the source code
 */
async function searchPattern(
  sourceCodePath: string,
  pattern: string,
  fileGlob?: string
): Promise<string[]> {
  return new Promise((resolve) => {
    const args = [
      "--files-with-matches",
      "--no-heading",
      "-i", // case insensitive
      pattern,
      sourceCodePath,
    ];

    if (fileGlob) {
      args.splice(1, 0, "-g", fileGlob);
    }

    const proc = spawn("rg", args, {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.on("close", () => {
      const files = stdout
        .split("\n")
        .map((f) => f.trim())
        .filter((f) => f.length > 0);
      resolve(files);
    });

    proc.on("error", () => {
      resolve([]);
    });

    // Timeout after 10 seconds per pattern
    setTimeout(() => {
      proc.kill("SIGTERM");
      resolve([]);
    }, 10000);
  });
}

/**
 * Detect vulnerability classes by analyzing source code
 *
 * @param sourceCodePath - Absolute path to source code directory
 * @param endpoint - Optional endpoint URL to help contextualize detection
 * @returns Detected vulnerability classes with evidence
 */
export async function detectVulnerabilityClasses(
  sourceCodePath: string,
  endpoint?: string
): Promise<DetectedVulnerabilities> {
  const evidence: Partial<Record<VulnerabilityClass, string[]>> = {};
  const scores: Partial<Record<VulnerabilityClass, number>> = {};

  // Search for patterns in parallel for each vulnerability class
  const searchPromises: Promise<void>[] = [];

  for (const [vulnClass, patterns] of Object.entries(VULN_PATTERNS)) {
    if (patterns.length === 0) continue;

    const classPromise = (async () => {
      let totalScore = 0;
      const matchedFiles = new Set<string>();

      for (const { pattern, fileGlob, weight } of patterns) {
        const files = await searchPattern(sourceCodePath, pattern, fileGlob);
        if (files.length > 0) {
          totalScore += weight * Math.min(files.length, 5); // Cap file count impact
          files.forEach((f) => matchedFiles.add(f));
        }
      }

      if (matchedFiles.size > 0) {
        evidence[vulnClass as VulnerabilityClass] = Array.from(matchedFiles).slice(0, 10);
        scores[vulnClass as VulnerabilityClass] = Math.min(totalScore * 10, 100);
      }
    })();

    searchPromises.push(classPromise);
  }

  await Promise.all(searchPromises);

  // Build the final list of detected classes
  const detectedClasses = new Set<VulnerabilityClass>();

  // Add classes with evidence
  for (const [vulnClass, score] of Object.entries(scores)) {
    if (score && score >= 10) {
      detectedClasses.add(vulnClass as VulnerabilityClass);
    }
  }

  // Always include baseline classes
  for (const baselineClass of ALWAYS_INCLUDE) {
    detectedClasses.add(baselineClass);
  }

  // If endpoint URL suggests specific patterns, add relevant classes
  if (endpoint) {
    const lowerEndpoint = endpoint.toLowerCase();
    if (
      lowerEndpoint.includes("login") ||
      lowerEndpoint.includes("auth") ||
      lowerEndpoint.includes("session")
    ) {
      detectedClasses.add("authentication_bypass");
      detectedClasses.add("sql_injection");
    }
    if (lowerEndpoint.includes("file") || lowerEndpoint.includes("download")) {
      detectedClasses.add("path_traversal");
    }
    if (lowerEndpoint.includes("api")) {
      detectedClasses.add("jwt_vulnerabilities");
    }
    if (
      lowerEndpoint.includes("user") ||
      lowerEndpoint.includes("account") ||
      lowerEndpoint.includes("order")
    ) {
      detectedClasses.add("idor");
    }
    if (lowerEndpoint.includes("search") || lowerEndpoint.includes("query")) {
      detectedClasses.add("sql_injection");
    }
  }

  // Sort by confidence score
  const sortedClasses = Array.from(detectedClasses).sort((a, b) => {
    return (scores[b] || 0) - (scores[a] || 0);
  });

  return {
    classes: sortedClasses,
    evidence,
    confidence: scores,
  };
}

/**
 * Get a human-readable summary of detected vulnerabilities
 */
export function formatDetectionSummary(detected: DetectedVulnerabilities): string {
  const lines: string[] = [
    `Detected ${detected.classes.length} vulnerability classes for testing:`,
    "",
  ];

  for (const vulnClass of detected.classes) {
    const confidence = detected.confidence[vulnClass];
    const evidenceFiles = detected.evidence[vulnClass];

    let line = `  - ${vulnClass}`;
    if (confidence) {
      line += ` (confidence: ${confidence}%)`;
    }
    lines.push(line);

    if (evidenceFiles && evidenceFiles.length > 0) {
      const shortFiles = evidenceFiles.slice(0, 3).map((f) => `    ${f}`);
      lines.push(...shortFiles);
      if (evidenceFiles.length > 3) {
        lines.push(`    ... and ${evidenceFiles.length - 3} more files`);
      }
    }
  }

  return lines.join("\n");
}
