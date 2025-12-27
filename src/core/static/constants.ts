/**
 * Shared Constants for Static Analysis
 *
 * Single source of truth for constants used across multiple agents and tools.
 * This prevents DRY violations and ensures consistency.
 */

// ============================================================================
// Directory Exclusion Patterns
// ============================================================================

/**
 * Directories to exclude from scanning
 * Used by: index-graph, repo-tools, file-utils
 */
export const EXCLUDE_DIRS = new Set([
  // Package managers
  'node_modules',
  'vendor',
  'venv',
  '.venv',
  '__pycache__',
  'packages',

  // Version control
  '.git',
  '.svn',
  '.hg',

  // Build outputs
  'dist',
  'build',
  'target',
  'out',
  'bin',
  'obj',

  // IDE/Editor
  '.idea',
  '.vscode',
  '.vs',

  // Test/Coverage
  'coverage',
  '.nyc_output',
  'test-results',

  // Temp/Misc
  'tmp',
  'temp',
  'logs',
  '.cache',
]);

// ============================================================================
// Language Extensions Mapping
// ============================================================================

/**
 * Maps programming languages to their file extensions
 * Used by: index-graph, repo-tools, detect_languages
 */
export const LANGUAGE_EXTENSIONS: Record<string, string[]> = {
  python: ['.py', '.pyw', '.pyi'],
  javascript: ['.js', '.mjs', '.cjs', '.jsx'],
  typescript: ['.ts', '.tsx', '.mts', '.cts'],
  java: ['.java'],
  kotlin: ['.kt', '.kts'],
  go: ['.go'],
  rust: ['.rs'],
  ruby: ['.rb', '.rake', '.gemspec'],
  php: ['.php', '.phtml'],
  csharp: ['.cs'],
  cpp: ['.cpp', '.cc', '.cxx', '.hpp', '.h', '.hxx'],
  c: ['.c'],
  swift: ['.swift'],
  scala: ['.scala', '.sc'],
  shell: ['.sh', '.bash', '.zsh'],
  sql: ['.sql'],
  html: ['.html', '.htm'],
  css: ['.css', '.scss', '.sass', '.less'],
  yaml: ['.yaml', '.yml'],
  json: ['.json'],
  xml: ['.xml'],
  markdown: ['.md', '.markdown'],
};

/**
 * Get all code file extensions (excludes data/config formats)
 */
export const CODE_EXTENSIONS = [
  '.py', '.pyw', '.pyi',
  '.js', '.mjs', '.cjs', '.jsx',
  '.ts', '.tsx', '.mts', '.cts',
  '.java', '.kt', '.kts',
  '.go', '.rs',
  '.rb', '.rake',
  '.php', '.phtml',
  '.cs',
  '.cpp', '.cc', '.cxx', '.c', '.h', '.hpp', '.hxx',
  '.swift', '.scala', '.sc',
  '.sh', '.bash', '.zsh',
];

/**
 * Get language from file extension
 */
export function getLanguageFromExtension(ext: string): string | null {
  const extLower = ext.toLowerCase();
  for (const [lang, exts] of Object.entries(LANGUAGE_EXTENSIONS)) {
    if (exts.includes(extLower)) return lang;
  }
  return null;
}

// ============================================================================
// Security Patterns
// ============================================================================

export interface SecurityPattern {
  pattern: RegExp;
  reason: string;
  category: string;
}

/**
 * Patterns to identify security-sensitive code
 * Used by: repo-tools (hotspot detection), index-graph (function tagging)
 */
export const SECURITY_PATTERNS: SecurityPattern[] = [
  // Authentication & Session
  { pattern: /\b(login|logout|authenticate|verify_password|check_auth|is_authenticated)\b/i, reason: 'authentication', category: 'authn' },
  { pattern: /\b(jwt|token|session|cookie|bearer)\b/i, reason: 'session management', category: 'authn' },

  // Authorization
  { pattern: /\b(authorize|is_admin|has_permission|check_role|can_access|rbac|acl)\b/i, reason: 'authorization', category: 'authz' },

  // Credentials
  { pattern: /\b(password|credential|secret|api_key|private_key)\b/i, reason: 'credential handling', category: 'secrets' },

  // Cryptography
  { pattern: /\b(encrypt|decrypt|hash|hmac|sign|verify_signature)\b/i, reason: 'cryptography', category: 'crypto' },
  { pattern: /\b(aes|rsa|sha256|sha512|bcrypt|argon2|pbkdf2)\b/i, reason: 'crypto algorithm', category: 'crypto' },

  // Injection Sinks
  { pattern: /\b(execute|query|raw_query|exec|eval|system|popen|subprocess|spawn|shell)\b/i, reason: 'command/query execution', category: 'injection' },
  { pattern: /\b(cursor\.execute|prepare|createStatement)\b/i, reason: 'SQL execution', category: 'injection' },

  // Deserialization
  { pattern: /\b(pickle|marshal|yaml\.load|deserialize|unserialize|readObject|fromJson)\b/i, reason: 'deserialization', category: 'deserialize' },

  // File Operations
  { pattern: /\b(read_file|write_file|open|upload|download|save_file|file_get_contents)\b/i, reason: 'file operations', category: 'file' },
  { pattern: /\b(path_join|resolve_path|get_path|realpath|normpath)\b/i, reason: 'path handling', category: 'file' },

  // Network
  { pattern: /\b(request|fetch|http_get|http_post|curl|wget|axios)\b/i, reason: 'network requests', category: 'network' },
  { pattern: /\b(redirect|forward|proxy|ssrf)\b/i, reason: 'request routing', category: 'network' },

  // Templating (SSTI risk)
  { pattern: /\b(render|template|jinja|mustache|handlebars|ejs|pug)\b/i, reason: 'templating', category: 'template' },
  { pattern: /\b(format_string|f-string|string\.format)\b/i, reason: 'string formatting', category: 'template' },

  // XML (XXE risk)
  { pattern: /\b(xml|parse|dom|sax|xpath|xslt|etree)\b/i, reason: 'XML parsing', category: 'xml' },
];

/**
 * Group security patterns by category
 */
export function getSecurityPatternsByCategory(): Record<string, SecurityPattern[]> {
  const grouped: Record<string, SecurityPattern[]> = {};
  for (const pattern of SECURITY_PATTERNS) {
    if (!grouped[pattern.category]) {
      grouped[pattern.category] = [];
    }
    grouped[pattern.category].push(pattern);
  }
  return grouped;
}

/**
 * Check if a string matches any security pattern
 * Returns the first matching pattern's reason, or null if no match
 */
export function matchSecurityPattern(text: string): { reason: string; category: string } | null {
  for (const { pattern, reason, category } of SECURITY_PATTERNS) {
    if (pattern.test(text)) {
      return { reason, category };
    }
  }
  return null;
}

// ============================================================================
// Build System Detection
// ============================================================================

export interface BuildSystemIndicator {
  buildSystem: string;
  isDependencyFile: boolean;
}

/**
 * Maps filenames to build systems
 */
export const BUILD_SYSTEM_INDICATORS: Record<string, BuildSystemIndicator> = {
  'package.json': { buildSystem: 'npm/yarn', isDependencyFile: true },
  'package-lock.json': { buildSystem: 'npm', isDependencyFile: false },
  'yarn.lock': { buildSystem: 'yarn', isDependencyFile: false },
  'pnpm-lock.yaml': { buildSystem: 'pnpm', isDependencyFile: false },
  'requirements.txt': { buildSystem: 'pip', isDependencyFile: true },
  'setup.py': { buildSystem: 'setuptools', isDependencyFile: true },
  'pyproject.toml': { buildSystem: 'poetry/pip', isDependencyFile: true },
  'Pipfile': { buildSystem: 'pipenv', isDependencyFile: true },
  'go.mod': { buildSystem: 'go modules', isDependencyFile: true },
  'Cargo.toml': { buildSystem: 'cargo', isDependencyFile: true },
  'pom.xml': { buildSystem: 'maven', isDependencyFile: true },
  'build.gradle': { buildSystem: 'gradle', isDependencyFile: true },
  'build.gradle.kts': { buildSystem: 'gradle', isDependencyFile: true },
  'Gemfile': { buildSystem: 'bundler', isDependencyFile: true },
  'composer.json': { buildSystem: 'composer', isDependencyFile: true },
  'CMakeLists.txt': { buildSystem: 'cmake', isDependencyFile: false },
  'Makefile': { buildSystem: 'make', isDependencyFile: false },
  'Dockerfile': { buildSystem: 'docker', isDependencyFile: false },
  'docker-compose.yml': { buildSystem: 'docker-compose', isDependencyFile: false },
};

// ============================================================================
// Limits & Thresholds
// ============================================================================

export const LIMITS = {
  /** Maximum directory depth for recursive scanning */
  MAX_DEPTH: 20,

  /** Maximum files to scan before stopping */
  MAX_FILES: 5000,

  /** Maximum file size to read into memory (1MB) */
  MAX_FILE_SIZE: 1_000_000,

  /** Maximum file size for content searching (100KB) */
  MAX_SEARCHABLE_SIZE: 100_000,

  /** Maximum results for search operations */
  MAX_SEARCH_RESULTS: 100,

  /** Maximum line length before truncation */
  MAX_LINE_LENGTH: 200,
};
