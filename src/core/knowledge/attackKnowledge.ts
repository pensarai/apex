/**
 * Attack Knowledge Schema & Store
 *
 * Structured schema for offensive security techniques and a
 * file-based store that loads from seed data + user-added techniques.
 */

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "fs";
import { join } from "path";
import { homedir } from "os";

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

export type AttackCategory =
  | "injection"
  | "auth_bypass"
  | "ssrf"
  | "deserialization"
  | "xss"
  | "api"
  | "business_logic"
  | "ai_llm"
  | "client_side"
  | "crypto"
  | "file_upload"
  | "race_condition"
  | "misconfiguration"
  | "other";

export interface PayloadVariant {
  payload: string;
  encoding: string; // "raw", "url-encoded", "double-encoded", "unicode"
  context: string; // "html-attribute", "sql-string", "json-body"
  notes: string;
}

export interface AttackTechnique {
  id: string; // e.g. "ssrf-dns-rebinding-bypass"
  title: string;
  category: AttackCategory;
  tags: string[]; // ["cloud", "aws", "metadata", "imds-v2"]
  applicability: {
    technologies: string[]; // ["node", "python-flask", "java-spring"]
    contexts: string[]; // ["api-endpoint", "file-upload", "url-parameter"]
    preconditions: string[]; // ["server-side-request", "no-egress-filter"]
  };
  technique: {
    summary: string; // 1-2 sentence overview
    steps: string[]; // ordered attack steps
    payloads: PayloadVariant[]; // concrete payloads with encoding variants
    bypassTechniques: string[]; // WAF/filter bypasses specific to this technique
  };
  references: string[]; // blog post URLs, CVEs, papers
  source: string; // "portswigger-research", "blog-xyz", "manual"
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

const USER_KNOWLEDGE_DIR = join(homedir(), ".apex", "knowledge", "techniques");
const SEED_DIR = join(__dirname, "seed", "techniques");

/**
 * Loads a single technique from a JSON file.
 * Returns null if the file is invalid.
 */
function loadTechnique(filePath: string): AttackTechnique | null {
  try {
    const raw = readFileSync(filePath, "utf-8");
    return JSON.parse(raw) as AttackTechnique;
  } catch {
    return null;
  }
}

/**
 * Loads all techniques from a directory, returning file paths alongside.
 */
function loadTechniquesFromDir(
  dir: string,
): { technique: AttackTechnique; filePath: string }[] {
  if (!existsSync(dir)) return [];

  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => {
      const filePath = join(dir, f);
      const technique = loadTechnique(filePath);
      return technique ? { technique, filePath } : null;
    })
    .filter(
      (t): t is { technique: AttackTechnique; filePath: string } => t !== null,
    );
}

/**
 * AttackKnowledgeStore loads techniques from:
 * 1. Bundled seed data (ships with the tool)
 * 2. User-level directory (~/.apex/knowledge/techniques/)
 *
 * User techniques override seed techniques with the same ID.
 */
/** A technique entry with its source file path. */
export interface StoredTechnique {
  technique: AttackTechnique;
  filePath: string;
}

/**
 * AttackKnowledgeStore loads techniques from:
 * 1. Bundled seed data (ships with the tool)
 * 2. User-level directory (~/.apex/knowledge/techniques/)
 *
 * User techniques override seed techniques with the same ID.
 */
export class AttackKnowledgeStore {
  private techniques: Map<string, StoredTechnique> = new Map();
  private loaded = false;

  /**
   * Loads all techniques from seed + user directories.
   * Idempotent — second call is a no-op unless force=true.
   */
  load(force = false): void {
    if (this.loaded && !force) return;

    this.techniques.clear();

    // Load seed first
    for (const { technique, filePath } of loadTechniquesFromDir(SEED_DIR)) {
      this.techniques.set(technique.id, { technique, filePath });
    }

    // User techniques override seed by ID
    for (const { technique, filePath } of loadTechniquesFromDir(
      USER_KNOWLEDGE_DIR,
    )) {
      this.techniques.set(technique.id, { technique, filePath });
    }

    this.loaded = true;
  }

  /**
   * Returns all loaded techniques.
   */
  getAll(): AttackTechnique[] {
    this.load();
    return Array.from(this.techniques.values()).map((s) => s.technique);
  }

  /**
   * Returns all stored entries (technique + file path).
   */
  getAllStored(): StoredTechnique[] {
    this.load();
    return Array.from(this.techniques.values());
  }

  /**
   * Returns a technique by ID or null.
   */
  getById(id: string): AttackTechnique | null {
    this.load();
    return this.techniques.get(id)?.technique ?? null;
  }

  /**
   * Returns the file path for a technique by ID, or null.
   */
  getFilePath(id: string): string | null {
    this.load();
    return this.techniques.get(id)?.filePath ?? null;
  }

  /**
   * Adds a technique to the user-level store. Persists to disk.
   */
  addTechnique(technique: AttackTechnique): void {
    if (!existsSync(USER_KNOWLEDGE_DIR)) {
      mkdirSync(USER_KNOWLEDGE_DIR, { recursive: true });
    }

    const filePath = join(USER_KNOWLEDGE_DIR, `${technique.id}.json`);
    writeFileSync(filePath, JSON.stringify(technique, null, 2));

    this.techniques.set(technique.id, { technique, filePath });
  }

  /**
   * Returns the count of loaded techniques.
   */
  get size(): number {
    this.load();
    return this.techniques.size;
  }
}

// Global singleton
let globalStore: AttackKnowledgeStore | null = null;

export function getAttackKnowledgeStore(): AttackKnowledgeStore {
  if (!globalStore) {
    globalStore = new AttackKnowledgeStore();
  }
  return globalStore;
}

export function resetAttackKnowledgeStore(): void {
  globalStore = null;
}
