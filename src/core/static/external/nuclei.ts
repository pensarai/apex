/**
 * Nuclei Template Integration
 *
 * Local management of Nuclei security templates for vulnerability enrichment.
 * Templates are cloned from GitHub and indexed locally - no API key required.
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { parse as parseYaml } from 'yaml';

const execAsync = promisify(exec);

// ============================================================================
// Configuration
// ============================================================================

const NUCLEI_TEMPLATES_URL = 'https://github.com/projectdiscovery/nuclei-templates.git';
const NUCLEI_CACHE_DIR = path.join(os.homedir(), '.pensar', 'static-cache', 'nuclei-templates');
const INDEX_FILE = path.join(NUCLEI_CACHE_DIR, 'index.json');
const INDEX_VERSION = '1.0.0';

// Directories in nuclei-templates that contain security-relevant templates
const TEMPLATE_DIRS = [
  'http/cves',
  'http/vulnerabilities',
  'http/misconfiguration',
  'http/exposures',
  'http/default-logins',
  'code',
  'javascript',
  'dast',
  'file',
  'network/cves',
  'network/vulnerabilities',
];

// ============================================================================
// Types
// ============================================================================

export interface NucleiTemplate {
  /** Template ID (e.g., "CVE-2021-41773") */
  id: string;
  /** Human-readable name */
  name: string;
  /** Severity level */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
  /** Tags for categorization */
  tags: string[];
  /** Associated CWE IDs */
  cwe?: string[];
  /** CVE IDs if applicable */
  cve?: string[];
  /** Template description */
  description?: string;
  /** Remediation guidance */
  remediation?: string;
  /** Reference URLs */
  references?: string[];
  /** Path to template file (relative to templates dir) */
  filePath: string;
  /** Author of the template */
  author?: string;
}

export interface NucleiIndex {
  /** Index format version */
  version: string;
  /** ISO timestamp of last update */
  updated_at: string;
  /** Git commit hash */
  commit: string;
  /** Total templates indexed */
  templates_count: number;
  /** Templates indexed by CWE ID */
  by_cwe: Record<string, string[]>;
  /** Templates indexed by tag */
  by_tag: Record<string, string[]>;
  /** Templates indexed by severity */
  by_severity: Record<string, string[]>;
  /** Full template metadata */
  templates: Record<string, NucleiTemplate>;
}

export interface NucleiSearchQuery {
  /** Search by CWE IDs (e.g., ["CWE-89", "CWE-79"]) */
  cwe?: string[];
  /** Search by tags (e.g., ["apache", "rce"]) */
  tags?: string[];
  /** Filter by severity levels */
  severity?: ('critical' | 'high' | 'medium' | 'low' | 'info')[];
  /** Full-text search in name/description */
  text?: string;
  /** Maximum results to return */
  limit?: number;
}

export interface NucleiSearchResult {
  /** Templates matching the query */
  templates: NucleiTemplate[];
  /** Total matches before limit */
  totalMatches: number;
  /** Query that was executed */
  query: NucleiSearchQuery;
}

// ============================================================================
// Template Management
// ============================================================================

/**
 * Check if Nuclei templates are cloned locally
 */
export async function templatesExist(): Promise<boolean> {
  try {
    await fs.access(path.join(NUCLEI_CACHE_DIR, '.git'));
    return true;
  } catch {
    return false;
  }
}

/**
 * Get the current commit hash of the templates
 */
export async function getCurrentCommit(): Promise<string | null> {
  try {
    const { stdout } = await execAsync('git rev-parse HEAD', {
      cwd: NUCLEI_CACHE_DIR,
    });
    return stdout.trim();
  } catch {
    return null;
  }
}

/**
 * Ensure Nuclei templates are cloned locally
 * Returns the path to the templates directory
 */
export async function ensureTemplatesCloned(): Promise<string> {
  const exists = await templatesExist();

  if (exists) {
    console.log('Nuclei templates already cloned');
    return NUCLEI_CACHE_DIR;
  }

  // Create cache directory
  await fs.mkdir(path.dirname(NUCLEI_CACHE_DIR), { recursive: true });

  console.log('Cloning Nuclei templates (this may take a few minutes)...');

  // Clone with depth 1 for faster initial clone
  await execAsync(
    `git clone --depth 1 ${NUCLEI_TEMPLATES_URL} "${NUCLEI_CACHE_DIR}"`,
    { timeout: 10 * 60 * 1000 } // 10 minute timeout
  );

  console.log('Nuclei templates cloned successfully');
  return NUCLEI_CACHE_DIR;
}

/**
 * Update Nuclei templates to latest version
 */
export async function updateTemplates(): Promise<{ updated: boolean; newCommit: string }> {
  const exists = await templatesExist();

  if (!exists) {
    await ensureTemplatesCloned();
    const commit = await getCurrentCommit();
    return { updated: true, newCommit: commit || 'unknown' };
  }

  const oldCommit = await getCurrentCommit();

  console.log('Updating Nuclei templates...');

  try {
    await execAsync('git fetch origin && git reset --hard origin/main', {
      cwd: NUCLEI_CACHE_DIR,
      timeout: 5 * 60 * 1000, // 5 minute timeout
    });
  } catch (error: any) {
    console.warn('Failed to update templates:', error.message);
    return { updated: false, newCommit: oldCommit || 'unknown' };
  }

  const newCommit = await getCurrentCommit();
  const updated = oldCommit !== newCommit;

  if (updated) {
    console.log(`Templates updated: ${oldCommit?.slice(0, 7)} → ${newCommit?.slice(0, 7)}`);
  } else {
    console.log('Templates already up to date');
  }

  return { updated, newCommit: newCommit || 'unknown' };
}

// ============================================================================
// Template Parsing
// ============================================================================

/**
 * Parse a single Nuclei template YAML file
 */
async function parseTemplate(filePath: string): Promise<NucleiTemplate | null> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const doc = parseYaml(content) as any;

    if (!doc || !doc.id || !doc.info) {
      return null;
    }

    const info = doc.info;
    const classification = info.classification || {};

    // Extract CWE IDs from various locations
    const cwes: string[] = [];
    if (classification['cwe-id']) {
      const cweIds = Array.isArray(classification['cwe-id'])
        ? classification['cwe-id']
        : [classification['cwe-id']];
      for (const cwe of cweIds) {
        const normalized = normalizeCWE(String(cwe));
        if (normalized) cwes.push(normalized);
      }
    }

    // Extract CVE IDs from tags
    const tags = Array.isArray(info.tags)
      ? info.tags
      : typeof info.tags === 'string'
        ? info.tags.split(',').map((t: string) => t.trim())
        : [];

    const cves = tags.filter((t: string) => /^cve-\d{4}-\d+$/i.test(t)).map((t: string) => t.toUpperCase());

    // Also check for CWE in tags
    for (const tag of tags) {
      if (/^cwe-\d+$/i.test(tag)) {
        const normalized = normalizeCWE(tag);
        if (normalized && !cwes.includes(normalized)) {
          cwes.push(normalized);
        }
      }
    }

    const relativePath = path.relative(NUCLEI_CACHE_DIR, filePath);

    return {
      id: doc.id,
      name: info.name || doc.id,
      severity: normalizeSeverity(info.severity),
      tags: tags.filter((t: string) => !/^cve-|^cwe-/i.test(t)),
      cwe: cwes.length > 0 ? cwes : undefined,
      cve: cves.length > 0 ? cves : undefined,
      description: info.description,
      remediation: info.remediation,
      references: Array.isArray(info.reference) ? info.reference : undefined,
      filePath: relativePath,
      author: info.author,
    };
  } catch {
    return null;
  }
}

/**
 * Normalize CWE ID to standard format (CWE-XXX)
 */
function normalizeCWE(cwe: string): string | null {
  const match = cwe.match(/(?:CWE-)?(\d+)/i);
  if (match) {
    return `CWE-${match[1]}`;
  }
  return null;
}

/**
 * Normalize severity to our standard levels
 */
function normalizeSeverity(severity: string | undefined): NucleiTemplate['severity'] {
  if (!severity) return 'unknown';
  const lower = severity.toLowerCase();
  if (lower === 'critical') return 'critical';
  if (lower === 'high') return 'high';
  if (lower === 'medium') return 'medium';
  if (lower === 'low') return 'low';
  if (lower === 'info' || lower === 'informational') return 'info';
  return 'unknown';
}

// ============================================================================
// Indexing
// ============================================================================

/**
 * Check if index exists and is valid
 */
export async function indexExists(): Promise<boolean> {
  try {
    await fs.access(INDEX_FILE);
    const content = await fs.readFile(INDEX_FILE, 'utf-8');
    const index = JSON.parse(content) as NucleiIndex;
    return index.version === INDEX_VERSION && index.templates_count > 0;
  } catch {
    return false;
  }
}

/**
 * Load the existing index
 */
export async function loadIndex(): Promise<NucleiIndex | null> {
  try {
    const content = await fs.readFile(INDEX_FILE, 'utf-8');
    return JSON.parse(content) as NucleiIndex;
  } catch {
    return null;
  }
}

/**
 * Build index of all Nuclei templates
 */
export async function indexTemplates(options?: { force?: boolean }): Promise<NucleiIndex> {
  // Check if we need to rebuild
  if (!options?.force) {
    const existing = await loadIndex();
    if (existing) {
      const currentCommit = await getCurrentCommit();
      if (existing.commit === currentCommit) {
        console.log('Index is up to date');
        return existing;
      }
    }
  }

  console.log('Building Nuclei template index...');

  const templates: Record<string, NucleiTemplate> = {};
  const byCwe: Record<string, string[]> = {};
  const byTag: Record<string, string[]> = {};
  const bySeverity: Record<string, string[]> = {};

  // Walk through template directories
  for (const dir of TEMPLATE_DIRS) {
    const fullDir = path.join(NUCLEI_CACHE_DIR, dir);

    try {
      await walkAndIndex(fullDir, templates, byCwe, byTag, bySeverity);
    } catch {
      // Directory may not exist, that's OK
    }
  }

  const commit = await getCurrentCommit();

  const index: NucleiIndex = {
    version: INDEX_VERSION,
    updated_at: new Date().toISOString(),
    commit: commit || 'unknown',
    templates_count: Object.keys(templates).length,
    by_cwe: byCwe,
    by_tag: byTag,
    by_severity: bySeverity,
    templates,
  };

  // Save index
  await fs.writeFile(INDEX_FILE, JSON.stringify(index, null, 2));

  console.log(`Indexed ${index.templates_count} templates`);
  return index;
}

/**
 * Recursively walk directory and index templates
 */
async function walkAndIndex(
  dir: string,
  templates: Record<string, NucleiTemplate>,
  byCwe: Record<string, string[]>,
  byTag: Record<string, string[]>,
  bySeverity: Record<string, string[]>
): Promise<void> {
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      await walkAndIndex(fullPath, templates, byCwe, byTag, bySeverity);
    } else if (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml')) {
      const template = await parseTemplate(fullPath);

      if (template) {
        templates[template.id] = template;

        // Index by CWE
        if (template.cwe) {
          for (const cwe of template.cwe) {
            if (!byCwe[cwe]) byCwe[cwe] = [];
            byCwe[cwe].push(template.id);
          }
        }

        // Index by tag
        for (const tag of template.tags) {
          const normalizedTag = tag.toLowerCase();
          if (!byTag[normalizedTag]) byTag[normalizedTag] = [];
          byTag[normalizedTag].push(template.id);
        }

        // Index by severity
        if (!bySeverity[template.severity]) bySeverity[template.severity] = [];
        bySeverity[template.severity].push(template.id);
      }
    }
  }
}

// ============================================================================
// Search
// ============================================================================

/**
 * Search Nuclei templates by various criteria
 */
export async function searchTemplates(query: NucleiSearchQuery): Promise<NucleiSearchResult> {
  const index = await loadIndex();

  if (!index) {
    // Try to build index if it doesn't exist
    await ensureTemplatesCloned();
    const newIndex = await indexTemplates();
    return searchWithIndex(newIndex, query);
  }

  return searchWithIndex(index, query);
}

/**
 * Search using a loaded index
 */
function searchWithIndex(index: NucleiIndex, query: NucleiSearchQuery): NucleiSearchResult {
  let candidateIds: Set<string> | null = null;

  // Filter by CWE
  if (query.cwe && query.cwe.length > 0) {
    const cweMatches = new Set<string>();
    for (const cwe of query.cwe) {
      const normalized = normalizeCWE(cwe);
      if (normalized && index.by_cwe[normalized]) {
        for (const id of index.by_cwe[normalized]) {
          cweMatches.add(id);
        }
      }
    }
    candidateIds = cweMatches;
  }

  // Filter by tags
  if (query.tags && query.tags.length > 0) {
    const tagMatches = new Set<string>();
    for (const tag of query.tags) {
      const normalizedTag = tag.toLowerCase();
      if (index.by_tag[normalizedTag]) {
        for (const id of index.by_tag[normalizedTag]) {
          tagMatches.add(id);
        }
      }
    }

    if (candidateIds) {
      // Intersection with existing candidates
      candidateIds = new Set([...candidateIds].filter(id => tagMatches.has(id)));
    } else {
      candidateIds = tagMatches;
    }
  }

  // Filter by severity
  if (query.severity && query.severity.length > 0) {
    const severityMatches = new Set<string>();
    for (const sev of query.severity) {
      if (index.by_severity[sev]) {
        for (const id of index.by_severity[sev]) {
          severityMatches.add(id);
        }
      }
    }

    if (candidateIds) {
      candidateIds = new Set([...candidateIds].filter(id => severityMatches.has(id)));
    } else {
      candidateIds = severityMatches;
    }
  }

  // If no filters specified, start with all templates
  if (!candidateIds) {
    candidateIds = new Set(Object.keys(index.templates));
  }

  // Convert to templates
  let results: NucleiTemplate[] = [];
  for (const id of candidateIds) {
    const template = index.templates[id];
    if (template) {
      results.push(template);
    }
  }

  // Text search filter
  if (query.text) {
    const searchText = query.text.toLowerCase();
    results = results.filter(t => {
      const searchable = [
        t.id,
        t.name,
        t.description || '',
        ...t.tags,
        ...(t.cwe || []),
        ...(t.cve || []),
      ].join(' ').toLowerCase();

      return searchable.includes(searchText);
    });
  }

  // Sort by severity (critical first)
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
    unknown: 5,
  };

  results.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const totalMatches = results.length;

  // Apply limit
  if (query.limit && query.limit > 0) {
    results = results.slice(0, query.limit);
  }

  return {
    templates: results,
    totalMatches,
    query,
  };
}

/**
 * Get a specific template by ID
 */
export async function getTemplate(templateId: string): Promise<NucleiTemplate | null> {
  const index = await loadIndex();
  if (!index) return null;

  return index.templates[templateId] || null;
}

/**
 * Read the full content of a template file
 */
export async function getTemplateContent(template: NucleiTemplate): Promise<string | null> {
  try {
    const fullPath = path.join(NUCLEI_CACHE_DIR, template.filePath);
    return await fs.readFile(fullPath, 'utf-8');
  } catch {
    return null;
  }
}

/**
 * Get templates related to specific CVEs
 */
export async function getTemplatesByCVE(cveIds: string[]): Promise<NucleiTemplate[]> {
  const index = await loadIndex();
  if (!index) return [];

  const results: NucleiTemplate[] = [];
  const normalizedCves = cveIds.map(c => c.toUpperCase());

  for (const template of Object.values(index.templates)) {
    if (template.cve && template.cve.some(c => normalizedCves.includes(c))) {
      results.push(template);
    }
  }

  return results;
}

/**
 * Get summary statistics about the template index
 */
export async function getIndexStats(): Promise<{
  total: number;
  bySeverity: Record<string, number>;
  topCwes: Array<{ cwe: string; count: number }>;
  topTags: Array<{ tag: string; count: number }>;
} | null> {
  const index = await loadIndex();
  if (!index) return null;

  const bySeverity: Record<string, number> = {};
  for (const [sev, ids] of Object.entries(index.by_severity)) {
    bySeverity[sev] = ids.length;
  }

  const cweEntries = Object.entries(index.by_cwe)
    .map(([cwe, ids]) => ({ cwe, count: ids.length }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  const tagEntries = Object.entries(index.by_tag)
    .map(([tag, ids]) => ({ tag, count: ids.length }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  return {
    total: index.templates_count,
    bySeverity,
    topCwes: cweEntries,
    topTags: tagEntries,
  };
}

// ============================================================================
// Initialization Helper
// ============================================================================

/**
 * Initialize Nuclei templates: clone if needed, update, and build index
 */
export async function initializeNucleiTemplates(options?: {
  skipUpdate?: boolean;
  forceReindex?: boolean;
}): Promise<NucleiIndex> {
  await ensureTemplatesCloned();

  if (!options?.skipUpdate) {
    await updateTemplates();
  }

  return await indexTemplates({ force: options?.forceReindex });
}
