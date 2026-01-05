/**
 * Unified Knowledge Lookup
 *
 * Provides a single entry point for tech-specific knowledge with fallback chain:
 * 1. Check disk cache
 * 2. Fetch from Nuclei API
 * 3. Fall back to local ATTACK_KNOWLEDGE
 * 4. Merge with local overlays (fingerprints, auth)
 */

import { getKnowledgeCache, CacheKeys } from './cache';
import { getTechKnowledge as getLocalTechKnowledge, listTechnologies } from './registry';
import type { TechKnowledge, Technique, VulnKnowledge } from './types';

export interface NucleiTemplate {
  id: string;
  name: string;
  severity: string;
  description?: string;
  tags?: string[];
  template_content?: string;
}

export interface UnifiedTechKnowledge {
  tech: string;
  name: string;
  category?: string;

  // From Nuclei or local
  techniques: Technique[];
  payloads: string[];
  indicators?: {
    vulnerable: string[];
    notVulnerable: string[];
  };
  adaptiveStrategy?: string;

  // From local overlays only
  fingerprints?: TechKnowledge['fingerprints'];
  auth?: TechKnowledge['auth'];
  commonEndpoints?: string[];
  notes?: string[];

  // Metadata
  source: 'cache' | 'nuclei' | 'local' | 'merged';
  nucleiTemplateCount?: number;
  vulnClasses?: string[];
}

export interface UnifiedLookupResult {
  success: boolean;
  knowledge?: UnifiedTechKnowledge;
  error?: string;
  fromCache?: boolean;
}

/**
 * Technology to Nuclei tag mapping
 * Maps our internal tech names to Nuclei template tags
 */
const TECH_TO_NUCLEI_TAGS: Record<string, string[]> = {
  express: ['express', 'nodejs', 'node'],
  nodejs: ['express', 'nodejs', 'node'],
  django: ['django', 'python'],
  python: ['django', 'python', 'flask'],
  graphql: ['graphql'],
  jwt: ['jwt', 'token'],
  wordpress: ['wordpress', 'wp'],
  wp: ['wordpress', 'wp'],
  laravel: ['laravel', 'php'],
  php: ['php'],
  spring: ['spring', 'java'],
  java: ['java', 'spring'],
  nginx: ['nginx'],
  apache: ['apache'],
  tomcat: ['tomcat'],
  rails: ['rails', 'ruby'],
};

/**
 * Vulnerability class to Nuclei tag mapping
 */
const VULN_TO_NUCLEI_TAGS: Record<string, string[]> = {
  sqli: ['sqli', 'sql-injection', 'injection'],
  xss: ['xss', 'cross-site-scripting'],
  rce: ['rce', 'remote-code-execution', 'command-injection'],
  lfi: ['lfi', 'local-file-inclusion', 'path-traversal'],
  ssrf: ['ssrf', 'server-side-request-forgery'],
  ssti: ['ssti', 'template-injection'],
  auth_bypass: ['auth-bypass', 'authentication-bypass', 'default-login'],
  idor: ['idor', 'broken-access-control'],
  nosqli: ['nosqli', 'nosql-injection'],
  xxe: ['xxe', 'xml-external-entity'],
  injection: ['injection'],
};

/**
 * Parse Nuclei template YAML to extract techniques
 */
function parseNucleiTemplate(template: NucleiTemplate): Technique | null {
  if (!template.template_content) {
    return {
      name: template.name,
      description: template.description || `${template.severity} severity vulnerability`,
      how: `Exploit using Nuclei template: ${template.id}`,
      context: template.tags?.join(', ') || 'Unknown context',
      examples: [],
      payloads: [],
    };
  }

  // Extract key information from YAML content
  const content = template.template_content;

  // Extract matchers (indicators of vulnerability)
  const matcherSection = content.match(/matchers:[\s\S]*?(?=\n[a-z]|\n-\s*name:|\Z)/);
  const matchers: string[] = [];
  if (matcherSection) {
    const wordsMatch = content.match(/words:\s*\n((?:\s*-\s*['"]?[^'"\n]+['"]?\s*\n?)+)/g);
    if (wordsMatch) {
      for (const match of wordsMatch) {
        const words = match.match(/-\s*['"]?([^'"\n]+)['"]?/g);
        if (words) {
          matchers.push(...words.map(w => w.replace(/^-\s*['"]?|['"]?$/g, '').trim()));
        }
      }
    }
  }

  // Extract payloads from raw or body sections
  const payloads: string[] = [];
  const rawMatch = content.match(/raw:\s*\n\s*-\s*\|[\s\S]*?(?=\n\s*-\s*\||matchers:|extractors:|\Z)/);
  if (rawMatch) {
    payloads.push(rawMatch[0].substring(0, 200) + '...'); // Truncate for readability
  }

  const bodyMatch = content.match(/body:\s*['"]?([^'"]+)['"]?/);
  if (bodyMatch) {
    payloads.push(bodyMatch[1]);
  }

  return {
    name: template.name,
    description: template.description || `${template.severity} severity vulnerability`,
    how: `Detected via template: ${template.id}`,
    context: `Tags: ${template.tags?.join(', ') || 'none'}`,
    examples: payloads.slice(0, 2),
    payloads: payloads,
    indicators: matchers.length > 0 ? {
      vulnerable: matchers.slice(0, 5),
      notVulnerable: [],
    } : undefined,
  };
}

/**
 * Fetch tech knowledge from Nuclei API
 */
async function fetchFromNuclei(
  tech: string,
  vulnClass?: string
): Promise<{ templates: NucleiTemplate[]; detectedTechs: string[] } | null> {
  const apiKey = process.env.DISCOVERY_API_KEY;
  if (!apiKey) {
    return null;
  }

  try {
    // Build query with tech tags
    const techTags = TECH_TO_NUCLEI_TAGS[tech.toLowerCase()] || [tech.toLowerCase()];
    let query = `tags:${techTags[0]}`;

    // Add vuln class filter if specified
    if (vulnClass) {
      const vulnTags = VULN_TO_NUCLEI_TAGS[vulnClass.toLowerCase()] || [vulnClass.toLowerCase()];
      query += ` tags:${vulnTags[0]}`;
    }

    const searchUrl = new URL('https://api.projectdiscovery.io/v2/template/search');
    searchUrl.searchParams.set('q', query);
    searchUrl.searchParams.set('limit', '20');
    searchUrl.searchParams.set('scope', 'public');

    const response = await fetch(searchUrl.toString(), {
      method: 'GET',
      headers: {
        'X-API-Key': apiKey,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json() as Record<string, any>;
    const results = (data.results || data.data || data.templates || []) as any[];

    const templates: NucleiTemplate[] = [];
    const detectedTechsSet = new Set<string>();
    const GITHUB_RAW_BASE = 'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main';

    for (const result of results) {
      const template: NucleiTemplate = {
        id: result.id || result.template_id || 'unknown',
        name: result.name || 'Unknown',
        severity: result.severity || 'unknown',
        description: result.description,
        tags: result.tags,
      };

      // Extract tech tags
      if (result.tags && Array.isArray(result.tags)) {
        for (const tag of result.tags) {
          const normalizedTag = tag.toLowerCase();
          if (Object.keys(TECH_TO_NUCLEI_TAGS).some(t =>
            TECH_TO_NUCLEI_TAGS[t].includes(normalizedTag)
          )) {
            detectedTechsSet.add(normalizedTag);
          }
        }
      }

      // Fetch template content
      if (result.raw) {
        template.template_content = result.raw;
      } else {
        const templatePath = result.uri || (result.dir && result.filename ? `${result.dir}/${result.filename}` : null);
        if (templatePath) {
          try {
            const githubUrl = `${GITHUB_RAW_BASE}/${templatePath}`;
            const templateResponse = await fetch(githubUrl);
            if (templateResponse.ok) {
              template.template_content = await templateResponse.text();
            }
          } catch {
            // Silently fail
          }
        }
      }

      templates.push(template);
    }

    return {
      templates,
      detectedTechs: Array.from(detectedTechsSet),
    };
  } catch {
    return null;
  }
}

/**
 * Unified tech knowledge lookup with fallback chain
 */
export async function getUnifiedTechKnowledge(
  tech: string,
  vulnClass?: string,
  options: { useCache?: boolean; fetchNuclei?: boolean } = {}
): Promise<UnifiedLookupResult> {
  const { useCache = true, fetchNuclei = true } = options;
  const cache = getKnowledgeCache();
  const cacheKey = CacheKeys.techKnowledge(`${tech}_${vulnClass || 'all'}`);

  // Step 1: Check disk cache
  if (useCache) {
    const cached = cache.get<UnifiedTechKnowledge>(cacheKey);
    if (cached) {
      return {
        success: true,
        knowledge: cached,
        fromCache: true,
      };
    }
  }

  // Step 2: Get local overlay (fingerprints, auth, common endpoints)
  const localKnowledge = getLocalTechKnowledge(tech);

  // Step 3: Try Nuclei API if available
  let nucleiTechniques: Technique[] = [];
  let nucleiPayloads: string[] = [];
  let nucleiIndicators: { vulnerable: string[]; notVulnerable: string[] } | undefined;
  let nucleiTemplateCount = 0;

  if (fetchNuclei) {
    const nucleiResult = await fetchFromNuclei(tech, vulnClass);
    if (nucleiResult && nucleiResult.templates.length > 0) {
      nucleiTemplateCount = nucleiResult.templates.length;

      for (const template of nucleiResult.templates) {
        const technique = parseNucleiTemplate(template);
        if (technique) {
          nucleiTechniques.push(technique);
          if (technique.payloads) {
            nucleiPayloads.push(...technique.payloads);
          }
          if (technique.indicators) {
            if (!nucleiIndicators) {
              nucleiIndicators = { vulnerable: [], notVulnerable: [] };
            }
            nucleiIndicators.vulnerable.push(...technique.indicators.vulnerable);
          }
        }
      }
    }
  }

  // Step 4: Build unified knowledge
  let unified: UnifiedTechKnowledge;

  if (localKnowledge) {
    // Merge local and Nuclei knowledge
    const localTechniques: Technique[] = [];
    const localPayloads: string[] = [];
    let localIndicators: { vulnerable: string[]; notVulnerable: string[] } | undefined;
    let localAdaptiveStrategy: string | undefined;
    const vulnClasses: string[] = [];

    if (localKnowledge.vulns) {
      for (const [vulnKey, vulnData] of Object.entries(localKnowledge.vulns)) {
        if (!vulnData) continue; // Skip undefined entries
        vulnClasses.push(vulnKey);
        if (!vulnClass || vulnKey.toLowerCase() === vulnClass?.toLowerCase()) {
          if (vulnData.techniques) {
            localTechniques.push(...vulnData.techniques);
          }
          if (vulnData.payloads) {
            localPayloads.push(...vulnData.payloads);
          }
          if (vulnData.indicators) {
            if (!localIndicators) {
              localIndicators = { vulnerable: [], notVulnerable: [] };
            }
            localIndicators.vulnerable.push(...(vulnData.indicators.vulnerable || []));
            localIndicators.notVulnerable.push(...(vulnData.indicators.notVulnerable || []));
          }
          if (vulnData.adaptiveStrategy) {
            localAdaptiveStrategy = vulnData.adaptiveStrategy;
          }
        }
      }
    }

    // Merge techniques (Nuclei first, then local)
    const allTechniques = [...nucleiTechniques, ...localTechniques];
    const allPayloads = [...new Set([...nucleiPayloads, ...localPayloads])];

    // Merge indicators
    let mergedIndicators: { vulnerable: string[]; notVulnerable: string[] } | undefined;
    if (nucleiIndicators || localIndicators) {
      mergedIndicators = {
        vulnerable: [...new Set([
          ...(nucleiIndicators?.vulnerable || []),
          ...(localIndicators?.vulnerable || []),
        ])],
        notVulnerable: [...new Set([
          ...(nucleiIndicators?.notVulnerable || []),
          ...(localIndicators?.notVulnerable || []),
        ])],
      };
    }

    unified = {
      tech,
      name: localKnowledge.name,
      category: localKnowledge.category,
      techniques: allTechniques,
      payloads: allPayloads,
      indicators: mergedIndicators,
      adaptiveStrategy: localAdaptiveStrategy,
      fingerprints: localKnowledge.fingerprints,
      auth: localKnowledge.auth,
      commonEndpoints: localKnowledge.commonEndpoints,
      notes: localKnowledge.notes,
      source: nucleiTemplateCount > 0 ? 'merged' : 'local',
      nucleiTemplateCount,
      vulnClasses,
    };
  } else if (nucleiTemplateCount > 0) {
    // Nuclei only (no local knowledge for this tech)
    unified = {
      tech,
      name: tech.charAt(0).toUpperCase() + tech.slice(1),
      techniques: nucleiTechniques,
      payloads: nucleiPayloads,
      indicators: nucleiIndicators,
      source: 'nuclei',
      nucleiTemplateCount,
    };
  } else {
    // No knowledge found
    const available = listTechnologies();
    return {
      success: false,
      error: `No knowledge found for '${tech}'. Try: ${available.join(', ')}. ` +
             `Nuclei API may not have templates tagged with '${tech}'.`,
    };
  }

  // Cache the result
  if (useCache) {
    cache.set(cacheKey, unified, { source: unified.source, ttl: 24 * 60 * 60 * 1000 });
  }

  return {
    success: true,
    knowledge: unified,
    fromCache: false,
  };
}

/**
 * List all available technologies (local + common Nuclei tags)
 */
export function listAvailableTechnologies(): string[] {
  const localTechs = listTechnologies();
  const nucleiTechs = Object.keys(TECH_TO_NUCLEI_TAGS).filter(t => !localTechs.includes(t));
  return [...localTechs, ...nucleiTechs];
}

/**
 * List available vulnerability classes
 */
export function listVulnClasses(): string[] {
  return Object.keys(VULN_TO_NUCLEI_TAGS);
}
