/**
 * Knowledge System Types
 *
 * Type definitions for the dynamic knowledge lookup system.
 * Enables technology-specific testing techniques to be loaded at runtime.
 */

/**
 * A testing technique with context and examples
 */
export interface Technique {
  name: string;
  description: string;
  how: string;
  context: string;
  examples: string[];
  payloads?: string[];
  indicators?: {
    vulnerable: string[];
    notVulnerable: string[];
  };
}

/**
 * Authentication patterns for a technology
 */
export interface AuthPattern {
  type: string;  // e.g., "session", "jwt", "oauth"
  cookieName?: string;
  headerName?: string;
  loginEndpoint?: string;
  logoutEndpoint?: string;
  tokenFormat?: string;
  commonMisconfigs?: string[];
}

/**
 * Technology-specific vulnerability knowledge
 */
export interface VulnKnowledge {
  techniques: Technique[];
  payloads: string[];
  indicators: {
    vulnerable: string[];
    notVulnerable: string[];
  };
  adaptiveStrategy: string;
  references?: string[];
}

/**
 * Complete knowledge profile for a technology
 */
export interface TechKnowledge {
  /** Technology identifier */
  id: string;

  /** Human-readable name */
  name: string;

  /** Technology category */
  category: 'framework' | 'language' | 'server' | 'database' | 'auth' | 'api' | 'cms' | 'other';

  /** How to detect this technology */
  fingerprints: {
    headers?: Record<string, string | RegExp>;
    cookies?: string[];
    bodyPatterns?: (string | RegExp)[];
    urlPatterns?: (string | RegExp)[];
    errorPatterns?: (string | RegExp)[];
  };

  /** Authentication patterns */
  auth?: AuthPattern;

  /** Common endpoints for this technology */
  commonEndpoints?: string[];

  /** Vulnerability-specific knowledge (keyed by vuln class) */
  vulns?: {
    sqli?: VulnKnowledge;
    nosqli?: VulnKnowledge;
    xss?: VulnKnowledge;
    ssti?: VulnKnowledge;
    idor?: VulnKnowledge;
    ssrf?: VulnKnowledge;
    lfi?: VulnKnowledge;
    rce?: VulnKnowledge;
    auth_bypass?: VulnKnowledge;
    injection?: VulnKnowledge;  // Generic injection
    [key: string]: VulnKnowledge | undefined;
  };

  /** General testing notes */
  notes?: string[];

  /** Related technologies often seen together */
  relatedTech?: string[];
}

/**
 * Result from tech_lookup tool
 */
export interface TechLookupResult {
  success: boolean;
  tech: string;
  vulnClass?: string;
  knowledge?: {
    name: string;
    category?: string;
    techniques: Technique[];
    payloads: string[];
    commonEndpoints?: string[];
    auth?: AuthPattern;
    indicators?: {
      vulnerable: string[];
      notVulnerable: string[];
    };
    adaptiveStrategy?: string;
    notes?: string[];
    // Unified knowledge fields
    fingerprints?: TechKnowledge['fingerprints'];
    source?: 'cache' | 'nuclei' | 'local' | 'merged';
    nucleiTemplateCount?: number;
    vulnClasses?: string[];
  };
  error?: string;
  fromCache?: boolean;
}

/**
 * Result from wordlist_lookup tool
 */
export interface WordlistLookupResult {
  success: boolean;
  tech: string;
  type: 'endpoints' | 'params' | 'files' | 'dirs' | 'payloads';
  entries: string[];
  source?: string;
  error?: string;
}

/**
 * Fingerprint detection result
 */
export interface FingerprintResult {
  technologies: string[];
  confidence: Record<string, number>;  // tech -> confidence 0-100
  rawSignals: {
    headers: Record<string, string>;
    cookies: string[];
    bodyMatches: string[];
    urlMatches: string[];
  };
}
