/**
 * Knowledge System
 *
 * Provides dynamic, technology-specific testing knowledge.
 * Enables agents to load relevant techniques, payloads, and patterns at runtime.
 */

// Type exports
export type {
  Technique,
  AuthPattern,
  VulnKnowledge,
  TechKnowledge,
  TechLookupResult,
  WordlistLookupResult,
  FingerprintResult,
} from './types';

// Registry exports
export {
  TECH_REGISTRY,
  CATEGORY_TECH,
  WORDLISTS,
  getTechKnowledge,
  getVulnKnowledge,
  getTechniques,
  getPayloads,
  getWordlist,
  getCommonEndpoints,
  fingerprintResponse,
  listTechnologies,
} from './registry';

// Utility exports
export { GRAPHQL_INTROSPECTION_QUERIES, JWT_UTILS, WORDPRESS_ENUM } from './registry';

// Unified lookup system (with Nuclei fallback)
export {
  getUnifiedTechKnowledge,
  listAvailableTechnologies,
  listVulnClasses,
  type UnifiedTechKnowledge,
  type UnifiedLookupResult,
} from './unified';

// Cache exports
export { getKnowledgeCache, CacheKeys, type CacheConfig } from './cache';

// Individual technology exports (for direct access if needed)
export { EXPRESS_KNOWLEDGE } from './technologies/express';
export { GRAPHQL_KNOWLEDGE } from './technologies/graphql';
export { JWT_KNOWLEDGE } from './technologies/jwt';
export { DJANGO_KNOWLEDGE } from './technologies/django';
export { WORDPRESS_KNOWLEDGE } from './technologies/wordpress';
