/**
 * Technology Knowledge Registry
 *
 * Central registry of all technology-specific knowledge.
 * Enables runtime lookup of testing techniques based on detected technologies.
 */

import type { TechKnowledge, Technique, VulnKnowledge, FingerprintResult } from './types';
import { EXPRESS_KNOWLEDGE } from './technologies/express';
import { GRAPHQL_KNOWLEDGE, GRAPHQL_INTROSPECTION_QUERIES } from './technologies/graphql';
import { JWT_KNOWLEDGE, JWT_UTILS } from './technologies/jwt';
import { DJANGO_KNOWLEDGE } from './technologies/django';
import { WORDPRESS_KNOWLEDGE, WORDPRESS_ENUM } from './technologies/wordpress';

/**
 * Main technology registry
 */
export const TECH_REGISTRY: Record<string, TechKnowledge> = {
  express: EXPRESS_KNOWLEDGE,
  nodejs: EXPRESS_KNOWLEDGE,  // Alias
  graphql: GRAPHQL_KNOWLEDGE,
  jwt: JWT_KNOWLEDGE,
  django: DJANGO_KNOWLEDGE,
  python: DJANGO_KNOWLEDGE,  // Alias (basic Python knowledge via Django)
  wordpress: WORDPRESS_KNOWLEDGE,
  wp: WORDPRESS_KNOWLEDGE,  // Alias
};

/**
 * Category mappings for related lookups
 */
export const CATEGORY_TECH: Record<string, string[]> = {
  framework: ['express', 'django'],
  api: ['graphql'],
  auth: ['jwt'],
  cms: ['wordpress'],
  database: [],  // Future: mongodb, postgresql, mysql
  server: [],    // Future: nginx, apache
};

/**
 * Common wordlists by technology and type
 */
export const WORDLISTS: Record<string, Record<string, string[]>> = {
  express: {
    endpoints: [
      '/api', '/api/v1', '/api/v2', '/api/users', '/api/auth', '/api/login',
      '/api/register', '/api/me', '/api/profile', '/api/admin', '/api/health',
      '/api/status', '/api/config', '/api/settings', '/api/debug', '/api/docs',
      '/health', '/healthcheck', '/status', '/metrics', '/debug', '/version',
      '/graphql', '/socket.io', '/ws', '/swagger', '/api-docs', '/openapi.json',
    ],
    params: [
      'id', 'user_id', 'userId', 'user', 'email', 'username', 'name',
      'password', 'token', 'api_key', 'apiKey', 'key', 'secret',
      'query', 'q', 'search', 'filter', 'sort', 'order', 'limit', 'offset',
      'page', 'per_page', 'perPage', 'callback', 'redirect', 'url', 'file',
    ],
    files: [
      'package.json', 'package-lock.json', '.env', '.env.local', '.env.development',
      '.env.production', 'config.json', 'config.js', 'settings.json', '.git/config',
      'node_modules/.package-lock.json', 'yarn.lock', '.npmrc', 'Dockerfile',
    ],
  },
  graphql: {
    endpoints: [
      '/graphql', '/graphiql', '/playground', '/altair', '/api/graphql',
      '/v1/graphql', '/v2/graphql', '/query', '/gql', '/graphql/console',
      '/graphql/playground', '/graphql-playground', '/__graphql',
    ],
    params: [],
    files: [],
  },
  django: {
    endpoints: [
      '/admin/', '/admin/login/', '/admin/logout/', '/api/', '/api/v1/',
      '/api/v2/', '/accounts/', '/accounts/login/', '/accounts/logout/',
      '/accounts/password/reset/', '/static/', '/media/', '/__debug__/',
      '/graphql/', '/health/', '/api/health/', '/api/schema/', '/api/docs/',
      '/rest-auth/', '/rest-auth/login/', '/rest-auth/logout/',
    ],
    params: [
      'pk', 'id', 'slug', 'username', 'email', 'password', 'token',
      'csrfmiddlewaretoken', 'next', 'page', 'limit', 'offset', 'ordering',
      'search', 'q', 'filter', 'format',
    ],
    files: [
      'settings.py', 'urls.py', 'requirements.txt', '.env', 'manage.py',
      'db.sqlite3', 'debug.log', '.git/config', 'Dockerfile', 'docker-compose.yml',
    ],
  },
  wordpress: {
    endpoints: [
      '/wp-admin/', '/wp-login.php', '/wp-content/', '/wp-includes/',
      '/wp-json/', '/wp-json/wp/v2/users', '/wp-json/wp/v2/posts',
      '/wp-json/wp/v2/pages', '/wp-json/wp/v2/media', '/xmlrpc.php',
      '/wp-cron.php', '/wp-trackback.php', '/wp-comments-post.php',
      '/?author=1', '/?rest_route=/wp/v2/users', '/feed/', '/feed/rss/',
      '/wp-content/uploads/', '/wp-content/plugins/', '/wp-content/themes/',
    ],
    params: [
      'author', 'p', 'page_id', 'cat', 'tag', 's', 'post_type',
      'action', 'log', 'pwd', 'redirect_to', 'testcookie',
    ],
    files: [
      '/wp-config.php', '/wp-config.php.bak', '/readme.html', '/license.txt',
      '/wp-content/debug.log', '/.htaccess', '/xmlrpc.php', '/wp-cron.php',
      '/wp-includes/version.php', '/wp-admin/install.php',
    ],
  },
  jwt: {
    endpoints: [
      '/api/auth/token', '/api/auth/refresh', '/api/auth/login',
      '/oauth/token', '/oauth/authorize', '/token', '/login',
      '/.well-known/jwks.json', '/.well-known/openid-configuration',
      '/api/auth/jwks', '/certs', '/keys',
    ],
    params: [
      'token', 'access_token', 'refresh_token', 'id_token', 'jwt',
      'authorization', 'bearer', 'grant_type', 'client_id', 'client_secret',
      'redirect_uri', 'scope', 'state', 'nonce',
    ],
    files: [
      '/.well-known/jwks.json', '/.well-known/openid-configuration',
      '/api/auth/jwks', '/oauth/.well-known/openid-configuration',
    ],
  },
  generic: {
    endpoints: [
      '/', '/api', '/api/v1', '/login', '/admin', '/dashboard',
      '/health', '/status', '/metrics', '/debug', '/config', '/settings',
      '/users', '/user', '/profile', '/account', '/auth', '/oauth',
      '/search', '/upload', '/download', '/export', '/import',
      '/.git/config', '/.env', '/robots.txt', '/sitemap.xml',
    ],
    params: [
      'id', 'user', 'username', 'email', 'password', 'token', 'key',
      'query', 'q', 'search', 'filter', 'sort', 'page', 'limit',
      'file', 'path', 'url', 'redirect', 'callback', 'return', 'next',
    ],
    files: [
      '/.git/config', '/.git/HEAD', '/.env', '/.env.local', '/config.json',
      '/package.json', '/composer.json', '/Gemfile', '/requirements.txt',
      '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/security.txt',
    ],
  },
};

/**
 * Get knowledge for a specific technology
 */
export function getTechKnowledge(tech: string): TechKnowledge | undefined {
  const normalizedTech = tech.toLowerCase().trim();
  return TECH_REGISTRY[normalizedTech];
}

/**
 * Get vulnerability-specific knowledge for a technology
 */
export function getVulnKnowledge(tech: string, vulnClass: string): VulnKnowledge | undefined {
  const techKnowledge = getTechKnowledge(tech);
  if (!techKnowledge?.vulns) return undefined;
  return techKnowledge.vulns[vulnClass.toLowerCase()];
}

/**
 * Get all techniques for a technology and optional vulnerability class
 */
export function getTechniques(tech: string, vulnClass?: string): Technique[] {
  const techKnowledge = getTechKnowledge(tech);
  if (!techKnowledge?.vulns) return [];

  if (vulnClass) {
    const vulnKnowledge = techKnowledge.vulns[vulnClass.toLowerCase()];
    return vulnKnowledge?.techniques || [];
  }

  // Return all techniques across all vuln classes
  const allTechniques: Technique[] = [];
  for (const vulnKey of Object.keys(techKnowledge.vulns)) {
    const vulnKnowledge = techKnowledge.vulns[vulnKey];
    if (vulnKnowledge?.techniques) {
      allTechniques.push(...vulnKnowledge.techniques);
    }
  }
  return allTechniques;
}

/**
 * Get payloads for a technology and vulnerability class
 */
export function getPayloads(tech: string, vulnClass: string): string[] {
  const vulnKnowledge = getVulnKnowledge(tech, vulnClass);
  return vulnKnowledge?.payloads || [];
}

/**
 * Get wordlist for a technology and type
 */
export function getWordlist(tech: string, type: 'endpoints' | 'params' | 'files'): string[] {
  const normalizedTech = tech.toLowerCase().trim();
  const techWordlists = WORDLISTS[normalizedTech] || WORDLISTS.generic;
  return techWordlists[type] || [];
}

/**
 * Get common endpoints for a technology
 */
export function getCommonEndpoints(tech: string): string[] {
  const techKnowledge = getTechKnowledge(tech);
  const techEndpoints = techKnowledge?.commonEndpoints || [];
  const wordlistEndpoints = getWordlist(tech, 'endpoints');

  // Combine and deduplicate
  return [...new Set([...techEndpoints, ...wordlistEndpoints])];
}

/**
 * Fingerprint a response to detect technologies
 */
export function fingerprintResponse(
  headers: Record<string, string>,
  cookies: string[],
  body: string,
  url: string
): FingerprintResult {
  const result: FingerprintResult = {
    technologies: [],
    confidence: {},
    rawSignals: {
      headers,
      cookies,
      bodyMatches: [],
      urlMatches: [],
    },
  };

  for (const [techId, techKnowledge] of Object.entries(TECH_REGISTRY)) {
    let confidence = 0;
    const fingerprints = techKnowledge.fingerprints;

    // Check headers
    if (fingerprints.headers) {
      for (const [headerName, pattern] of Object.entries(fingerprints.headers)) {
        const headerValue = headers[headerName.toLowerCase()];
        if (headerValue) {
          if (pattern instanceof RegExp) {
            if (pattern.test(headerValue)) confidence += 30;
          } else if (headerValue.includes(pattern)) {
            confidence += 30;
          }
        }
      }
    }

    // Check cookies
    if (fingerprints.cookies) {
      for (const cookiePattern of fingerprints.cookies) {
        if (cookies.some(c => c.includes(cookiePattern))) {
          confidence += 25;
          result.rawSignals.bodyMatches.push(`Cookie: ${cookiePattern}`);
        }
      }
    }

    // Check body patterns
    if (fingerprints.bodyPatterns) {
      for (const pattern of fingerprints.bodyPatterns) {
        if (pattern instanceof RegExp) {
          if (pattern.test(body)) {
            confidence += 20;
            result.rawSignals.bodyMatches.push(pattern.toString());
          }
        } else if (body.includes(pattern)) {
          confidence += 20;
          result.rawSignals.bodyMatches.push(pattern);
        }
      }
    }

    // Check URL patterns
    if (fingerprints.urlPatterns) {
      for (const pattern of fingerprints.urlPatterns) {
        if (pattern instanceof RegExp) {
          if (pattern.test(url)) {
            confidence += 25;
            result.rawSignals.urlMatches.push(pattern.toString());
          }
        } else if (url.includes(pattern)) {
          confidence += 25;
          result.rawSignals.urlMatches.push(pattern);
        }
      }
    }

    if (confidence > 0) {
      // Skip aliases (they share the same knowledge object)
      if (!result.technologies.includes(techId)) {
        result.technologies.push(techId);
        result.confidence[techId] = Math.min(confidence, 100);
      }
    }
  }

  // Sort by confidence
  result.technologies.sort((a, b) => (result.confidence[b] || 0) - (result.confidence[a] || 0));

  return result;
}

/**
 * List all available technologies
 */
export function listTechnologies(): string[] {
  return Object.keys(TECH_REGISTRY).filter(key => {
    // Filter out aliases
    const tech = TECH_REGISTRY[key];
    return tech.id === key;
  });
}

// Re-export utilities
export { GRAPHQL_INTROSPECTION_QUERIES } from './technologies/graphql';
export { JWT_UTILS } from './technologies/jwt';
export { WORDPRESS_ENUM } from './technologies/wordpress';
