// Braintrust Data Sanitization
//
// Provides utilities for scrubbing sensitive data from tool inputs/outputs before
// sending to Braintrust. Uses semantic placeholders to preserve structure and context.
//
// Strategy:
// - Uses typed tokens like <JWT_TOKEN>, <API_KEY>, <EMAIL> instead of generic [REDACTED]
// - Compiles regex patterns once for performance
// - Applies patterns in order of specificity (most specific first)
// - Preserves full log structure so models learn what TYPE of data belongs where
// - Provides strongest training signal without exposing actual sensitive data
//
// This approach helps fine-tuned models learn patterns and structure rather than
// developing confusion about generic redaction markers.

import { SENSITIVE_PATTERNS } from './types';

const MAX_STRING_LENGTH = 1000; // Maximum length for string values
const MAX_ARRAY_LENGTH = 50; // Maximum number of array elements to include
const MAX_OBJECT_DEPTH = 5; // Maximum nesting depth to prevent infinite recursion

// Semantic placeholder pattern definitions with compiled regex
// Ordered by specificity (most specific first) for accurate matching
interface SensitivePattern {
  regex: RegExp; // Compiled regex pattern
  placeholder: string; // Semantic placeholder token
  description: string; // What this pattern detects
}

// Compiled patterns for value-based detection (applied to actual values)
const VALUE_PATTERNS: SensitivePattern[] = [
  // JWT tokens (most specific: three base64 segments separated by dots)
  {
    regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    placeholder: '<JWT_TOKEN>',
    description: 'JSON Web Token',
  },
  // Bearer tokens in Authorization header format
  {
    regex: /Bearer\s+[A-Za-z0-9_\-\.]{20,}/gi,
    placeholder: 'Bearer <BEARER_TOKEN>',
    description: 'Bearer token',
  },
  // Basic auth credentials
  {
    regex: /Basic\s+[A-Za-z0-9+\/=]{20,}/gi,
    placeholder: 'Basic <BASE64_CREDENTIALS>',
    description: 'Basic auth credentials',
  },
  // AWS access key IDs (AKIA followed by 16 alphanumeric chars)
  {
    regex: /AKIA[0-9A-Z]{16}/g,
    placeholder: '<AWS_ACCESS_KEY_ID>',
    description: 'AWS access key ID',
  },
  // AWS secret access keys (40 base64 chars)
  {
    regex: /(?:aws_secret_access_key|secret)["\s:=]+([A-Za-z0-9/+=]{40})/gi,
    placeholder: '<AWS_SECRET_KEY>',
    description: 'AWS secret access key',
  },
  // GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_ prefixes)
  {
    regex: /gh[pousrv]_[A-Za-z0-9]{36,}/g,
    placeholder: '<GITHUB_TOKEN>',
    description: 'GitHub token',
  },
  // Stripe keys (sk_live_, pk_live_, sk_test_, pk_test_)
  {
    regex: /[sp]k_(live|test)_[A-Za-z0-9]{24,}/g,
    placeholder: '<STRIPE_KEY>',
    description: 'Stripe API key',
  },
  // Generic API keys (common patterns)
  {
    regex: /["\s:=](sk|pk|api|key)[-_]?[A-Za-z0-9]{32,}/gi,
    placeholder: '<API_KEY>',
    description: 'Generic API key',
  },
  // Private keys (PEM format)
  {
    regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gi,
    placeholder: '<PRIVATE_KEY>',
    description: 'PEM private key',
  },
  // Email addresses
  {
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    placeholder: '<EMAIL>',
    description: 'Email address',
  },
  // IPv4 addresses
  {
    regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    placeholder: '<IPV4_ADDRESS>',
    description: 'IPv4 address',
  },
  // IPv6 addresses (simplified pattern)
  {
    regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
    placeholder: '<IPV6_ADDRESS>',
    description: 'IPv6 address',
  },
  // UUIDs
  {
    regex: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
    placeholder: '<UUID>',
    description: 'UUID',
  },
  // Credit card numbers (basic pattern, not comprehensive)
  {
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
    placeholder: '<CREDIT_CARD>',
    description: 'Credit card number',
  },
  // Phone numbers (US format and international)
  {
    regex: /\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g,
    placeholder: '<PHONE_NUMBER>',
    description: 'Phone number',
  },
  // Session IDs and similar long hex strings
  {
    regex: /\b[a-fA-F0-9]{32,}\b/g,
    placeholder: '<SESSION_ID>',
    description: 'Session ID or hex string',
  },
];

// Field name to semantic placeholder mapping
// Used when field names indicate sensitive data
const FIELD_NAME_PLACEHOLDERS: Record<string, string> = {
  // Authentication
  authorization: '<AUTH_HEADER>',
  auth: '<AUTH_TOKEN>',
  bearer: '<BEARER_TOKEN>',
  token: '<TOKEN>',
  'access_token': '<ACCESS_TOKEN>',
  'refresh_token': '<REFRESH_TOKEN>',
  'id_token': '<ID_TOKEN>',

  // API keys
  'api_key': '<API_KEY>',
  'apikey': '<API_KEY>',
  'api-key': '<API_KEY>',
  'x-api-key': '<API_KEY>',

  // Passwords
  password: '<PASSWORD>',
  passwd: '<PASSWORD>',
  pwd: '<PASSWORD>',
  pass: '<PASSWORD>',

  // Secrets
  secret: '<SECRET>',
  'client_secret': '<CLIENT_SECRET>',
  'app_secret': '<APP_SECRET>',

  // Cookies and sessions
  cookie: '<COOKIE>',
  'set-cookie': '<SET_COOKIE>',
  session: '<SESSION>',
  'session_id': '<SESSION_ID>',
  sid: '<SESSION_ID>',

  // Keys
  key: '<KEY>',
  'private_key': '<PRIVATE_KEY>',
  'public_key': '<PUBLIC_KEY>',
};

// Applies all value-based patterns to a string, replacing matches with semantic placeholders.
// Patterns are applied in order of specificity (most specific first).
function sanitizeStringValue(value: string): string {
  let sanitized = value;

  // Apply each pattern in order
  for (const pattern of VALUE_PATTERNS) {
    sanitized = sanitized.replace(pattern.regex, pattern.placeholder);
  }

  return sanitized;
}

// Truncates a string to the maximum length, adding ellipsis if truncated.
// Applied AFTER sanitization to preserve semantic placeholders.
function truncateString(value: string): string {
  if (value.length <= MAX_STRING_LENGTH) {
    return value;
  }
  return value.substring(0, MAX_STRING_LENGTH) + '... [truncated]';
}

// Determines the appropriate semantic placeholder for a field name.
// Returns the placeholder token or null if field is not sensitive.
function getFieldPlaceholder(fieldName: string): string | null {
  const lowerField = fieldName.toLowerCase();

  // Check exact matches first
  if (FIELD_NAME_PLACEHOLDERS[lowerField]) {
    return FIELD_NAME_PLACEHOLDERS[lowerField];
  }

  // Check if field name contains any sensitive patterns
  for (const [key, placeholder] of Object.entries(FIELD_NAME_PLACEHOLDERS)) {
    if (lowerField.includes(key)) {
      return placeholder;
    }
  }

  return null;
}

// Checks if a field name matches any sensitive pattern (case-insensitive).
function isSensitiveField(fieldName: string, patterns: string[]): boolean {
  const lowerField = fieldName.toLowerCase();
  return patterns.some(pattern => lowerField.includes(pattern.toLowerCase()));
}

// Sanitizes a single value, handling different types appropriately.
// Uses semantic placeholders based on field names and value patterns.
function sanitizeValue(
  value: any,
  fieldName: string,
  depth: number,
  contextPatterns: string[]
): any {
  // Check depth limit to prevent infinite recursion
  if (depth > MAX_OBJECT_DEPTH) {
    return '<MAX_DEPTH_EXCEEDED>';
  }

  // Handle null/undefined
  if (value === null || value === undefined) {
    return value;
  }

  // Check if field name indicates sensitive data
  const fieldPlaceholder = getFieldPlaceholder(fieldName);
  if (fieldPlaceholder && typeof value === 'string') {
    // For sensitive fields, use the field-specific placeholder
    return fieldPlaceholder;
  }

  // Legacy check for backward compatibility with SENSITIVE_PATTERNS
  if (isSensitiveField(fieldName, contextPatterns)) {
    if (typeof value === 'string') {
      return fieldPlaceholder || '<SENSITIVE_DATA>';
    }
  }

  // Handle strings - apply value-based pattern matching
  if (typeof value === 'string') {
    const sanitized = sanitizeStringValue(value);
    return truncateString(sanitized);
  }

  // Handle arrays
  if (Array.isArray(value)) {
    const truncated = value.slice(0, MAX_ARRAY_LENGTH);
    const sanitized = truncated.map((item, index) =>
      sanitizeValue(item, `${fieldName}[${index}]`, depth + 1, contextPatterns)
    );
    if (value.length > MAX_ARRAY_LENGTH) {
      sanitized.push(`<${value.length - MAX_ARRAY_LENGTH}_MORE_ITEMS>`);
    }
    return sanitized;
  }

  // Handle objects
  if (typeof value === 'object') {
    const sanitized: Record<string, any> = {};
    for (const key in value) {
      if (value.hasOwnProperty(key)) {
        sanitized[key] = sanitizeValue(value[key], key, depth + 1, contextPatterns);
      }
    }
    return sanitized;
  }

  // Return primitives as-is (numbers, booleans, etc.)
  return value;
}

// Sanitizes HTTP headers by scrubbing sensitive header names.
// Returns a new object with sensitive headers replaced with semantic placeholders.
export function sanitizeHeaders(headers: Record<string, any> | undefined): Record<string, any> | undefined {
  if (!headers || typeof headers !== 'object') {
    return headers;
  }

  const sanitized: Record<string, any> = {};
  for (const key in headers) {
    if (headers.hasOwnProperty(key)) {
      sanitized[key] = sanitizeValue(headers[key], key, 0, SENSITIVE_PATTERNS.headers);
    }
  }
  return sanitized;
}

// Sanitizes query parameters by scrubbing sensitive parameter names.
// Returns a new object with sensitive params replaced with semantic placeholders.
export function sanitizeQueryParams(params: Record<string, any> | undefined): Record<string, any> | undefined {
  if (!params || typeof params !== 'object') {
    return params;
  }

  const sanitized: Record<string, any> = {};
  for (const key in params) {
    if (params.hasOwnProperty(key)) {
      sanitized[key] = sanitizeValue(params[key], key, 0, SENSITIVE_PATTERNS.queryParams);
    }
  }
  return sanitized;
}

// Sanitizes request/response body by scrubbing sensitive field names.
// Returns a new object with sensitive fields replaced with semantic placeholders.
export function sanitizeBody(body: any): any {
  if (!body) {
    return body;
  }

  // Handle string bodies (e.g., JSON strings, plain text)
  if (typeof body === 'string') {
    // Try to parse as JSON and sanitize, otherwise sanitize as string
    try {
      const parsed = JSON.parse(body);
      const sanitized = sanitizeValue(parsed, 'body', 0, SENSITIVE_PATTERNS.bodyFields);
      return JSON.stringify(sanitized);
    } catch {
      // Not JSON, sanitize as string
      const sanitized = sanitizeStringValue(body);
      return truncateString(sanitized);
    }
  }

  // Handle object bodies
  if (typeof body === 'object') {
    return sanitizeValue(body, 'body', 0, SENSITIVE_PATTERNS.bodyFields);
  }

  return body;
}

// Sanitizes a complete tool input object, scrubbing headers, query params, and body.
// This is the main entry point for sanitizing tool inputs before sending to Braintrust.
export function sanitizeToolInput(input: any): any {
  if (!input) {
    return input;
  }

  if (typeof input !== 'object') {
    const str = String(input);
    const sanitized = sanitizeStringValue(str);
    return truncateString(sanitized);
  }

  const sanitized: Record<string, any> = {};

  // Combine all patterns for general field sanitization
  const allPatterns = [
    ...SENSITIVE_PATTERNS.headers,
    ...SENSITIVE_PATTERNS.queryParams,
    ...SENSITIVE_PATTERNS.bodyFields,
  ];

  // Sanitize known fields
  if (input.headers) {
    sanitized.headers = sanitizeHeaders(input.headers);
  }
  if (input.queryParams || input.query) {
    sanitized.queryParams = sanitizeQueryParams(input.queryParams || input.query);
  }
  if (input.body) {
    sanitized.body = sanitizeBody(input.body);
  }

  // Sanitize other fields
  for (const key in input) {
    if (input.hasOwnProperty(key) && !['headers', 'queryParams', 'query', 'body'].includes(key)) {
      sanitized[key] = sanitizeValue(input[key], key, 0, allPatterns);
    }
  }

  return sanitized;
}

// Sanitizes a complete tool output object, scrubbing sensitive data.
// This is the main entry point for sanitizing tool outputs before sending to Braintrust.
export function sanitizeToolOutput(output: any): any {
  if (!output) {
    return output;
  }

  if (typeof output !== 'object') {
    const str = String(output);
    const sanitized = sanitizeStringValue(str);
    return truncateString(sanitized);
  }

  const sanitized: Record<string, any> = {};

  // Combine all patterns for general field sanitization
  const allPatterns = [
    ...SENSITIVE_PATTERNS.headers,
    ...SENSITIVE_PATTERNS.queryParams,
    ...SENSITIVE_PATTERNS.bodyFields,
  ];

  // Sanitize known fields
  if (output.headers) {
    sanitized.headers = sanitizeHeaders(output.headers);
  }
  if (output.body) {
    sanitized.body = sanitizeBody(output.body);
  }

  // Sanitize other fields
  for (const key in output) {
    if (output.hasOwnProperty(key) && !['headers', 'body'].includes(key)) {
      sanitized[key] = sanitizeValue(output[key], key, 0, allPatterns);
    }
  }

  return sanitized;
}
