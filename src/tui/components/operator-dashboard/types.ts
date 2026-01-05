/**
 * Types for enhanced operator dashboard
 */

export interface Endpoint {
  id: string;
  path: string;
  method: string;
  category?: string; // auth, api, admin, etc.
  params?: string[];
  discovered?: Date;
}

export interface Suggestion {
  id: string;
  number: number; // 1, 2, or 3
  label: string;
  description?: string;
  action?: SuggestionAction;
}

export interface SuggestionAction {
  type: 'spawn_attack_surface' | 'spawn_pentest' | 'direct_test' | 'custom';
  target?: string;
  vulnClass?: string;
  directive?: string;
}

export interface VerifiedVuln {
  id: string;
  type: string; // sqli, idor, xss, etc.
  endpoint: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  summary: string;
  pocPath?: string;
  verified: Date;
}

/**
 * Parse suggestions from agent output text
 * Looks for patterns like [1] Description or [2] Description
 */
export function parseSuggestionsFromText(text: string): Suggestion[] {
  const suggestions: Suggestion[] = [];
  const regex = /\[(\d)\]\s*([^\[\n]+)/g;
  let match;

  while ((match = regex.exec(text)) !== null) {
    const num = parseInt(match[1], 10);
    if (num >= 1 && num <= 9) {
      suggestions.push({
        id: `suggestion-${num}`,
        number: num,
        label: match[2].trim(),
      });
    }
  }

  return suggestions;
}
