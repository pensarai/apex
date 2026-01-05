/**
 * Types for enhanced operator dashboard
 */

// ============================================
// Endpoint Status & Types
// ============================================

/** Endpoint status markers for attack surface panel */
export type EndpointStatus = 'untested' | 'suspicious' | 'confirmed' | 'clean' | 'blocked';

export interface Endpoint {
  id: string;
  path: string;
  method: string;
  category?: string; // auth, api, admin, etc.
  params?: string[];
  discovered?: Date;
  status?: EndpointStatus;  // ✔/⚠/✖/blocked markers
  vulnType?: string;        // e.g., "SQLi" when confirmed
}

// ============================================
// Target State (Agent's Mental Model)
// ============================================

/** Privilege level phases (distinct from workflow stages) */
export type PentestPhase = 'recon' | 'foothold' | 'user' | 'root';

/** Auth state progression */
export type AuthState = 'none' | 'cookie' | 'creds' | 'shell';

export interface TargetState {
  host: string;
  ports: { port: number; service: string }[];
  authState: AuthState;
  authDetails?: string;           // e.g., "admin cookie"
  phase: PentestPhase;
  pendingPhase?: PentestPhase;    // Agent-suggested, awaiting user confirm
  objective: string;
  objectiveOverride?: string;     // User override, agent must respect
  focus?: string;                 // Active context pointer: "GET /api/users?id="
}

/** Create initial empty target state */
export function createInitialTargetState(host: string): TargetState {
  return {
    host,
    ports: [],
    authState: 'none',
    phase: 'recon',
    objective: 'Discover attack surface',
  };
}

// ============================================
// Credentials
// ============================================

export type CredentialType = 'password' | 'cookie' | 'jwt' | 'ssh_key' | 'api_key';

export interface Credential {
  id: string;
  username: string;
  secret: string;       // Redacted in display with ****
  type: CredentialType;
  source: string;       // "wp-config.php", "login form", etc.
  scope: string;        // "HTTP" | "MySQL" | "SSH"
  isActive: boolean;    // ★ indicator
}

// ============================================
// Hypothesis Tracking (for stuck detection)
// ============================================

export type VulnClass = 'sqli' | 'idor' | 'xss' | 'ssti' | 'ssrf' | 'xxe' | 'lfi' | 'rce' | 'auth_bypass' | 'other';

export interface Hypothesis {
  id: string;
  type: VulnClass;
  target: string;       // endpoint or param
  outcome: 'failed' | 'partial' | 'blocked';
  timestamp: number;
}

// ============================================
// Evidence (with stable IDs for replay)
// ============================================

export type EvidenceType = 'scan' | 'poc' | 'dump' | 'screenshot' | 'request';

export interface Evidence {
  id: string;           // e.g., "evidence:nmap_scan_001"
  type: EvidenceType;
  path: string;
  summary: string;
  timestamp: number;
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
