/**
 * Shared Memory Types
 *
 * Types for the shared memory system that tracks approach outcomes
 * across all testing agents in a session.
 */

import type { VulnerabilityClass } from '../orchestrator/types';

/**
 * A single approach attempt recorded in shared memory
 */
export interface SharedApproach {
  /** Unique identifier */
  id: string;

  /** When this approach was recorded */
  timestamp: number;

  /** Which agent recorded this approach */
  agentId: string;

  /** Description of what was tried */
  approach: string;

  /** Specific technique used (e.g., "UNION-based SQLi", "time-based blind") */
  technique: string;

  /** Target URL/endpoint */
  target: string;

  /** Outcome of the approach */
  outcome: 'success' | 'failure' | 'partial';

  /** Evidence supporting the outcome */
  evidence?: string;

  /** Specific constraints/blockers discovered */
  constraintsLearned: string[];

  /** Vulnerability classes this approach is relevant to */
  vulnClasses: VulnerabilityClass[];

  /** Additional context tags (e.g., "waf-present", "rate-limited") */
  contextTags: string[];
}

/**
 * Input for recording a new approach (without auto-generated fields)
 */
export type SharedApproachInput = Omit<SharedApproach, 'id' | 'timestamp'>;

/**
 * Filter criteria for querying shared memory
 */
export interface SharedMemoryFilter {
  /** Filter by relevant vulnerability classes */
  vulnClasses?: VulnerabilityClass[];

  /** Filter by outcome type */
  outcomes?: ('success' | 'failure' | 'partial')[];

  /** Filter by specific target (partial match on hostname) */
  target?: string;

  /** Exclude entries from a specific agent */
  excludeAgentId?: string;

  /** Match specific context tags */
  contextTags?: string[];

  /** Maximum number of results */
  limit?: number;

  /** Only include entries after this timestamp */
  since?: number;
}

/**
 * Result from querying relevant approaches
 */
export interface RelevantApproachesResult {
  /** Successful approaches to prioritize */
  successful: SharedApproach[];

  /** Failed approaches to avoid */
  failed: SharedApproach[];

  /** All constraints learned for this context */
  constraints: string[];
}

/**
 * Summary of shared memory state
 */
export interface SharedMemorySummary {
  /** Total number of recorded approaches */
  totalApproaches: number;

  /** Count of successful approaches by vuln class */
  successfulByVulnClass: Partial<Record<VulnerabilityClass, number>>;

  /** Count of failed approaches by vuln class */
  failedByVulnClass: Partial<Record<VulnerabilityClass, number>>;

  /** Most common constraints across all approaches */
  commonConstraints: string[];

  /** Most recent successful approaches */
  recentSuccesses: SharedApproach[];
}

/**
 * Interface for shared memory store implementations
 */
export interface SharedMemoryStore {
  /**
   * Record a new approach outcome
   */
  record(approach: SharedApproachInput): Promise<SharedApproach>;

  /**
   * Query approaches matching filter criteria
   */
  query(filter: SharedMemoryFilter): Promise<SharedApproach[]>;

  /**
   * Get approaches relevant to a specific vulnerability class and target
   * This is the primary query method for agents
   */
  getRelevantApproaches(
    vulnClass: VulnerabilityClass,
    target?: string,
    includeFailures?: boolean
  ): Promise<RelevantApproachesResult>;

  /**
   * Get all constraints learned for a specific target
   */
  getConstraintsForTarget(target: string): Promise<string[]>;

  /**
   * Get a summary of the shared memory state
   */
  getSummary(): Promise<SharedMemorySummary>;
}
