/**
 * Finding Bus — Cross-agent finding pub/sub
 *
 * A publish/subscribe bus shared across all swarm agents within a
 * single workflow run. Enables agents to discover what other agents
 * have found during the same engagement.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type FindingType =
  | "credential"
  | "access"
  | "vulnerability"
  | "endpoint"
  | "configuration"
  | "information";

export interface SharedFinding {
  id: string;
  type: FindingType;
  source: string; // agent ID that found it
  data: Record<string, unknown>; // type-specific payload
  timestamp: number;
  /** Optional severity for prioritization */
  severity?: "critical" | "high" | "medium" | "low";
  /** The target URL/endpoint this finding relates to */
  target?: string;
}

export interface FindingFilter {
  type?: FindingType;
  severity?: string;
  /** Substring match on the target URL */
  relatedTo?: string;
  /** Only findings from a specific agent */
  source?: string;
}

type FindingCallback = (finding: SharedFinding) => void;

interface Subscription {
  filter: FindingFilter;
  callback: FindingCallback;
}

// ---------------------------------------------------------------------------
// FindingBus
// ---------------------------------------------------------------------------

export class FindingBus {
  private findings: SharedFinding[] = [];
  private subscriptions: Subscription[] = [];
  private nextId = 1;

  /**
   * Publish a finding to the bus. Notifies all matching subscribers.
   */
  publish(finding: Omit<SharedFinding, "id" | "timestamp">): SharedFinding {
    const full: SharedFinding = {
      ...finding,
      id: `sf-${this.nextId++}`,
      timestamp: Date.now(),
    };

    this.findings.push(full);

    // Notify matching subscribers
    for (const sub of this.subscriptions) {
      if (this.matches(full, sub.filter)) {
        try {
          sub.callback(full);
        } catch {
          // Don't let a failing subscriber break the bus
        }
      }
    }

    return full;
  }

  /**
   * Subscribe to findings matching a filter.
   * Returns an unsubscribe function.
   */
  subscribe(filter: FindingFilter, callback: FindingCallback): () => void {
    const sub: Subscription = { filter, callback };
    this.subscriptions.push(sub);

    return () => {
      const idx = this.subscriptions.indexOf(sub);
      if (idx !== -1) this.subscriptions.splice(idx, 1);
    };
  }

  /**
   * Query all findings matching a filter.
   */
  query(filter: FindingFilter = {}): SharedFinding[] {
    return this.findings.filter((f) => this.matches(f, filter));
  }

  /**
   * Get all findings (unfiltered).
   */
  getAll(): SharedFinding[] {
    return [...this.findings];
  }

  /**
   * Get the count of findings.
   */
  get size(): number {
    return this.findings.length;
  }

  /**
   * Clear all findings and subscriptions (for testing).
   */
  clear(): void {
    this.findings = [];
    this.subscriptions = [];
    this.nextId = 1;
  }

  // ---------------------------------------------------------------------------
  // Private
  // ---------------------------------------------------------------------------

  private matches(finding: SharedFinding, filter: FindingFilter): boolean {
    if (filter.type && finding.type !== filter.type) return false;
    if (filter.severity && finding.severity !== filter.severity) return false;
    if (filter.source && finding.source !== filter.source) return false;
    if (filter.relatedTo && finding.target) {
      if (!finding.target.includes(filter.relatedTo)) return false;
    }
    return true;
  }
}
