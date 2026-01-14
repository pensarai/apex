/**
 * Shared Memory Store Implementation
 *
 * File-based shared memory store that persists approach outcomes
 * to a JSON file in the session directory.
 */

import { join } from 'path';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { nanoid } from 'nanoid';
import type { VulnerabilityClass } from '../orchestrator/types';
import type {
  SharedApproach,
  SharedApproachInput,
  SharedMemoryFilter,
  SharedMemoryStore,
  SharedMemorySummary,
  RelevantApproachesResult,
} from './types';

const SHARED_MEMORY_FILENAME = 'shared-memory.json';

/**
 * File-based implementation of SharedMemoryStore
 */
export class SharedMemoryFileStore implements SharedMemoryStore {
  private memoryPath: string;
  private cache: SharedApproach[] = [];
  private cacheLoaded = false;

  constructor(sessionRootPath: string) {
    this.memoryPath = join(sessionRootPath, SHARED_MEMORY_FILENAME);
  }

  /**
   * Load cache from file if not already loaded
   */
  private loadCache(): void {
    if (this.cacheLoaded) return;

    if (existsSync(this.memoryPath)) {
      try {
        const data = readFileSync(this.memoryPath, 'utf-8');
        this.cache = JSON.parse(data);
      } catch {
        // If parse fails, start with empty cache
        this.cache = [];
      }
    }
    this.cacheLoaded = true;
  }

  /**
   * Save cache to file
   */
  private saveCache(): void {
    writeFileSync(this.memoryPath, JSON.stringify(this.cache, null, 2));
  }

  /**
   * Record a new approach outcome
   */
  async record(input: SharedApproachInput): Promise<SharedApproach> {
    this.loadCache();

    const approach: SharedApproach = {
      ...input,
      id: nanoid(8),
      timestamp: Date.now(),
    };

    this.cache.push(approach);
    this.saveCache();

    return approach;
  }

  /**
   * Check if an approach matches filter criteria
   */
  private matchesFilter(approach: SharedApproach, filter: SharedMemoryFilter): boolean {
    // Filter by vuln classes
    if (filter.vulnClasses && filter.vulnClasses.length > 0) {
      const hasMatchingClass = approach.vulnClasses.some(vc =>
        filter.vulnClasses!.includes(vc)
      );
      if (!hasMatchingClass) return false;
    }

    // Filter by outcomes
    if (filter.outcomes && filter.outcomes.length > 0) {
      if (!filter.outcomes.includes(approach.outcome)) return false;
    }

    // Filter by target (partial hostname match)
    if (filter.target) {
      try {
        const filterHostname = new URL(filter.target).hostname;
        const approachHostname = new URL(approach.target).hostname;
        if (!approachHostname.includes(filterHostname) && !filterHostname.includes(approachHostname)) {
          return false;
        }
      } catch {
        // If URL parsing fails, do simple string match
        if (!approach.target.includes(filter.target)) return false;
      }
    }

    // Exclude specific agent
    if (filter.excludeAgentId && approach.agentId === filter.excludeAgentId) {
      return false;
    }

    // Filter by context tags
    if (filter.contextTags && filter.contextTags.length > 0) {
      const hasMatchingTag = filter.contextTags.some(tag =>
        approach.contextTags.includes(tag)
      );
      if (!hasMatchingTag) return false;
    }

    // Filter by timestamp
    if (filter.since && approach.timestamp < filter.since) {
      return false;
    }

    return true;
  }

  /**
   * Query approaches matching filter criteria
   */
  async query(filter: SharedMemoryFilter): Promise<SharedApproach[]> {
    this.loadCache();

    let results = this.cache.filter(a => this.matchesFilter(a, filter));

    // Sort by timestamp descending (most recent first)
    results.sort((a, b) => b.timestamp - a.timestamp);

    // Apply limit
    if (filter.limit && filter.limit > 0) {
      results = results.slice(0, filter.limit);
    }

    return results;
  }

  /**
   * Get approaches relevant to a specific vulnerability class and target
   */
  async getRelevantApproaches(
    vulnClass: VulnerabilityClass,
    target?: string,
    includeFailures = true
  ): Promise<RelevantApproachesResult> {
    this.loadCache();

    // Get successful approaches for this vuln class
    const successful = await this.query({
      vulnClasses: [vulnClass],
      outcomes: ['success', 'partial'],
      target,
      limit: 10,
    });

    // Get failed approaches if requested
    const failed = includeFailures
      ? await this.query({
          vulnClasses: [vulnClass],
          outcomes: ['failure'],
          target,
          limit: 10,
        })
      : [];

    // Collect all constraints from matching approaches
    const constraintSet = new Set<string>();
    const allApproaches = [...successful, ...failed];
    for (const approach of allApproaches) {
      for (const constraint of approach.constraintsLearned) {
        constraintSet.add(constraint);
      }
    }

    // Also get constraints from target-specific approaches (any vuln class)
    if (target) {
      const targetConstraints = await this.getConstraintsForTarget(target);
      for (const constraint of targetConstraints) {
        constraintSet.add(constraint);
      }
    }

    return {
      successful,
      failed,
      constraints: Array.from(constraintSet),
    };
  }

  /**
   * Get all constraints learned for a specific target
   */
  async getConstraintsForTarget(target: string): Promise<string[]> {
    this.loadCache();

    const constraintSet = new Set<string>();

    for (const approach of this.cache) {
      // Check if approach is for the same target (hostname match)
      try {
        const targetHostname = new URL(target).hostname;
        const approachHostname = new URL(approach.target).hostname;
        if (
          approachHostname.includes(targetHostname) ||
          targetHostname.includes(approachHostname)
        ) {
          for (const constraint of approach.constraintsLearned) {
            constraintSet.add(constraint);
          }
        }
      } catch {
        // If URL parsing fails, do simple string match
        if (approach.target.includes(target)) {
          for (const constraint of approach.constraintsLearned) {
            constraintSet.add(constraint);
          }
        }
      }
    }

    return Array.from(constraintSet);
  }

  /**
   * Get a summary of the shared memory state
   */
  async getSummary(): Promise<SharedMemorySummary> {
    this.loadCache();

    const successfulByVulnClass: Partial<Record<VulnerabilityClass, number>> = {};
    const failedByVulnClass: Partial<Record<VulnerabilityClass, number>> = {};
    const constraintCounts = new Map<string, number>();

    for (const approach of this.cache) {
      // Count by vuln class and outcome
      for (const vulnClass of approach.vulnClasses) {
        if (approach.outcome === 'success' || approach.outcome === 'partial') {
          successfulByVulnClass[vulnClass] = (successfulByVulnClass[vulnClass] || 0) + 1;
        } else {
          failedByVulnClass[vulnClass] = (failedByVulnClass[vulnClass] || 0) + 1;
        }
      }

      // Count constraints
      for (const constraint of approach.constraintsLearned) {
        constraintCounts.set(constraint, (constraintCounts.get(constraint) || 0) + 1);
      }
    }

    // Get most common constraints (top 10)
    const commonConstraints = Array.from(constraintCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([constraint]) => constraint);

    // Get recent successes (top 5)
    const recentSuccesses = this.cache
      .filter(a => a.outcome === 'success')
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, 5);

    return {
      totalApproaches: this.cache.length,
      successfulByVulnClass,
      failedByVulnClass,
      commonConstraints,
      recentSuccesses,
    };
  }
}

/**
 * Build shared memory context string for injection into agent prompt
 */
export function buildSharedMemoryContext(
  result: RelevantApproachesResult,
  vulnClass: VulnerabilityClass
): string {
  if (result.successful.length === 0 && result.failed.length === 0 && result.constraints.length === 0) {
    return ''; // No relevant shared memory
  }

  let context = '\n## Shared Memory (Learned from this session)\n\n';

  if (result.successful.length > 0) {
    context += '### Working Approaches (prioritize these)\n';
    for (const s of result.successful.slice(0, 5)) {
      context += `- **${s.technique}** on \`${s.target}\`: ${s.approach}\n`;
      if (s.evidence) {
        context += `  - Evidence: ${s.evidence.slice(0, 200)}${s.evidence.length > 200 ? '...' : ''}\n`;
      }
    }
    context += '\n';
  }

  if (result.failed.length > 0) {
    context += '### Failed Approaches (avoid these)\n';
    for (const f of result.failed.slice(0, 5)) {
      context += `- **${f.technique}**: ${f.approach}\n`;
      if (f.constraintsLearned.length > 0) {
        context += `  - Constraints: ${f.constraintsLearned.join(', ')}\n`;
      }
    }
    context += '\n';
  }

  if (result.constraints.length > 0) {
    context += '### Known Constraints (apply to your testing)\n';
    for (const c of result.constraints.slice(0, 10)) {
      context += `- ${c}\n`;
    }
    context += '\n';
  }

  return context;
}
