/**
 * Attack Knowledge Query Engine
 *
 * In-memory filtered search over AttackTechnique entries.
 * Scores results by how many query dimensions match.
 */

import {
  type AttackCategory,
  type AttackTechnique,
  getAttackKnowledgeStore,
} from "./attackKnowledge";

// ---------------------------------------------------------------------------
// Query interface
// ---------------------------------------------------------------------------

export interface KnowledgeQuery {
  /** Filter by attack category (exact match) */
  category?: AttackCategory;
  /** Filter by technologies — any overlap counts */
  technology?: string[];
  /** Filter by context — any overlap with applicability.contexts */
  context?: string;
  /** Free-text search across title, tags, summary, steps, bypass techniques */
  freeText?: string;
  /** Max results to return (default: 10) */
  limit?: number;
}

export interface ScoredTechnique {
  technique: AttackTechnique;
  score: number;
}

// ---------------------------------------------------------------------------
// Query engine
// ---------------------------------------------------------------------------

export class AttackKnowledgeQueryEngine {
  /**
   * Query the knowledge base. Results are ranked by relevance score
   * (number of matching query dimensions + free-text hit count).
   */
  query(q: KnowledgeQuery): AttackTechnique[] {
    const store = getAttackKnowledgeStore();
    const all = store.getAll();
    const limit = q.limit ?? 10;

    if (!q.category && !q.technology?.length && !q.context && !q.freeText) {
      return all.slice(0, limit);
    }

    const scored: ScoredTechnique[] = [];

    for (const technique of all) {
      let score = 0;

      // Category match (exact)
      if (q.category) {
        if (technique.category === q.category) {
          score += 3;
        } else {
          // If category specified and doesn't match, skip unless other dimensions hit
          score -= 1;
        }
      }

      // Technology match (any overlap)
      if (q.technology && q.technology.length > 0) {
        const techLower = q.technology.map((t) => t.toLowerCase());
        const matchCount = technique.applicability.technologies.filter((t) =>
          techLower.some(
            (qt) => t.toLowerCase().includes(qt) || qt.includes(t.toLowerCase()),
          ),
        ).length;

        if (matchCount > 0) {
          score += 2 * matchCount;
        }
      }

      // Context match (substring)
      if (q.context) {
        const ctxLower = q.context.toLowerCase();
        const contextMatch = technique.applicability.contexts.some(
          (c) =>
            c.toLowerCase().includes(ctxLower) ||
            ctxLower.includes(c.toLowerCase()),
        );
        if (contextMatch) {
          score += 2;
        }
      }

      // Free-text match across multiple fields
      if (q.freeText) {
        const terms = q.freeText
          .toLowerCase()
          .split(/\s+/)
          .filter((t) => t.length > 1);

        const searchable = [
          technique.title,
          technique.technique.summary,
          ...technique.tags,
          ...technique.technique.steps,
          ...technique.technique.bypassTechniques,
          ...technique.applicability.preconditions,
          technique.id,
        ]
          .join(" ")
          .toLowerCase();

        for (const term of terms) {
          if (searchable.includes(term)) {
            score += 1;
          }
        }
      }

      if (score > 0) {
        scored.push({ technique, score });
      }
    }

    // Sort by score descending, then by title alphabetically for stability
    scored.sort(
      (a, b) =>
        b.score - a.score || a.technique.title.localeCompare(b.technique.title),
    );

    return scored.slice(0, limit).map((s) => s.technique);
  }

  /**
   * List all techniques filtered by category.
   */
  listByCategory(category: AttackCategory): AttackTechnique[] {
    const store = getAttackKnowledgeStore();
    return store.getAll().filter((t) => t.category === category);
  }

  /**
   * Get all available categories with counts.
   */
  getCategoryCounts(): Record<string, number> {
    const store = getAttackKnowledgeStore();
    const counts: Record<string, number> = {};
    for (const t of store.getAll()) {
      counts[t.category] = (counts[t.category] || 0) + 1;
    }
    return counts;
  }
}

// Global singleton
let globalEngine: AttackKnowledgeQueryEngine | null = null;

export function getQueryEngine(): AttackKnowledgeQueryEngine {
  if (!globalEngine) {
    globalEngine = new AttackKnowledgeQueryEngine();
  }
  return globalEngine;
}
