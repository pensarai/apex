# Design Document System

## Purpose

Design documents capture architectural decisions, trade-offs, and implementation plans before code is written. They serve as:

1. **Communication** — Align the team on what's being built and why.
2. **Decision records** — Document the reasoning behind choices, not just the choices themselves.
3. **Implementation guides** — Provide enough detail for engineers (or agents) to implement independently.

## Template

Every design doc should follow this structure:

```markdown
# [Title]

| Field         | Value                          |
|---------------|--------------------------------|
| **Author**    | Name                           |
| **Status**    | draft / review / approved / implemented / deprecated |
| **Created**   | YYYY-MM-DD HH:MM:SS TZ        |
| **Last Modified** | YYYY-MM-DD HH:MM:SS TZ    |

## Summary

One paragraph describing what this document proposes and why.

## Problem Statement

What problem does this solve? Why does it need to exist? What are the pain points today?

## Goals

Bulleted list of concrete goals. What does success look like?

## Non-Goals

What is explicitly out of scope?

## Current State

Describe the relevant parts of the system as they exist today.

## Proposed Design

The core of the document. Include:
- Architecture overview
- TypeScript interfaces / schemas
- Data flow diagrams (ASCII or description)
- API designs

## Alternatives Considered

For each major decision, what alternatives were evaluated and why were they rejected?

## Implementation Plan

Ordered list of tasks with:
- Task description
- Files affected
- Dependencies on other tasks
- Estimated complexity

## Testing Strategy

How will correctness be verified? What tests need to exist before and after migration?

## Migration Plan

If this changes existing behavior, how do we get from here to there safely?

## Appendices

### Appendix A: [Decision Title]

**Context:** Why this decision matters.
**Options:**
1. Option A — description, pros, cons
2. Option B — description, pros, cons

**Decision:** Which option and why.
**Consequences:** What follows from this decision.
```

## Conventions

- **File naming:** `YYYYMMDDHHMMSS-short-slug.md` (e.g., `20260226182203-agent-output-schema.md`)
- **Location:** `.jraad/docs/design-docs/`
- **Status lifecycle:** `draft` → `review` → `approved` → `implemented`
- **Appendices are first-class.** A design doc with 5-8 appendices is healthier than one with zero. They document the reasoning.
- **Be concrete.** Show TypeScript interfaces, Zod schemas, API shapes. Abstract prose is less useful than concrete examples.
- **Reference existing code.** Use file paths and line numbers when discussing current implementations.
