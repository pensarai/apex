# Agent Output Schema System: Flexible, Composable, User-Extensible

| Field             | Value                          |
|-------------------|--------------------------------|
| **Author**        | Jorge Raad                     |
| **Status**        | draft                          |
| **Created**       | 2026-02-26 18:22:03 UTC        |
| **Last Modified** | 2026-02-26 18:22:03 UTC        |

## Summary

This document proposes a redesign of Apex's agent type system to replace rigid, per-agent TypeScript interfaces with a flexible, schema-driven architecture. The goal is to enable agent specializations to be defined declaratively (prompt + input schema + output schema + toolset), allow users to create their own agent definitions and workflows, and make it safe to iterate on schemas by introducing a comprehensive test suite for existing behavior.

## Problem Statement

Today, each specialized agent in Apex requires a new TypeScript class file with hardcoded types, prompts, and tool selections. This creates several pain points:

1. **High coupling between agent definition and code.** Adding a new agent type requires creating a new `.ts` file, defining TypeScript interfaces, writing a class constructor, and wiring it into the API layer. Developer velocity is limited by boilerplate.

2. **Rigid inter-stage schemas.** The typed inputs/outputs between stages (e.g., `WhiteboxAttackSurfaceResult` → `SwarmTarget[]` → `PentestResult`) are hardcoded TypeScript interfaces. When an agent discovers something outside the schema (e.g., an unusual parameter type that doesn't fit the `Endpoint` schema), that data is silently dropped. The schema limits the agent's ability to surface unexpected findings.

3. **No user extensibility.** Users cannot define their own agent configurations, modify schemas, or create custom workflows without forking the codebase. This prevents the kind of target-specific customization that power users want (e.g., "always test my payment API endpoints with these specific payloads").

4. **Duplication across agents.** Specialized agents share significant structural overlap (`SpecializedAgentInput`, common patterns for prompt building, result resolution), but each reimplements these patterns independently.

5. **No test safety net.** There are no tests that verify agent input/output schemas produce expected results. Schema changes are untestable — you can't refactor the type system without risking silent regressions in the data pipeline.

## Goals

- **G1: Schema-driven agent definitions.** Define agents as data (prompt + input schema + output schema + toolset) rather than as TypeScript classes. The `OffensiveSecurityAgent` base class already supports `responseSchema` — generalize this into a first-class pattern.

- **G2: Runtime schema passing.** Enable callers to pass an output schema when spawning a sub-agent, so the same agent harness can produce different structured outputs depending on the caller's needs. The `CodeAgent` already demonstrates this with its `responseSchema` parameter — make this the universal pattern.

- **G3: Reusable workflow definitions.** Define workflows as composable pipelines with typed stage connections. Each stage specifies: prompt template, input schema, output schema, toolset, and stop conditions. Workflows can be saved, shared, and modified.

- **G4: User-defined agent configurations.** Enable users to define custom agent specializations via configuration files (JSON/YAML), loaded at runtime. Users should be able to create, modify, and share agent definitions without touching TypeScript.

- **G5: Flexible schemas with extension points.** Replace schemas that silently drop unexpected data with schemas that have explicit extension points (e.g., `additionalProperties`, `metadata` bags, `z.passthrough()`). Enforce the required structure while allowing agents to surface additional findings.

- **G6: Test coverage for migration safety.** Create a comprehensive test suite that validates the current agent behavior (schema shapes, workflow outputs, inter-stage data flow) so that refactoring can be done safely.

## Non-Goals

- **Removing all TypeScript types.** The core framework types (`OffensiveSecurityAgentInput`, `AgentEventBus`, `ToolContext`, `SessionInfo`) remain as TypeScript. The goal is to make *agent specializations* data-driven, not to remove type safety from the framework.

- **Removing existing specialized agent classes.** Existing classes (`TargetedPentestAgent`, `AuthenticationAgent`, etc.) continue to work. The new system is additive — it provides an alternative way to define agents that coexists with the class-based approach.

- **Building a visual workflow editor.** The workflow system is code/config-first. A UI can be built later.

- **Changing the AI SDK integration.** The `streamResponse` / Vercel AI SDK layer is out of scope. We're redesigning the layer above it.

## Current State

### Agent Definition Pattern

Agents are TypeScript classes extending `OffensiveSecurityAgent<TResult>`:

```typescript
// src/core/agents/specialized/pentest/agent.ts
export class TargetedPentestAgent extends OffensiveSecurityAgent<PentestResult> {
  constructor(opts: PentestAgentInput) {
    super({
      system: PENTEST_SYSTEM_PROMPT,
      prompt: buildPrompt(target, objectives, session.rootPath),
      model,
      session,
      activeTools: ["execute_command", "http_request", "document_finding", "create_poc"],
      stopWhen: hasToolCall("document_finding"),
      resolveResult: () => ({
        findings: loadFindings(session.findingsPath),
        findingsPath: session.findingsPath,
        pocsPath: session.pocsPath,
      }),
    });
  }
}
```

Each specialized agent follows the same pattern:
1. Extend `OffensiveSecurityAgent<TResult>`
2. Define a TypeScript interface for input (`PentestAgentInput extends SpecializedAgentInput`)
3. Define a TypeScript interface for output (`PentestResult`)
4. Hardcode the system prompt, active tools, stop conditions, and `resolveResult`

### Existing `responseSchema` Support

The base class already supports schema-driven structured output via `responseSchema`:

```typescript
// src/core/agents/offSecAgent/offensiveSecurityAgent.ts (lines 80-99)
if (input.responseSchema) {
  tools = {
    ...tools,
    [RESPONSE_TOOL_NAME]: createResponseTool(
      input.responseSchema,
      (result) => { capturedResponse = result as TResult; },
    ),
  };
}

if (input.resolveResult) {
  this.resolveResult = input.resolveResult;
} else if (input.responseSchema) {
  this.resolveResult = () => {
    if (capturedResponse !== null) return capturedResponse;
    return undefined as TResult;
  };
}
```

The `CodeAgent` already uses this to accept a caller-defined schema:

```typescript
// src/core/agents/specialized/codeAgent/agent.ts
export class CodeAgent<TResult = void> extends OffensiveSecurityAgent<TResult> {
  constructor(opts: CodeAgentInput<TResult>) {
    // ...
    if (responseSchema) {
      activeTools.push("response");
    }
    super({ ..., responseSchema });
  }
}
```

And it's consumed in workflows with caller-defined schemas:

```typescript
// src/core/workflows/whiteboxAttackSurface.ts
const appsAgent = new CodeAgent<AppsDiscoveryResult>({
  objective: buildAppsDiscoveryObjective(codebasePath),
  responseSchema: AppsDiscoveryResultSchema,
  // ...
});
const appsResult = await appsAgent.consume();
```

This pattern — pass a Zod schema at spawn time, get typed output — is exactly what we want to generalize.

### Rigid Schema Example

The `WhiteboxAttackSurfaceResult` schema enforces a specific structure:

```typescript
// src/core/agents/specialized/whiteboxAttackSurface/types.ts
export const EndpointSchema = z.object({
  method: z.string(),
  path: z.string(),
  handler: z.string().optional(),
  file: z.string(),
  line: z.number().optional(),
  authRequired: z.boolean().optional(),
  description: z.string().optional(),
  pentestObjectives: z.array(z.string()),
});
```

If the agent discovers something important that doesn't fit these fields (e.g., a WebSocket endpoint, a GraphQL subscription, rate limiting behavior, interesting response headers), there's no place to put it. The data is lost.

### Inter-Stage Data Flow

The pentest workflow (`src/core/workflows/pentest.ts`) demonstrates the rigid pipeline:

```
BlackboxAttackSurfaceAgent → AttackSurfaceResult → SwarmTarget[] → TargetedPentestAgent → PentestResult
```

Each stage has fixed input/output types. The transform between stages (e.g., `result.targets.map(t => ({ target: t.target, objectives: [t.objective] }))`) is hardcoded in the workflow function.

### Test Coverage

Current tests cover:
- `AgentEventBus` — event emission, filtering, child buses, bubbling (unit tests)
- `AgentRun` — streaming, buffering, error propagation (unit tests)
- Integration tests in `src/tests/` — require API keys, test full agent runs

There are **no tests** for:
- Schema validation (do agent outputs conform to their declared schemas?)
- Inter-stage data transforms (does the whitebox→pentest pipeline preserve all data?)
- Schema evolution (can old data be parsed by new schemas?)

## Proposed Design

### 1. Agent Definition Interface

Introduce `AgentDefinition` — a plain data object that fully describes an agent specialization without requiring a TypeScript class:

```typescript
import { z } from "zod";

interface AgentDefinition<TInput = unknown, TOutput = unknown> {
  /** Unique identifier for this agent type */
  id: string;

  /** Human-readable name */
  name: string;

  /** Description of what this agent does */
  description: string;

  /** System prompt (string or template function) */
  system: string | ((input: TInput) => string);

  /** User prompt template (string or builder function) */
  prompt: string | ((input: TInput) => string);

  /** Zod schema for the agent's input */
  inputSchema: z.ZodSchema<TInput>;

  /**
   * Zod schema for the agent's structured output.
   * When provided, the agent gets a `response` tool and stops
   * when it calls it. `consume()` returns the validated data.
   */
  outputSchema?: z.ZodSchema<TOutput>;

  /** Which tools the agent is allowed to use */
  tools: string[];

  /** Stop conditions (tool call names or step count) */
  stopConditions?: StopConditionConfig;

  /**
   * Custom result resolver.
   * When set, overrides `outputSchema` for result extraction.
   * Receives the completed stream result and session info.
   */
  resolveResult?: (ctx: ResultResolverContext) => TOutput | Promise<TOutput>;

  /**
   * Optional metadata for categorization, documentation, etc.
   * Users can attach arbitrary metadata to their definitions.
   */
  metadata?: Record<string, unknown>;
}

interface StopConditionConfig {
  /** Stop when any of these tools are called */
  onToolCall?: string[];
  /** Stop after this many steps */
  maxSteps?: number;
}

interface ResultResolverContext {
  streamResult: StreamTextResult<ToolSet, never>;
  session: SessionInfo;
}
```

### 2. Agent Registry

A runtime registry that maps definition IDs to `AgentDefinition` objects:

```typescript
class AgentRegistry {
  private definitions = new Map<string, AgentDefinition>();

  /** Register a built-in or user-defined agent definition */
  register(definition: AgentDefinition): void;

  /** Retrieve a definition by ID */
  get(id: string): AgentDefinition | undefined;

  /** List all registered definitions */
  list(): AgentDefinition[];

  /** Load definitions from a directory of JSON/YAML files */
  loadFromDirectory(dirPath: string): Promise<void>;

  /**
   * Create an agent instance from a definition.
   * The caller provides runtime values (model, session, input data).
   */
  createAgent<TOutput>(
    id: string,
    runtime: AgentRuntimeConfig,
    input: unknown,
  ): OffensiveSecurityAgent<TOutput>;

  /**
   * Create an agent from an inline definition (not registered).
   * Useful for one-off or dynamically constructed agents.
   */
  createFromDefinition<TInput, TOutput>(
    definition: AgentDefinition<TInput, TOutput>,
    runtime: AgentRuntimeConfig,
    input: TInput,
  ): OffensiveSecurityAgent<TOutput>;
}

interface AgentRuntimeConfig {
  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  eventBus?: AgentEventBus;
  sandbox?: UnifiedSandbox;
}
```

### 3. Flexible Schemas with Extension Points

Replace rigid schemas with schemas that preserve the required structure but allow additional data:

```typescript
const FlexibleEndpointSchema = z.object({
  method: z.string(),
  path: z.string(),
  handler: z.string().optional(),
  file: z.string(),
  line: z.number().optional(),
  authRequired: z.boolean().optional(),
  description: z.string().optional(),
  pentestObjectives: z.array(z.string()),
  /** Agent can attach any additional observations */
  metadata: z.record(z.unknown()).optional(),
}).passthrough();
```

The `.passthrough()` call tells Zod to preserve unknown keys rather than stripping them. The `metadata` field provides a structured place for agents to attach additional context.

For inter-stage data, introduce an `AgentOutput` wrapper that separates the structured schema from freeform observations:

```typescript
interface AgentOutput<T> {
  /** The structured data matching the output schema */
  data: T;

  /**
   * Freeform observations, notes, and findings that don't fit
   * the schema. Preserved for downstream stages and logging.
   */
  observations?: string[];

  /**
   * Key-value metadata the agent wants to pass downstream.
   * Unlike `data`, this is not schema-validated.
   */
  metadata?: Record<string, unknown>;

  /** The raw text output from the agent (narration) */
  rawText?: string;
}
```

### 4. Workflow Definitions

Workflows become composable pipelines of agent stages:

```typescript
interface WorkflowStage<TIn = unknown, TOut = unknown> {
  /** Unique ID for this stage within the workflow */
  id: string;

  /** The agent definition to use for this stage */
  agentId: string;

  /**
   * Transform the previous stage's output into this stage's input.
   * If omitted, the previous output is passed through directly.
   */
  mapInput?: (previousOutput: unknown, context: WorkflowContext) => TIn;

  /**
   * Override the output schema for this stage.
   * When set, overrides the agent definition's outputSchema.
   */
  outputSchema?: z.ZodSchema<TOut>;

  /** Override tools for this stage */
  tools?: string[];

  /** Override system prompt for this stage */
  system?: string;
}

interface WorkflowDefinition {
  /** Unique identifier */
  id: string;

  /** Human-readable name */
  name: string;

  /** Description */
  description: string;

  /**
   * Ordered list of stages. Each stage's output feeds into the
   * next stage's input (unless `mapInput` transforms it).
   */
  stages: WorkflowStage[];

  /**
   * Parallel stage groups. Stages within a group run concurrently
   * with bounded concurrency. Groups execute sequentially.
   */
  parallelGroups?: ParallelGroup[];

  /** Input schema for the workflow itself */
  inputSchema: z.ZodSchema;

  /** Output schema — derived from the last stage's output */
  outputSchema?: z.ZodSchema;

  /** Default concurrency for parallel stages */
  concurrency?: number;
}

interface ParallelGroup {
  /** Stage IDs to run in parallel */
  stageIds: string[];

  /** Max concurrent agents */
  concurrency?: number;

  /**
   * How to split input across parallel instances.
   * Receives the previous stage's output and returns an array
   * of inputs, one per parallel instance.
   */
  fanOut: (previousOutput: unknown) => unknown[];

  /**
   * How to merge parallel outputs into a single value
   * for the next stage.
   */
  fanIn: (outputs: unknown[]) => unknown;
}

interface WorkflowContext {
  session: SessionInfo;
  model: AIModel;
  originalInput: unknown;
  stageOutputs: Map<string, unknown>;
}
```

### 5. User-Defined Configuration Format

Users can create agent definitions and workflows as JSON files in `~/.pensar/agents/` and `~/.pensar/workflows/`:

```jsonc
// ~/.pensar/agents/payment-api-tester.json
{
  "id": "payment-api-tester",
  "name": "Payment API Security Tester",
  "description": "Specialized agent for testing payment processing endpoints",
  "system": "You are an expert payment security tester. Focus on PCI-DSS compliance issues, payment flow manipulation, race conditions in transaction processing, and price tampering.",
  "prompt": "Test the payment endpoints at {{target}} for security vulnerabilities.\n\nFocus areas:\n{{#each objectives}}\n- {{this}}\n{{/each}}",
  "tools": ["execute_command", "http_request", "document_finding", "create_poc"],
  "stopConditions": {
    "onToolCall": ["document_finding"],
    "maxSteps": 50
  },
  "inputSchema": {
    "type": "object",
    "properties": {
      "target": { "type": "string" },
      "objectives": { "type": "array", "items": { "type": "string" } }
    },
    "required": ["target"]
  },
  "outputSchema": {
    "type": "object",
    "properties": {
      "findings": {
        "type": "array",
        "items": { "$ref": "#/definitions/Finding" }
      },
      "pciIssues": {
        "type": "array",
        "items": { "type": "string" }
      }
    }
  }
}
```

For JSON Schema-based definitions from users, provide a `jsonSchemaToZod` converter that translates JSON Schema into Zod schemas at load time. This keeps the internal runtime on Zod (which integrates with the AI SDK's tool system) while giving users a familiar, language-agnostic schema format.

### 6. Schema-Driven `spawn_agent` Tool

Replace the current specialized spawn tools (`spawn_coding_agent`, `spawn_pentest_swarm`) with a generalized `spawn_agent` tool:

```typescript
function spawnAgent(ctx: ToolContext, registry: AgentRegistry) {
  return tool({
    description: `Spawn a sub-agent to perform a specific task. You can use a registered agent definition by ID, or define an inline agent with a custom prompt and output schema.`,
    inputSchema: z.object({
      tasks: z.array(z.object({
        agentId: z.string().optional()
          .describe("ID of a registered agent definition. If omitted, uses the default general agent."),
        prompt: z.string()
          .describe("The objective/prompt for this sub-agent"),
        outputSchema: z.record(z.unknown()).optional()
          .describe("JSON Schema for the expected output. If omitted, the agent returns unstructured text."),
        input: z.record(z.unknown()).optional()
          .describe("Input data to pass to the agent"),
      })),
      concurrency: z.number().optional()
        .describe("Max concurrent agents (default: 5)"),
      toolCallDescription: z.string(),
    }),
    execute: async ({ tasks, concurrency }) => {
      // For each task, resolve the agent definition (from registry or inline),
      // convert JSON Schema to Zod if needed, create the agent, and run it.
    },
  });
}
```

This preserves the existing pattern of parent agents spawning sub-agents but makes it schema-driven and extensible.

### 7. Backward Compatibility Layer

Existing specialized agent classes are preserved and refactored to be thin wrappers around `AgentDefinition`:

```typescript
// Refactored PentestAgent — same API, backed by AgentDefinition
export const PentestAgentDefinition: AgentDefinition<PentestAgentInput, PentestResult> = {
  id: "pentest",
  name: "Targeted Pentest Agent",
  description: "Penetration testing agent focused on specific targets and objectives",
  system: PENTEST_SYSTEM_PROMPT,
  prompt: (input) => buildPrompt(input.target, input.objectives, input.session.rootPath),
  inputSchema: PentestAgentInputSchema,
  tools: ["execute_command", "http_request", "document_finding", "create_poc"],
  stopConditions: { onToolCall: ["document_finding"] },
  resolveResult: (ctx) => ({
    findings: loadFindings(ctx.session.findingsPath),
    findingsPath: ctx.session.findingsPath,
    pocsPath: ctx.session.pocsPath,
  }),
};

// Class wrapper for backward compat
export class TargetedPentestAgent extends OffensiveSecurityAgent<PentestResult> {
  constructor(opts: PentestAgentInput) {
    const def = PentestAgentDefinition;
    super({
      system: typeof def.system === "function" ? def.system(opts) : def.system,
      prompt: typeof def.prompt === "function" ? def.prompt(opts) : def.prompt,
      model: opts.model,
      session: opts.session,
      target: opts.target,
      activeTools: def.tools,
      stopWhen: buildStopConditions(def.stopConditions),
      resolveResult: def.resolveResult
        ? (sr) => def.resolveResult!({ streamResult: sr, session: opts.session })
        : undefined,
      // ... other fields
    });
  }
}
```

## Alternatives Considered

### A. Pure config-only (no code-defined agents)

Remove all TypeScript agent classes and define everything in JSON/YAML config.

**Rejected because:**
- Some agents need runtime logic that config can't express (e.g., `AuthenticationAgent`'s `resolveResult` that parses tool call results from the stream)
- The `prompt` builder for `PentestAgent` reads auth data from the filesystem — this requires code
- Loses TypeScript type safety for internal consumers

The hybrid approach (config OR code, with code wrapping config) gives us the best of both worlds.

### B. Structured output via AI SDK `structuredOutputs` mode

Use the AI SDK's native structured output mode instead of the `response` tool pattern.

**Rejected because:**
- Not all models support structured outputs natively
- The `response` tool pattern works universally and is already battle-tested in the codebase
- The tool-based approach gives the agent more flexibility — it decides *when* to submit the structured output, not just *what* to submit

### C. GraphQL-style schema language

Define schemas in a custom SDL or GraphQL-like language instead of JSON Schema/Zod.

**Rejected because:**
- Adds a parser/compiler dependency
- JSON Schema is universal and well-understood
- Zod is already the standard in the codebase and integrates directly with the AI SDK

### D. Removing inter-stage typing entirely

Pass raw text/JSON between stages with no schema validation.

**Rejected because:**
- Console integration requires predictable data shapes for UI rendering
- Loses the ability to catch malformed data before it reaches downstream consumers
- The `AgentOutput<T>` wrapper with `metadata` + `observations` provides flexibility without losing structure

## Implementation Plan

### Phase 0: Test Infrastructure (Safety Net)

**Goal:** Create tests that capture current behavior so we can refactor safely.

#### Task 0.1: Schema Conformance Tests
- **What:** Write tests that validate example agent outputs against their declared schemas
- **Files:** `src/core/agents/specialized/*/schema.test.ts` (new)
- **Details:** For each agent type, create representative output fixtures and validate them against the Zod schemas. This catches if schema changes silently break parsing.
- **Complexity:** Low

```typescript
// Example: src/core/agents/specialized/whiteboxAttackSurface/schema.test.ts
import { describe, it, expect } from "vitest";
import { WhiteboxAttackSurfaceResultSchema } from "./types";

describe("WhiteboxAttackSurfaceResult schema", () => {
  it("validates a complete result", () => {
    const fixture = {
      repoType: "monorepo",
      packageManager: "npm",
      apps: [{
        name: "api",
        framework: "Express",
        description: "REST API",
        location: "packages/api",
        pages: [],
        apiEndpoints: [{
          method: "GET",
          path: "/api/users",
          file: "src/routes/users.ts",
          pentestObjectives: ["Test for IDOR"],
        }],
      }],
      summary: { totalApps: 1, totalPages: 0, totalApiEndpoints: 1, totalPentestObjectives: 1 },
    };

    expect(() => WhiteboxAttackSurfaceResultSchema.parse(fixture)).not.toThrow();
  });

  it("rejects incomplete results", () => {
    const fixture = { repoType: "monorepo" }; // missing required fields
    expect(() => WhiteboxAttackSurfaceResultSchema.parse(fixture)).toThrow();
  });
});
```

#### Task 0.2: Inter-Stage Transform Tests
- **What:** Test the data transforms between workflow stages (e.g., attack surface → swarm targets)
- **Files:** `src/core/workflows/pentest.test.ts` (new), `src/core/workflows/whiteboxAttackSurface.test.ts` (new)
- **Details:** Extract the transform functions from workflow files, make them testable, and verify that representative inputs produce expected outputs.
- **Complexity:** Low

#### Task 0.3: Agent Definition Snapshot Tests
- **What:** Capture the current configuration of each specialized agent as a snapshot
- **Files:** `src/core/agents/specialized/*/definition.test.ts` (new)
- **Details:** For each agent, assert its system prompt, active tools, stop conditions, and other configuration values. If a refactor changes these, the test fails and you know to verify the change was intentional.
- **Complexity:** Low

### Phase 1: Core Abstractions

**Goal:** Introduce `AgentDefinition`, `AgentRegistry`, and the flexible schema wrapper without changing existing behavior.

#### Task 1.1: Define `AgentDefinition` Interface
- **What:** Create the `AgentDefinition` type and related types
- **Files:** `src/core/agents/definition/types.ts` (new)
- **Dependencies:** None
- **Complexity:** Low

#### Task 1.2: Implement `AgentRegistry`
- **What:** Create the registry with register/get/list/createAgent
- **Files:** `src/core/agents/definition/registry.ts` (new)
- **Dependencies:** Task 1.1
- **Complexity:** Medium

#### Task 1.3: Create `AgentOutput<T>` Wrapper
- **What:** Implement the flexible output wrapper with `data`, `observations`, `metadata`
- **Files:** `src/core/agents/definition/output.ts` (new)
- **Dependencies:** Task 1.1
- **Complexity:** Low

#### Task 1.4: JSON Schema → Zod Converter
- **What:** Implement `jsonSchemaToZod()` for loading user-defined schemas
- **Files:** `src/core/agents/definition/schemaConverter.ts` (new)
- **Dependencies:** None
- **Complexity:** Medium — JSON Schema has many features; we support a practical subset (object, array, string, number, boolean, enum, $ref for built-in types like Finding)

#### Task 1.5: Config File Loader
- **What:** Load agent definitions from `~/.pensar/agents/` JSON files
- **Files:** `src/core/agents/definition/loader.ts` (new)
- **Dependencies:** Tasks 1.1, 1.2, 1.4
- **Complexity:** Medium

### Phase 2: Migrate Existing Agents

**Goal:** Refactor each specialized agent to be backed by an `AgentDefinition` while preserving the existing class API.

#### Task 2.1: Extract `PentestAgentDefinition`
- **What:** Create a definition object for the pentest agent, wrap the existing class
- **Files:** `src/core/agents/specialized/pentest/definition.ts` (new), `src/core/agents/specialized/pentest/agent.ts` (modify)
- **Dependencies:** Phase 1
- **Complexity:** Low

#### Task 2.2: Extract `CodeAgentDefinition`
- **What:** Same for CodeAgent
- **Files:** `src/core/agents/specialized/codeAgent/definition.ts` (new), `src/core/agents/specialized/codeAgent/agent.ts` (modify)
- **Dependencies:** Phase 1
- **Complexity:** Low

#### Task 2.3: Extract `AttackSurfaceAgentDefinition` (blackbox + whitebox)
- **What:** Same for both attack surface agents
- **Files:** `src/core/agents/specialized/attackSurface/definition.ts` (new), `src/core/agents/specialized/whiteboxAttackSurface/definition.ts` (new)
- **Dependencies:** Phase 1
- **Complexity:** Low-Medium

#### Task 2.4: Extract `AuthenticationAgentDefinition`
- **What:** Same for authentication agent. This one is more complex because `resolveResult` parses tool call results from the stream.
- **Files:** `src/core/agents/specialized/authenticationAgent/definition.ts` (new), `src/core/agents/specialized/authenticationAgent/agent.ts` (modify)
- **Dependencies:** Phase 1
- **Complexity:** Medium

#### Task 2.5: Register All Built-in Definitions
- **What:** Create a barrel that registers all built-in agent definitions with the registry
- **Files:** `src/core/agents/definition/builtins.ts` (new)
- **Dependencies:** Tasks 2.1–2.4
- **Complexity:** Low

### Phase 3: Workflow Engine

**Goal:** Implement the workflow definition system and migrate existing workflows.

#### Task 3.1: Implement Workflow Runner
- **What:** Create `runWorkflow(definition, input, runtime)` that executes a `WorkflowDefinition`
- **Files:** `src/core/workflows/engine.ts` (new)
- **Dependencies:** Phase 1
- **Complexity:** High — handles sequential stages, parallel fan-out/fan-in, bounded concurrency, error recovery

#### Task 3.2: Migrate Pentest Workflow
- **What:** Express the existing `runPentestWorkflow` as a `WorkflowDefinition`
- **Files:** `src/core/workflows/definitions/pentest.ts` (new), `src/core/workflows/pentest.ts` (modify to delegate)
- **Dependencies:** Task 3.1
- **Complexity:** Medium

#### Task 3.3: Migrate Whitebox Attack Surface Workflow
- **What:** Express the existing `runWhiteboxAttackSurfaceWorkflow` as a `WorkflowDefinition`
- **Files:** `src/core/workflows/definitions/whiteboxAttackSurface.ts` (new)
- **Dependencies:** Task 3.1
- **Complexity:** Medium

#### Task 3.4: Workflow Config Loader
- **What:** Load workflow definitions from `~/.pensar/workflows/` JSON files
- **Files:** `src/core/workflows/loader.ts` (new)
- **Dependencies:** Tasks 3.1, 1.5
- **Complexity:** Medium

### Phase 4: Generalized Spawn Tool

**Goal:** Replace specialized spawn tools with a general `spawn_agent` tool.

#### Task 4.1: Implement `spawn_agent` Tool
- **What:** Create the generalized spawn tool that accepts agent IDs or inline definitions
- **Files:** `src/core/agents/offSecAgent/tools/spawnAgent.ts` (new)
- **Dependencies:** Phase 1 (registry)
- **Complexity:** Medium

#### Task 4.2: Deprecate `spawn_coding_agent` and `spawn_pentest_swarm`
- **What:** Mark existing spawn tools as deprecated, make them delegate to `spawn_agent`
- **Files:** `src/core/agents/offSecAgent/tools/spawnCodingAgent.ts`, `src/core/agents/offSecAgent/tools/spawnPentestSwarm.ts`
- **Dependencies:** Task 4.1
- **Complexity:** Low

### Phase 5: Schema Flexibility

**Goal:** Add `.passthrough()` and `metadata` fields to existing schemas.

#### Task 5.1: Add Flexibility to Endpoint/App Schemas
- **What:** Add `.passthrough()` and optional `metadata` to `EndpointSchema`, `AppSchema`, `WhiteboxAttackSurfaceResultSchema`
- **Files:** `src/core/agents/specialized/whiteboxAttackSurface/types.ts`
- **Dependencies:** Phase 0 tests (so we can verify nothing breaks)
- **Complexity:** Low

#### Task 5.2: Add Flexibility to Finding Schema
- **What:** Add optional `metadata` to `ApexFindingObject`, apply `.passthrough()`
- **Files:** `src/core/agents/offSecAgent/types.ts`
- **Dependencies:** Phase 0 tests
- **Complexity:** Low

#### Task 5.3: Add Flexibility to Attack Surface Schemas
- **What:** Same for blackbox attack surface types
- **Files:** `src/core/agents/specialized/attackSurface/types.ts`, `src/core/agents/specialized/attackSurface/schemas.ts`
- **Dependencies:** Phase 0 tests
- **Complexity:** Low

### Dependency Graph

```
Phase 0 (Tests) ─────────────────────────────────────┐
  0.1 Schema Tests          (parallel)                │
  0.2 Transform Tests       (parallel)                │
  0.3 Snapshot Tests         (parallel)                │
                                                      │
Phase 1 (Core) ──────────────────────────────────────┐│
  1.1 AgentDefinition types  (no deps)               ││
  1.2 AgentRegistry          (← 1.1)                 ││
  1.3 AgentOutput<T>         (← 1.1)                 ││
  1.4 JSON Schema → Zod      (no deps)               ││
  1.5 Config Loader          (← 1.1, 1.2, 1.4)      ││
                                                      ││
Phase 2 (Migration) ─────────────────────────────────┐││
  2.1–2.4 Agent definitions  (← Phase 1, parallel)   │││
  2.5 Register builtins      (← 2.1–2.4)             │││
                                                      │││
Phase 3 (Workflows) ─────────────────────────────────┐│││
  3.1 Workflow engine        (← Phase 1)              ││││
  3.2–3.3 Migrate workflows  (← 3.1, parallel)       ││││
  3.4 Workflow loader        (← 3.1, 1.5)            ││││
                                                      ││││
Phase 4 (Spawn Tool) ────────────────────────────────┐│││
  4.1 spawn_agent            (← Phase 1)             ││││
  4.2 Deprecate old spawns   (← 4.1)                 ││││
                                                      ││││
Phase 5 (Flexibility) ──────────── (← Phase 0) ──────┘│││
  5.1–5.3 Schema updates     (parallel)                │││
```

Phases 0 and 5 can be done independently of Phases 1–4. Phase 5 only depends on Phase 0 tests existing. Phases 2, 3, and 4 all depend on Phase 1 but can run in parallel with each other.

## Testing Strategy

### Unit Tests (Phase 0 — pre-migration)

1. **Schema conformance tests** — Validate fixtures against every Zod schema in the codebase. These are the safety net for any schema refactoring.

2. **Transform tests** — Extract the data transforms from workflows (e.g., attack surface → swarm targets) into pure functions and test them with representative inputs.

3. **Agent definition snapshots** — Capture each agent's prompt, tools, and stop conditions as snapshots. Regressions during migration are caught immediately.

### Unit Tests (ongoing)

4. **AgentDefinition validation** — Test that the registry validates definitions on registration (rejects missing required fields, invalid tool names, etc.).

5. **JSON Schema → Zod conversion** — Test the converter with representative JSON Schemas, including edge cases (nested objects, arrays, enums, optional fields, $ref).

6. **Config loader** — Test loading agent definitions from JSON files, including error cases (malformed JSON, missing required fields, invalid schemas).

7. **Workflow engine** — Test sequential execution, parallel fan-out/fan-in, error handling, bounded concurrency. Use mock agents that return predetermined outputs.

8. **AgentOutput wrapper** — Test that `metadata` and `observations` are preserved through the pipeline.

### Integration Tests

9. **Round-trip test** — Define an agent via JSON config, load it, run it against a mock target, verify the output matches the declared schema. Requires API key.

10. **Migration equivalence test** — For each migrated agent, verify that the definition-backed version produces the same configuration (prompt, tools, stop conditions) as the original class.

## Migration Plan

### Step 1: Ship Phase 0 tests

Write and merge the test suite before touching any production code. This is the safety net that makes everything else safe.

### Step 2: Ship Phase 1 as additive-only

The `AgentDefinition`, `AgentRegistry`, and related types are purely additive — they don't change any existing code. Ship them behind the existing API surface. No consumer changes.

### Step 3: Ship Phase 2 one agent at a time

Migrate agents one by one, verifying each migration against the Phase 0 snapshot tests. The class API doesn't change — only the internal implementation is backed by a definition.

Order: CodeAgent (simplest) → PentestAgent → AttackSurface → Authentication (most complex)

### Step 4: Ship Phase 5 (schema flexibility) with Phase 0 tests as guard

Add `.passthrough()` and `metadata` to schemas. Phase 0 schema tests verify that existing valid data still parses. Console integration is unaffected because it only reads known fields — extra fields are ignored.

### Step 5: Ship Phases 3 and 4

The workflow engine and generalized spawn tool are more significant changes. Ship with comprehensive tests. Keep the old workflow functions as thin wrappers that delegate to the engine.

### Rollback plan

Every phase is additive and preserves the existing class-based API. If issues arise:
- Phase 1: Delete the definition types. No production code depends on them.
- Phase 2: Revert individual agents to their original class-only implementations. The definition is a parallel code path.
- Phase 3: Revert to the original workflow functions. The engine is a parallel code path.
- Phase 5: Remove `.passthrough()` from schemas. The only risk is that downstream code tries to access `metadata` on outputs — but since this is optional, existing code never does.

## Appendices

### Appendix A: Why `responseSchema` Tool Pattern Over Native Structured Outputs

**Context:** The AI SDK supports native structured output mode where the model is constrained to produce JSON matching a schema. We could use this instead of the `response` tool pattern.

**Options:**

1. **Native structured outputs** — Pass the schema to the model directly. The final message is guaranteed to match the schema.
   - Pros: No tool call overhead, guaranteed schema conformance
   - Cons: Not all models support it (especially local/vLLM models), removes the agent's ability to narrate before submitting, model can't "think" before outputting

2. **`response` tool pattern** (current) — The agent gets a `response` tool that captures structured data. The agent decides when to call it.
   - Pros: Universal (works with any model that supports tool use), agent can think/reason before submitting, agent controls timing
   - Cons: Agent could theoretically never call the tool (mitigated by stop conditions)

**Decision:** Keep the `response` tool pattern. It's universal, battle-tested, and gives the agent more flexibility. The `responseSchema` field on `AgentDefinition` maps directly to this mechanism.

### Appendix B: JSON Schema vs Zod for User-Defined Schemas

**Context:** Users need a way to define schemas in config files. Zod is TypeScript-only and can't be serialized to JSON. JSON Schema is language-agnostic but doesn't integrate directly with the AI SDK.

**Options:**

1. **JSON Schema in config, Zod at runtime** — Users write JSON Schema in their config files. A converter translates it to Zod at load time.
   - Pros: JSON Schema is familiar, language-agnostic, well-tooled (editors, validators, generators)
   - Cons: Converter adds complexity, may not support all JSON Schema features

2. **Zod as strings** — Users write Zod schemas as JavaScript strings that are eval'd at load time.
   - Pros: Direct integration, no converter needed
   - Cons: Security risk (eval), unfamiliar to non-TypeScript users, hard to validate without executing

3. **Custom DSL** — Define a simplified schema language purpose-built for Apex.
   - Pros: Can be optimized for the use case
   - Cons: Yet another schema language to learn, no tooling ecosystem

**Decision:** Option 1 — JSON Schema in config files, Zod at runtime. JSON Schema is the standard, and a practical converter that covers the subset of features we need (object, array, primitives, enum, optional, descriptions) is straightforward to build. We don't need to support the full JSON Schema spec.

### Appendix C: Granularity of the `spawn_agent` Tool

**Context:** Should we have one general `spawn_agent` tool that replaces all specialized spawn tools, or keep specialized tools alongside a general one?

**Options:**

1. **Single `spawn_agent` tool** — One tool that can instantiate any agent definition.
   - Pros: Simpler toolset, fewer tools for the model to choose from, more flexible
   - Cons: More complex input schema (agent ID, inline definition, etc.), may confuse the model about which agent to use

2. **Keep specialized + add general** — Keep `spawn_coding_agent` and `spawn_pentest_swarm` but add a general `spawn_agent` for custom definitions.
   - Pros: Backward compatible, specialized tools have focused descriptions that help the model
   - Cons: More tools, potential confusion about which to use

3. **Specialized tools delegate to general** — Keep the specialized tool interfaces but implement them as wrappers around `spawn_agent`.
   - Pros: Backward compatible externally, unified implementation internally
   - Cons: Indirection

**Decision:** Option 3 — Keep specialized tool interfaces for backward compatibility but implement them internally using the general `spawn_agent` mechanism. Add `spawn_agent` as a new tool that power users and custom agents can use directly. Gradually deprecate the specialized tools as the model becomes comfortable with the general tool.

### Appendix D: Workflow Definition — Code vs Config

**Context:** Should workflows be definable in JSON config files (like agent definitions) or only in code?

**Options:**

1. **Config-only workflows** — All workflows are JSON files with stage definitions.
   - Pros: Fully user-customizable, no code changes needed for new workflows
   - Cons: Hard to express complex transform logic (`mapInput`, `fanOut`, `fanIn`) in JSON. These are functions.

2. **Code-only workflows** — Workflows remain TypeScript functions.
   - Pros: Full expressiveness, TypeScript type checking
   - Cons: Users can't define custom workflows without forking

3. **Hybrid** — Workflow structure in config, transform functions in code. Users can define simple workflows (sequential stages with pass-through data) in config, but complex transforms require code plugins.
   - Pros: Covers both simple and complex cases
   - Cons: Two authoring modes, more complexity

**Decision:** Option 3 — Hybrid. Simple sequential workflows with string-template-based input mapping can be fully config-driven. For fan-out/fan-in and complex transforms, provide a small set of built-in transform strategies (e.g., `flatMap`, `groupBy`, `identity`) that can be referenced by name in config. For truly custom logic, code-defined workflows remain available. This covers the 80/20 case.

### Appendix E: `.passthrough()` vs Explicit `metadata` Field

**Context:** How do we allow agents to surface data that doesn't fit the declared schema?

**Options:**

1. **`.passthrough()` only** — Add `.passthrough()` to all Zod schemas. Unknown keys are preserved.
   - Pros: Simple, agents can add any key
   - Cons: No discoverability, downstream code doesn't know what extra keys to expect, hard to distinguish intentional additions from noise

2. **Explicit `metadata: z.record(z.unknown())` only** — Add a typed `metadata` bag.
   - Pros: Clear contract ("extra stuff goes in metadata"), discoverable
   - Cons: Agent must learn to put things in `metadata` rather than at the top level

3. **Both** — `.passthrough()` on schemas + explicit `metadata` field.
   - Pros: Flexible (agents can use either), robust (extra top-level keys are preserved even if the agent doesn't use `metadata`)
   - Cons: Two mechanisms for the same thing

**Decision:** Option 3 — Both. `.passthrough()` acts as a safety net so we never silently drop data. The `metadata` field is the recommended place for extra data and is documented in the prompt. In practice, prompts will guide agents to use `metadata`, but `.passthrough()` ensures we never lose information even if the agent puts extra fields at the top level. Downstream consumers that need to be strict can use `.strip()` on their end.

### Appendix F: Testing Strategy for Schema Migration

**Context:** How do we ensure that adding `.passthrough()` and `metadata` to existing schemas doesn't break console or other downstream consumers?

**Analysis:**
- `.passthrough()` is backward-compatible for *parsing* — it accepts all inputs that the strict schema accepted, plus more.
- `.passthrough()` is *not* backward-compatible for *output* — parsed objects may now have extra keys that weren't there before.
- Console reads specific fields from agent outputs (e.g., `findings[].title`, `findings[].severity`). Extra fields are ignored by TypeScript type narrowing and by `JSON.stringify` → UI rendering.
- The risk is in code that does `Object.keys(result)` or spread operations that might pick up extra keys.

**Mitigation:**
1. Schema conformance tests (Phase 0, Task 0.1) verify that existing valid inputs still parse correctly.
2. Add tests that verify `.passthrough()` preserves unknown keys.
3. Add tests that verify console-facing code only accesses known fields (audit via grep for `Object.keys`, spread patterns on agent outputs).
4. Add `metadata` as an explicitly optional field — existing code that doesn't read it is unaffected.

**Decision:** The combination of Phase 0 tests + the backward-compatible nature of `.passthrough()` makes this safe. Ship Phase 5 after Phase 0 tests are green.
