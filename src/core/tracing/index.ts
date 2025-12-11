let weaveModule: typeof import('weave') | null = null;
let initialized = false;
let initializationFailed = false;

/**
 * Initialize Weave tracing if WANDB_API_KEY is set.
 * Returns true if Weave was successfully initialized.
 */
export async function initWeave(): Promise<boolean> {
  if (!process.env.WANDB_API_KEY) {
    return false;
  }

  if (initialized) {
    return true;
  }

  if (initializationFailed) {
    return false;
  }

  try {
    // Dynamically import weave only when needed
    weaveModule = await import('weave');
    await weaveModule.init(process.env.WANDB_PROJECT || 'apex-pentest-traces');
    initialized = true;
    console.log('[Weave] Tracing initialized');
    return true;
  } catch (error: any) {
    initializationFailed = true;
    weaveModule = null;
    console.warn('[Weave] Failed to initialize:', error?.message || error);
    return false;
  }
}

/**
 * Check if Weave tracing is enabled and initialized.
 */
export function isWeaveEnabled(): boolean {
  return initialized;
}

/**
 * Get the weave module (only available after initWeave succeeds).
 */
export function getWeave(): typeof import('weave') | null {
  return weaveModule;
}

/**
 * Create a traced operation wrapper. Returns a no-op if Weave is not initialized.
 * This should be called at runtime, not at module load time.
 */
export function createTracedOp<T extends (...args: any[]) => any>(
  name: string,
  fn: T
): T {
  if (!initialized || !weaveModule) {
    return fn;
  }
  return weaveModule.op(fn, { name }) as T;
}

// Cached traced wrappers for specific operations
let _tracedOrchestratorExecution: any = null;
let _tracedToolExecution: any = null;

/**
 * Get or create a traced wrapper for the orchestrator execution.
 * This wraps the entire pentest flow so all child operations nest under it.
 */
export function getTracedOrchestratorExecution() {
  if (_tracedOrchestratorExecution) return _tracedOrchestratorExecution;
  if (!weaveModule) return null;

  _tracedOrchestratorExecution = weaveModule.op(
    async function thoroughPentestOrchestrator<T>(
      params: { target: string; sessionId: string; model: string },
      executeFn: () => Promise<T>
    ): Promise<T> {
      return executeFn();
    }
  );
  return _tracedOrchestratorExecution;
}

/**
 * Get or create a traced wrapper for tool executions within the orchestrator.
 * When called within a traced orchestrator context, these will be children.
 */
export function getTracedToolExecution() {
  if (_tracedToolExecution) return _tracedToolExecution;
  if (!weaveModule) return null;

  _tracedToolExecution = weaveModule.op(
    async function toolExecution<T>(
      params: { toolName: string; input: any },
      executeFn: () => Promise<T>
    ): Promise<T> {
      return executeFn();
    }
  );
  return _tracedToolExecution;
}

/**
 * Execute a function within a traced orchestrator context.
 * All operations awaited within executeFn will be children of this trace.
 */
export async function withTracedOrchestrator<T>(
  params: { target: string; sessionId: string; model: string },
  executeFn: () => Promise<T>
): Promise<T> {
  const tracedFn = getTracedOrchestratorExecution();
  if (tracedFn) {
    try {
      return await tracedFn(params, executeFn);
    } catch (error) {
      // Silently fall back to untraced execution if Weave fails
      return executeFn();
    }
  }
  return executeFn();
}

/**
 * Execute a tool within a traced context.
 * When called within withTracedOrchestrator, this will be a child trace.
 */
export async function withTracedTool<T>(
  toolName: string,
  input: any,
  executeFn: () => Promise<T>
): Promise<T> {
  const tracedFn = getTracedToolExecution();
  if (tracedFn) {
    try {
      return await tracedFn({ toolName, input }, executeFn);
    } catch (error) {
      // Silently fall back to untraced execution if Weave fails
      return executeFn();
    }
  }
  return executeFn();
}

// Cached traced wrapper for subagents
let _tracedSubagentExecution: any = null;

/**
 * Get or create a traced wrapper for subagent execution.
 */
function getTracedSubagentExecution() {
  if (_tracedSubagentExecution) return _tracedSubagentExecution;
  if (!weaveModule) return null;

  _tracedSubagentExecution = weaveModule.op(
    async function subagentExecution<T>(
      params: { agentType: string; target: string; subagentId: string },
      executeFn: () => Promise<T>
    ): Promise<T> {
      return executeFn();
    }
  );
  return _tracedSubagentExecution;
}

/**
 * Execute a subagent within a traced context.
 * When called within withTracedTool (which is within withTracedOrchestrator),
 * this will be a grandchild trace.
 */
export async function withTracedSubagent<T>(
  agentType: string,
  target: string,
  subagentId: string,
  executeFn: () => Promise<T>
): Promise<T> {
  const tracedFn = getTracedSubagentExecution();
  if (tracedFn) {
    try {
      return await tracedFn({ agentType, target, subagentId }, executeFn);
    } catch (error) {
      // Silently fall back to untraced execution if Weave fails
      return executeFn();
    }
  }
  return executeFn();
}
