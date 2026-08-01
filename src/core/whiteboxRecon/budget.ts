import type { ModelUsage } from "./types";

export interface ReconBudgetLimits {
  maxModelCalls: number;
  maxInputTokens: number;
  maxOutputTokens: number;
  maxDurationMs: number;
}

export const DEFAULT_RECON_BUDGET: ReconBudgetLimits = {
  maxModelCalls: 34,
  maxInputTokens: 1_500_000,
  maxOutputTokens: 250_000,
  maxDurationMs: 30 * 60 * 1_000,
};

export interface BudgetReservation {
  inputTokens: number;
  outputTokens: number;
}

export class ReconBudget {
  private modelCalls = 0;
  private reservedInputTokens = 0;
  private reservedOutputTokens = 0;
  private actualInputTokens = 0;
  private actualOutputTokens = 0;

  constructor(readonly limits: ReconBudgetLimits) {}

  reserve(reservation: BudgetReservation): void {
    const nextCalls = this.modelCalls + 1;
    const nextInput = this.reservedInputTokens + reservation.inputTokens;
    const nextOutput = this.reservedOutputTokens + reservation.outputTokens;
    if (nextCalls > this.limits.maxModelCalls) {
      throw new ReconBudgetExceededError(
        `model-call-limit:${nextCalls}>${this.limits.maxModelCalls}`,
      );
    }
    if (nextInput > this.limits.maxInputTokens) {
      throw new ReconBudgetExceededError(
        `input-token-limit:${nextInput}>${this.limits.maxInputTokens}`,
      );
    }
    if (nextOutput > this.limits.maxOutputTokens) {
      throw new ReconBudgetExceededError(
        `output-token-limit:${nextOutput}>${this.limits.maxOutputTokens}`,
      );
    }
    this.modelCalls = nextCalls;
    this.reservedInputTokens = nextInput;
    this.reservedOutputTokens = nextOutput;
  }

  record(usage: ModelUsage): void {
    this.actualInputTokens += usage.input_tokens;
    this.actualOutputTokens += usage.output_tokens;
  }

  snapshot(): {
    modelCalls: number;
    estimatedInputTokens: number;
    reservedOutputTokens: number;
    actualInputTokens: number;
    actualOutputTokens: number;
  } {
    return {
      modelCalls: this.modelCalls,
      estimatedInputTokens: this.reservedInputTokens,
      reservedOutputTokens: this.reservedOutputTokens,
      actualInputTokens: this.actualInputTokens,
      actualOutputTokens: this.actualOutputTokens,
    };
  }
}

export class ReconBudgetExceededError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReconBudgetExceededError";
  }
}

export function createReconAbortSignal(
  externalSignal: AbortSignal | undefined,
  durationMs: number,
): { signal: AbortSignal; dispose: () => void } {
  const controller = new AbortController();
  const abortFromExternal = () =>
    controller.abort(
      externalSignal?.reason ?? new DOMException("Aborted", "AbortError"),
    );
  if (externalSignal?.aborted) abortFromExternal();
  else
    externalSignal?.addEventListener("abort", abortFromExternal, {
      once: true,
    });
  const timeout = setTimeout(
    () =>
      controller.abort(
        new DOMException("Whitebox recon time budget exceeded", "TimeoutError"),
      ),
    durationMs,
  );
  timeout.unref?.();
  return {
    signal: controller.signal,
    dispose: () => {
      clearTimeout(timeout);
      externalSignal?.removeEventListener("abort", abortFromExternal);
    },
  };
}
