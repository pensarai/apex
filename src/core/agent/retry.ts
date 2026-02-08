/**
 * Shared retry utilities for agent execution.
 *
 * Provides exponential backoff retry logic for handling API overload errors
 * (429, 529, 503) across all agent types.
 */

export const RETRY_CONFIG = {
  maxRetries: 5,
  initialDelayMs: 1000,
  maxDelayMs: 60000,
  backoffMultiplier: 2,
};

export function isOverloadedError(error: any): boolean {
  const message = error?.message?.toLowerCase() || '';
  const status = error?.status || error?.statusCode;

  return (
    status === 429 ||
    status === 529 ||
    status === 503 ||
    message.includes('overloaded') ||
    message.includes('rate limit') ||
    message.includes('too many requests') ||
    message.includes('capacity') ||
    message.includes('temporarily unavailable')
  );
}

export function isContextTooLongError(error: any): boolean {
  const message = error?.message?.toLowerCase() || '';
  const status = error?.status || error?.statusCode;
  return (
    status === 400 &&
    (message.includes('too long') ||
      message.includes('context length') ||
      message.includes('maximum context') ||
      message.includes('input is too long'))
  );
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
