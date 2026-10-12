export const OPENAI_PRO_TIMEOUT_MS = 35 * 60 * 1000;

let dispatcher: import("undici").Agent | undefined;

// Pro returns no bytes while reasoning, so both runtimes need a longer HTTP wait.
export const fetchOpenAIPro = (async (
  input: RequestInfo | URL,
  init?: RequestInit,
) => {
  const deadline = AbortSignal.timeout(OPENAI_PRO_TIMEOUT_MS);
  const signal = init?.signal
    ? AbortSignal.any([init.signal, deadline])
    : deadline;
  if (typeof Bun !== "undefined") {
    const options = { ...init, signal, timeout: false };
    return globalThis.fetch(input, options);
  }

  const { Agent, fetch } = await import("undici");
  dispatcher ??= new Agent({
    headersTimeout: OPENAI_PRO_TIMEOUT_MS,
    bodyTimeout: OPENAI_PRO_TIMEOUT_MS,
  });
  return fetch(
    input as import("undici").RequestInfo,
    {
      ...init,
      signal,
      dispatcher,
    } as import("undici").RequestInit,
  );
}) as typeof fetch;
