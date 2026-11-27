import tls from "node:tls";

let providerCAs: string[] | undefined;

export const providerFetch = ((
  input: RequestInfo | URL,
  init?: BunFetchRequestInit,
): Promise<Response> => {
  if (typeof Bun === "undefined" || !tls.getCACertificates || init?.tls?.ca) {
    return globalThis.fetch(input, init);
  }

  // Bun's fetch does not pick up changes made through tls.setDefaultCACertificates.
  providerCAs ??= [
    ...new Set([
      ...tls.getCACertificates("default"),
      ...tls.getCACertificates("system"),
    ]),
  ];
  return globalThis.fetch(input, {
    ...init,
    tls: { ...init?.tls, ca: providerCAs },
  });
}) as typeof fetch;
