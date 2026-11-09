interface TestDomainSession {
  config?: { testDomains?: readonly string[] };
}

/** The session's test domains, lowercased and without a trailing dot. */
export function sessionTestDomains(session: TestDomainSession): string[] {
  return (session.config?.testDomains ?? [])
    .map((host) => host.trim().toLowerCase().replace(/\.$/, ""))
    .filter(Boolean);
}

export function isTestDomain(
  hostname: string,
  session: TestDomainSession,
): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return sessionTestDomains(session).includes(host);
}

/** {@link isTestDomain} for a URL; false for anything that doesn't parse. */
export function isTestDomainUrl(
  url: string,
  session: TestDomainSession,
): boolean {
  try {
    return isTestDomain(new URL(url).hostname, session);
  } catch {
    return false;
  }
}
