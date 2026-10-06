import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { PlaywrightMcpSession } from "../agents/offSecAgent/tools/playwrightMcp";
import { getPensarApiUrl } from "../api/constants";
import type { EmailInboxConfig } from "../session";
import { ManagedGoogleAuthError } from "./failures";
import { classifyGoogleBarrier } from "./googleBarriers";
import {
  type BrowserStorageState,
  cookieHeaderFromState,
  filterMixedDomainState,
  opaqueAuthHandle,
} from "./targetSession";
import { isAuthTransitUrl } from "./transit";

export type ManagedGoogleCredential = {
  identityId: string;
  email?: string;
  verificationUrl?: string;
  buttonSelector?: string;
  authBrokerHint?: string;
  workspaceId?: string;
  scanId?: string;
};

export type GoogleAuthCookie = {
  name: string;
  value: string;
  url: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: "Lax" | "Strict" | "None";
  path: string;
};

export type ManagedGoogleGrant = {
  token: string;
  nonce: string;
  issuer: string;
  cookie: GoogleAuthCookie;
};

const SOFTWARE_BROWSER_MARKERS = [
  "this browser or app may not be secure",
  "couldn't sign you in",
  "automated software",
];

export { classifyGoogleBarrier };

export function getIssuerUrl(): string {
  return (
    process.env.PENSAR_OIDC_ISSUER_URL ||
    process.env.NEXT_PUBLIC_OIDC_ISSUER_URL ||
    ""
  ).replace(/\/+$/, "");
}

export function detectTypedFailure(
  pageText: string,
): ManagedGoogleAuthError | null {
  const lower = pageText.toLowerCase();
  if (SOFTWARE_BROWSER_MARKERS.some((marker) => lower.includes(marker))) {
    return new ManagedGoogleAuthError(
      "automation_block",
      "Google blocked the software-controlled browser",
    );
  }
  if (lower.includes("access blocked") || lower.includes("app is blocked")) {
    return new ManagedGoogleAuthError(
      "admin_policy",
      "Google admin policy blocked sign-in",
    );
  }
  if (
    lower.includes("has not been invited") ||
    lower.includes("isn't a member")
  ) {
    return new ManagedGoogleAuthError(
      "target_membership",
      "Managed Google identity is not a member of the target",
    );
  }
  return null;
}

export function freezeModelToolsOnTransit(
  toolName: string,
  currentUrl: string,
  issuerUrl?: string,
): void {
  if (!isAuthTransitUrl(currentUrl, { issuerUrl })) return;
  const allowed = new Set([
    "browser_snapshot",
    "browser_tabs",
    "complete_authentication",
  ]);
  if (!allowed.has(toolName)) {
    throw new ManagedGoogleAuthError(
      "automation_block",
      `Model tools are frozen on auth-transit origins (${toolName})`,
    );
  }
}

export function extraScopesRequested(scopes: string[]): boolean {
  const allowed = new Set(["openid", "email", "profile"]);
  return scopes.some((scope) => {
    const trimmed = scope.trim().toLowerCase();
    if (!trimmed) return false;
    if (allowed.has(trimmed)) return false;
    return (
      trimmed.includes("gmail") ||
      trimmed.includes("drive") ||
      trimmed.startsWith("https://")
    );
  });
}

function serviceHeaders(): Record<string, string> {
  const token = process.env.PENSAR_API_KEY || "";
  return {
    "content-type": "application/json",
    authorization: token ? `Bearer ${token}` : "",
    "x-api-key": token,
  };
}

export async function mintManagedGoogleGrant(input: {
  workspaceId: string;
  identityId: string;
  scanId?: string;
  browserSessionId: string;
  targetOrigin: string;
}): Promise<ManagedGoogleGrant> {
  const response = await fetch(
    `${getPensarApiUrl()}/agents/managed-google/grant`,
    {
      method: "POST",
      headers: serviceHeaders(),
      body: JSON.stringify(input),
    },
  );
  if (!response.ok) {
    throw new ManagedGoogleAuthError(
      "identity_not_ready",
      `Could not mint a Google OIDC grant (${response.status})`,
    );
  }
  return (await response.json()) as ManagedGoogleGrant;
}

export async function persistFilteredTargetSession(input: {
  workspaceId: string;
  identityId: string;
  scanId?: string;
  targetOrigin: string;
  state: BrowserStorageState;
  issuerUrl?: string;
  sessionRootPath: string;
}): Promise<{ handle: string }> {
  const filtered = filterMixedDomainState(input.state, {
    targetOrigin: input.targetOrigin,
    issuerUrl: input.issuerUrl ?? getIssuerUrl(),
  });
  const handle = opaqueAuthHandle();
  const authDir = join(input.sessionRootPath, "auth");
  mkdirSync(authDir, { recursive: true });
  writeFileSync(
    join(authDir, "auth-data.json"),
    JSON.stringify({
      authenticated: true,
      strategy: "managed_google",
      handle,
      target: input.targetOrigin,
      timestamp: new Date().toISOString(),
    }),
  );
  writeFileSync(
    join(authDir, "target-session.json"),
    JSON.stringify({
      handle,
      cookies: cookieHeaderFromState(filtered),
      headers: {},
      timestamp: new Date().toISOString(),
    }),
    { mode: 0o600 },
  );

  if (process.env.PENSAR_API_KEY && input.workspaceId) {
    await fetch(`${getPensarApiUrl()}/agents/managed-google/session`, {
      method: "POST",
      headers: serviceHeaders(),
      body: JSON.stringify({
        workspaceId: input.workspaceId,
        identityId: input.identityId,
        scanId: input.scanId,
        targetOrigin: input.targetOrigin,
        state: filtered,
      }),
    }).catch(() => undefined);
  }

  return { handle };
}

export async function loadCachedTargetSession(input: {
  workspaceId: string;
  identityId: string;
  targetOrigin: string;
}): Promise<BrowserStorageState | null> {
  if (!process.env.PENSAR_API_KEY) return null;
  const url = new URL(`${getPensarApiUrl()}/agents/managed-google/session`);
  url.searchParams.set("workspaceId", input.workspaceId);
  url.searchParams.set("identityId", input.identityId);
  url.searchParams.set("targetOrigin", input.targetOrigin);
  const response = await fetch(url, { headers: serviceHeaders() });
  if (!response.ok) return null;
  const body = (await response.json()) as { state?: BrowserStorageState };
  return body.state ?? null;
}

export function managedGoogleMailboxInbox(input: {
  identityId: string;
  email: string;
}): EmailInboxConfig {
  return {
    provider: "http",
    id: `managed-google-${input.identityId}`,
    name: "Pensar Google agent mailbox",
    emailAddress: input.email,
    endpoint: `${getPensarApiUrl()}/agents/managed-google/mailbox/${input.identityId}`,
    token: process.env.PENSAR_API_KEY || "",
  };
}

function snapshotText(result: unknown): string {
  if (typeof result === "string") return result;
  try {
    return JSON.stringify(result);
  } catch {
    return String(result);
  }
}

async function trustedRun(
  session: PlaywrightMcpSession,
  code: string,
): Promise<unknown> {
  try {
    return await session.callTool("browser_run_code", { code });
  } catch {
    return null;
  }
}

async function focusGooglePopup(session: PlaywrightMcpSession): Promise<void> {
  await trustedRun(
    session,
    `async (page) => {
      const pages = page.context().pages();
      for (const candidate of pages) {
        const url = candidate.url();
        if (/accounts\\.google\\.com|google\\.com\\/o\\/oauth|google\\.com\\/signin/i.test(url)) {
          await candidate.bringToFront();
          return { url };
        }
      }
      return { url: page.url() };
    }`,
  );
}

async function clickBasicConsent(session: PlaywrightMcpSession): Promise<void> {
  await trustedRun(
    session,
    `async (page) => {
      const names = ['Continue', 'Allow', 'Next', 'I agree', 'Accept'];
      for (const name of names) {
        const button = page.getByRole('button', { name, exact: false });
        if (await button.count()) {
          try {
            await button.first().click({ timeout: 2000 });
            return { clicked: name };
          } catch {}
        }
      }
      return { clicked: null };
    }`,
  );
}

export async function completeManagedGoogleTransit(input: {
  session: PlaywrightMcpSession;
  verificationUrl: string;
  issuerUrl?: string;
  persist?: {
    workspaceId: string;
    identityId: string;
    scanId?: string;
    sessionRootPath: string;
  };
}): Promise<{ url: string }> {
  const issuerUrl = input.issuerUrl ?? getIssuerUrl();
  const deadline = Date.now() + 90_000;
  let lastUrl = (await input.session.currentUrl()) ?? "";

  while (Date.now() < deadline) {
    await focusGooglePopup(input.session);
    lastUrl = (await input.session.currentUrl()) ?? lastUrl;
    const pageText = snapshotText(
      await input.session.callTool("browser_snapshot", {}),
    );
    const failure = detectTypedFailure(pageText);
    if (failure) throw failure;
    if (
      extraScopesRequested(
        pageText.match(/https:\/\/www\.googleapis\.com\/auth\/[a-z._-]+/gi) ??
          [],
      )
    ) {
      throw new ManagedGoogleAuthError(
        "extra_scopes",
        "Target requested Google scopes beyond basic sign-in",
      );
    }
    if (!isAuthTransitUrl(lastUrl, { issuerUrl })) {
      break;
    }
    await clickBasicConsent(input.session);
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }

  lastUrl = (await input.session.currentUrl()) ?? lastUrl;
  if (isAuthTransitUrl(lastUrl, { issuerUrl })) {
    throw new ManagedGoogleAuthError(
      "callback_failure",
      "Google OIDC transit did not return to the target",
    );
  }

  if (input.verificationUrl) {
    try {
      const expected = new URL(input.verificationUrl).origin;
      const actual = lastUrl ? new URL(lastUrl).origin : "";
      if (actual !== expected) {
        await trustedRun(
          input.session,
          `async (page) => {
            await page.goto(${JSON.stringify(input.verificationUrl)}, { waitUntil: 'domcontentloaded', timeout: 20000 });
            return { url: page.url() };
          }`,
        );
        lastUrl = (await input.session.currentUrl()) ?? lastUrl;
      }
    } catch {
      throw new ManagedGoogleAuthError(
        "verification_failure",
        "Could not reach the authenticated verification URL",
      );
    }
  }

  if (input.persist) {
    const state = await input.session.captureStorageState();
    if (state) {
      await persistFilteredTargetSession({
        workspaceId: input.persist.workspaceId,
        identityId: input.persist.identityId,
        scanId: input.persist.scanId,
        targetOrigin: new URL(input.verificationUrl || lastUrl).origin,
        state,
        issuerUrl,
        sessionRootPath: input.persist.sessionRootPath,
      });
    }
  }

  return { url: lastUrl };
}
