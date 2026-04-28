import type { ConsolidatedEndpoint } from "./types";

/**
 * Page-vs-API classifier for surface-derived endpoints.
 *
 * Apex's `Endpoint.method = "PAGE"` is an apex-level marker for renderable
 * pages — a concept that doesn't exist in surface, which only emits real
 * HTTP methods plus `ACTION` (Server Actions) and `WS` (WebSockets).
 *
 * Rules (see design doc section 1.4):
 *   - Next.js App Router `page.{ts,tsx,js,jsx}` files → PAGE.
 *   - Next.js Pages Router files under `pages/` (excluding `pages/api/`) → PAGE.
 *   - Next.js App Router `route.{ts,tsx,js,jsx}` files → API (preserve method).
 *   - `framework === "server_actions"` (always `method = ["ACTION"]`) → API.
 *   - `method` includes `"WS"` → API (real-time channel).
 *   - Everything else → API with the original method array preserved.
 *
 * v1 scope note:
 * Frameworks that mix server-rendered HTML pages with API endpoints
 * (Rails view-rendering controllers, Django CBV `template_name`, FastAPI
 * `HTMLResponse`, Spring `@Controller` returning view names) are
 * deliberately NOT classified as PAGE in v1. They pass through as their
 * actual HTTP method (typically GET). This is a known precision loss; the
 * eval suite tracks it. Apps using these frameworks are expected to land
 * on the agentic fallback path until the classifier is extended. See
 * `.jraad/docs/design-docs/20260428123342-apex-surface-npm-integration.md`
 * for the rationale and rollout plan.
 */

const NEXTJS_PAGE_FILE_RE = /(?:^|\/)page\.(?:t|j)sx?$/;
const NEXTJS_ROUTE_FILE_RE = /(?:^|\/)route\.(?:t|j)sx?$/;
// Pages Router files: anything under `pages/` that is NOT under `pages/api/`.
// Examples that match: `pages/index.tsx`, `pages/dashboard/[id].tsx`.
// Examples that don't: `pages/api/users.ts`, `pages/_app.tsx` (handled below).
const NEXTJS_PAGES_DIR_RE = /(?:^|\/)pages\//;
const NEXTJS_PAGES_API_RE = /(?:^|\/)pages\/api\//;
// Pages Router special files like `_app.tsx`, `_document.tsx`, `_error.tsx`
// are framework chrome rather than user-visible pages — exclude them.
const NEXTJS_PAGES_SPECIAL_RE =
  /(?:^|\/)pages\/_(?:app|document|error|middleware)\.(?:t|j)sx?$/;

function isNextjsPage(file: string): boolean {
  if (NEXTJS_PAGE_FILE_RE.test(file)) return true;
  if (NEXTJS_PAGES_DIR_RE.test(file) && !NEXTJS_PAGES_API_RE.test(file)) {
    if (NEXTJS_PAGES_SPECIAL_RE.test(file)) return false;
    // Only treat React-ish source files as pages; ignore stray .ts/.js helpers
    // that happen to live under `pages/`.
    return /\.(?:t|j)sx?$/.test(file);
  }
  return false;
}

function isNextjsRoute(file: string): boolean {
  return NEXTJS_ROUTE_FILE_RE.test(file);
}

export interface ClassifiedEndpoint {
  method: string[];
  isPage: boolean;
}

export function classifyEndpoint(ep: ConsolidatedEndpoint): ClassifiedEndpoint {
  if (ep.framework === "nextjs") {
    if (isNextjsPage(ep.file)) {
      return { method: ["PAGE"], isPage: true };
    }
    if (isNextjsRoute(ep.file)) {
      return { method: ep.method, isPage: false };
    }
    // Other Next.js files (e.g. middleware) — pass through as API.
    return { method: ep.method, isPage: false };
  }

  if (ep.framework === "server_actions") {
    return { method: ep.method, isPage: false };
  }

  if (ep.method.includes("WS")) {
    return { method: ep.method, isPage: false };
  }

  return { method: ep.method, isPage: false };
}
