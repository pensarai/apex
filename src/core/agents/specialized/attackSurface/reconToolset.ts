/**
 * Tool rosters shared by the generalized attack-surface agent and its
 * `recon-worker` sub-agents. Both get the same primitive toolset — browser,
 * shell, HTTP, code navigation, web search, repo cloning and app
 * documentation — so a worker spawned for a scoped goal has the same reach as
 * its parent. The orchestrator additionally gets the spawn + report tools; a
 * worker omits them so it cannot recursively fan out or finalize the run.
 */

/** Primitive toolset shared by the orchestrator and every recon worker. */
export const RECON_WORKER_TOOLS: string[] = [
  // Browser automation for SPAs, JS-heavy apps, and auth flows.
  "browser_navigate",
  "browser_snapshot",
  "browser_screenshot",
  "browser_click",
  "browser_fill",
  "browser_evaluate",
  "browser_console",
  "browser_get_cookies",
  // Shell + HTTP probing.
  "execute_command",
  "http_request",
  // Code navigation over cloned repositories.
  "read_file",
  "list_files",
  "glob",
  "grep",
  // Research.
  "web_search",
  "get_page",
  // Map an origin to source and document discovered services.
  "clone_repository",
  "document_app",
  // Email / SMS (filtered out by the base class when none are configured).
  "email_list_inboxes",
  "email_list_messages",
  "email_search_messages",
  "email_get_message",
  "send_email",
  "sms_list_messages",
];

/**
 * The orchestrator's roster: the shared primitives plus the ability to spawn
 * scoped recon workers and to finalize the run with an attack-surface report.
 */
export const GENERALIZED_ATTACK_SURFACE_TOOLS: string[] = [
  ...RECON_WORKER_TOOLS,
  "spawn_recon_agent",
  "create_attack_surface_report",
];
