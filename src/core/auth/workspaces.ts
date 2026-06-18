import type {
  CreateWorkspaceSelectionResponse,
  FetchWorkspacesResponse,
  SelectWorkspaceResponse,
  WorkspaceInfo,
  WorkspaceSelectionStatusResponse,
} from "./types";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Fetch the list of workspaces visible to the authenticated user.
 * Also returns the optional consoleUrl if provided by the server.
 */
export async function fetchWorkspaces(
  apiUrl: string,
  accessToken: string,
): Promise<FetchWorkspacesResponse> {
  const response = await fetch(`${apiUrl}/api/cli/workspaces`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch workspaces (${response.status})`);
  }

  const data = (await response.json()) as {
    workspaces: WorkspaceInfo[];
    consoleUrl?: string;
  };
  return {
    workspaces: data.workspaces,
    consoleUrl: data.consoleUrl,
  };
}

/**
 * Poll until at least one workspace exists (e.g. after sending the user
 * to the Console to create one).
 *
 * Resolves with the workspace list once one or more workspaces appear.
 */
export async function pollForWorkspaceCreation(
  apiUrl: string,
  accessToken: string,
  signal?: AbortSignal,
): Promise<WorkspaceInfo[]> {
  const POLL_INTERVAL = 3000;
  const TIMEOUT = 5 * 60 * 1000;
  const deadline = Date.now() + TIMEOUT;

  while (Date.now() < deadline) {
    if (signal?.aborted) throw new Error("Cancelled");

    await sleep(POLL_INTERVAL);

    if (signal?.aborted) throw new Error("Cancelled");

    try {
      const response = await fetch(`${apiUrl}/api/cli/workspaces`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      if (!response.ok) continue;

      const data = (await response.json()) as {
        workspaces: WorkspaceInfo[];
      };

      if (data.workspaces.length > 0) {
        return data.workspaces;
      }
    } catch {
      // retry
    }
  }

  throw new Error("Workspace creation timed out. Please try again.");
}

/**
 * Select a workspace and confirm billing.
 *
 * Returns the server response which includes the gateway signing key
 * and billing status.
 */
export async function selectWorkspace(
  apiUrl: string,
  accessToken: string,
  workspaceId: string,
): Promise<SelectWorkspaceResponse> {
  const response = await fetch(`${apiUrl}/api/cli/select-workspace`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({ workspaceId }),
  });

  if (!response.ok) {
    throw new Error("Failed to select workspace");
  }

  return (await response.json()) as SelectWorkspaceResponse;
}

/**
 * Open a browser-based workspace selection rendezvous on the Console.
 *
 * Returns the selection id and the URL the user should open to pick a
 * workspace in the browser, keeping `pensar login` non-interactive.
 */
export async function createWorkspaceSelection(
  apiUrl: string,
  accessToken: string,
): Promise<CreateWorkspaceSelectionResponse> {
  const response = await fetch(`${apiUrl}/api/cli/workspace-selection`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error("Failed to start workspace selection");
  }

  return (await response.json()) as CreateWorkspaceSelectionResponse;
}

/**
 * Poll the Console until the user selects a workspace in the browser.
 *
 * Resolves with the chosen workspace id. Rejects on expiry, timeout, or
 * cancellation via the optional `AbortSignal`.
 */
export async function pollWorkspaceSelection(
  apiUrl: string,
  accessToken: string,
  selectionId: string,
  signal?: AbortSignal,
): Promise<string> {
  const POLL_INTERVAL = 3000;
  const TIMEOUT = 10 * 60 * 1000;
  const deadline = Date.now() + TIMEOUT;

  while (Date.now() < deadline) {
    if (signal?.aborted) throw new Error("Cancelled");

    await sleep(POLL_INTERVAL);

    if (signal?.aborted) throw new Error("Cancelled");

    try {
      const response = await fetch(
        `${apiUrl}/api/cli/workspace-selection?id=${encodeURIComponent(selectionId)}`,
        {
          headers: { Authorization: `Bearer ${accessToken}` },
        },
      );

      if (!response.ok) continue;

      const data = (await response.json()) as WorkspaceSelectionStatusResponse;

      if (data.status === "complete" && data.workspaceId) {
        return data.workspaceId;
      }

      if (data.status === "expired") {
        throw new Error(
          "Workspace selection expired. Please run `pensar login` again.",
        );
      }
    } catch (err) {
      if (signal?.aborted) throw new Error("Cancelled");
      if (err instanceof Error && err.message.includes("Please try again")) {
        throw err;
      }
      if (err instanceof Error && err.message.includes("expired")) {
        throw err;
      }
      // Network glitch — retry
    }
  }

  throw new Error("Workspace selection timed out. Please try again.");
}
