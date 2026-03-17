import type {
  WorkspaceInfo,
  FetchWorkspacesResponse,
  SelectWorkspaceResponse,
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
