import {
  getPensarApiUrl,
  getPensarConsoleUrl,
} from "../../../src/core/api/constants";
import {
  disconnect,
  ensureValidToken,
  fetchWorkspaces,
  isConnected,
  pollForWorkspaceCreation,
  pollLegacyToken,
  pollWorkOSToken,
  selectWorkspace,
  startDeviceFlow,
  validateGateway,
} from "../../../src/core/auth";
import { config } from "../../../src/core/config";
import type { AccountState, SettingsRequests } from "./contract";

export function createAccount(openExternal: (url: string) => void) {
  const apiUrl = getPensarApiUrl();
  let state: AccountState = { stage: "idle" };
  let controller: AbortController | undefined;
  let billingUrl: string | undefined;
  function open(url: string) {
    const parsed = new URL(url);
    if (!["https:", "http:"].includes(parsed.protocol))
      throw new Error("Expected a web URL.");
    openExternal(parsed.href);
  }

  async function select(token: string, id: string, signal: AbortSignal) {
    const result = await selectWorkspace(apiUrl, token, id);
    signal.throwIfAborted();
    await config.update({
      workspaceId: result.workspace.id,
      workspaceSlug: result.workspace.slug,
      gatewaySigningKey: result.signingKey ?? null,
      gatewayUrl: result.gatewayUrl ?? null,
    });
    signal.throwIfAborted();
    billingUrl = result.billingUrl;
    state = {
      stage: "connected",
      workspace: result.workspace.name,
      canSwitch: true,
      balance: result.billing.balance,
      billingReady: result.billing.ready && result.confirmed,
    };
  }
  async function workspaces(token: string, signal: AbortSignal) {
    const result = await fetchWorkspaces(apiUrl, token);
    signal.throwIfAborted();
    let choices = result.workspaces;
    if (!choices.length) {
      const url = new URL(
        "/create-workspace?redirect=/credits",
        result.consoleUrl ?? getPensarConsoleUrl(),
      ).href;
      state = { stage: "create", url };
      open(url);
      choices = await pollForWorkspaceCreation(apiUrl, token, signal);
      signal.throwIfAborted();
    }
    if (choices.length === 1) return select(token, choices[0]!.id, signal);
    state = {
      stage: "choose",
      workspaces: choices.map(({ id, name }) => ({ id, name })),
    };
  }

  async function login(signal: AbortSignal) {
    const flow = await startDeviceFlow(apiUrl);
    signal.throwIfAborted();
    if (flow.mode === "workos") {
      const info = flow.deviceInfo;
      state = {
        stage: "authorize",
        url: info.verification_uri_complete,
        code: info.user_code,
      };
      open(state.url);
      const tokens = await pollWorkOSToken({
        clientId: flow.clientId,
        deviceCode: info.device_code,
        expiresIn: info.expires_in,
        interval: info.interval,
        signal,
      });
      signal.throwIfAborted();
      await config.update({
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        pensarAPIKey: null,
        workspaceId: null,
        workspaceSlug: null,
        gatewaySigningKey: null,
        gatewayUrl: null,
      });
      signal.throwIfAborted();
      await workspaces(tokens.accessToken, signal);
    } else {
      const info = flow.deviceInfo;
      state = {
        stage: "authorize",
        url: info.verificationUriComplete,
        code: info.userCode,
      };
      open(state.url);
      const result = await pollLegacyToken({
        apiUrl,
        clientId: flow.clientId,
        deviceCode: info.deviceCode,
        expiresIn: info.expiresIn,
        interval: info.interval,
        signal,
      });
      signal.throwIfAborted();
      if (!result.apiKey)
        throw new Error("Console did not return a credential.");
      await config.update({
        accessToken: null,
        refreshToken: null,
        pensarAPIKey: result.apiKey,
        workspaceId: result.workspace?.id ?? null,
        workspaceSlug: result.workspace?.slug ?? null,
        gatewaySigningKey: result.signingKey ?? null,
        gatewayUrl: result.gatewayUrl ?? null,
      });
      signal.throwIfAborted();
      state = {
        stage: "connected",
        workspace: result.workspace?.name,
        balance: result.credits?.balance,
      };
    }
  }

  function cancel() {
    controller?.abort();
    controller = undefined;
  }
  function begin(task: (signal: AbortSignal) => Promise<void>) {
    cancel();
    const next = new AbortController();
    controller = next;
    state = { stage: "loading" };
    void task(next.signal)
      .catch((error) => {
        if (!next.signal.aborted)
          state = {
            stage: "error",
            message: error instanceof Error ? error.message : String(error),
          };
      })
      .finally(() => {
        if (controller === next) controller = undefined;
      });
  }
  return {
    dispose: cancel,
    status: () => state,
    action: async (
      params: SettingsRequests["accountAction"]["params"],
    ): Promise<AccountState> => {
      if (params.action === "billing") {
        open(billingUrl ?? new URL("/credits", getPensarConsoleUrl()).href);
        return state;
      }
      if (params.action === "cancel") {
        cancel();
        state = { stage: "idle" };
        return state;
      }
      if (params.action === "disconnect") {
        cancel();
        await disconnect();
        billingUrl = undefined;
        state = { stage: "idle" };
        return state;
      }
      if (params.action === "login") {
        billingUrl = undefined;
        begin(login);
        return state;
      }
      if (params.action === "inspect" && controller) return state;
      const previous = state;
      begin(async (signal) => {
        const cfg = await config.get();
        signal.throwIfAborted();
        const token = await ensureValidToken(cfg);
        signal.throwIfAborted();
        if (!token) {
          state = { stage: "idle", storedCredentials: isConnected(cfg) };
        } else if (params.action === "select") {
          if (
            token.type !== "workos" ||
            previous.stage !== "choose" ||
            !previous.workspaces.some((w) => w.id === params.id)
          )
            throw new Error("Select an available workspace.");
          await select(token.token, params.id, signal);
        } else if (
          token.type === "workos" &&
          (params.action === "switch" || !cfg.workspaceId)
        ) {
          await workspaces(token.token, signal);
        } else {
          state = {
            stage: "connected",
            workspace: cfg.workspaceSlug ?? undefined,
            canSwitch: token.type === "workos",
          };
        }
      });
      return state;
    },
    async balance() {
      const result = await validateGateway();
      return result
        ? { balance: result.credits.balance, workspace: result.workspace.name }
        : null;
    },
  };
}
