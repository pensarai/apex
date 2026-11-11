import { createOpenRouter } from "@openrouter/ai-sdk-provider";
import { wrapLanguageModel } from "ai";
import { signGatewayRequest } from "../../auth";
import type { PensarModelConfig } from "./pensar";

export function createPensarOpenRouterModel(
  modelId: string,
  config: PensarModelConfig,
) {
  const openrouter = createOpenRouter({
    apiKey: config.apiKey,
    baseURL: `${config.baseUrl}/v1`,
    fetch: (async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (typeof init?.body !== "string")
        throw new Error("Pensar inference requires a serialized request body");
      const headers = new Headers(init.headers);
      if (config.getToken) {
        const token = await config.getToken();
        if (!token) throw new Error("Pensar session expired. Run /login.");
        headers.set("Authorization", `Bearer ${token.token}`);
      }
      if (config.workspaceId) headers.set("X-Workspace-Id", config.workspaceId);
      if (config.signingKey) {
        const signed = signGatewayRequest(
          config.signingKey,
          modelId,
          init.body,
        );
        headers.set("X-Pensar-Signature", signed.signature);
        headers.set("X-Pensar-Timestamp", signed.timestamp);
        headers.set("X-Pensar-Nonce", signed.nonce);
      }
      return fetch(`${config.baseUrl}/v1/chat/completions`, {
        ...init,
        headers,
      });
    }) as typeof fetch,
  });
  return wrapLanguageModel({
    model: openrouter(modelId),
    modelId: `pensar:${modelId}`,
    providerId: "pensar",
    middleware: { specificationVersion: "v3" },
  });
}
