import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { z } from "zod";
import type { SubagentSpawner } from "../subagentSpawner";
import {
  createDocumentEndpointExecutor,
  type DocumentEndpointInput,
} from "./documentEndpoint";
import {
  DOCUMENT_ENDPOINT_BATCH_SIZE,
  documentEndpoints,
  documentEndpointsInputSchema,
} from "./documentEndpoints";
import type { ToolContext } from "./types";

const roots: string[] = [];
const options = { toolCallId: "batch-call", messages: [] };
type BatchResult = {
  success: boolean;
  endpoints: Array<Record<string, unknown>>;
  succeeded: number;
  failed: number;
};

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function context() {
  const rootPath = mkdtempSync(join(tmpdir(), "apex-endpoint-batch-"));
  roots.push(rootPath);
  const spawnMany = vi.fn(
    async <TItem, TResult>(
      items: readonly TItem[],
      worker: (item: TItem, index: number) => Promise<TResult>,
      _opts: { concurrency: number; abortSignal?: AbortSignal },
    ): Promise<(TResult | null)[]> =>
      Promise.all(
        items.map(async (item, index) => {
          try {
            return await worker(item, index);
          } catch {
            return null;
          }
        }),
      ),
  );
  const ctx = {
    agentCwd: rootPath,
    session: {
      id: "ses_batch",
      rootPath,
      targets: ["https://example.com"],
    },
    subagentSpawner: {
      spawn: vi.fn(),
      spawnMany,
    } as unknown as SubagentSpawner,
  } as ToolContext;
  return { ctx, rootPath, spawnMany };
}

function endpoint(routePath: string) {
  return {
    appName: "API",
    routePath,
    endpointType: "api-endpoint" as const,
    description: `Handler for ${routePath}`,
    method: "GET",
    riskLevel: "MEDIUM" as const,
  };
}

async function executeBatch(
  ctx: ToolContext,
  input: z.infer<typeof documentEndpointsInputSchema>,
): Promise<BatchResult> {
  const execute = documentEndpoints(ctx).execute;
  if (!execute) throw new Error("document_endpoints has no executor");
  return (await execute(input, options)) as BatchResult;
}

describe("document_endpoints", () => {
  it("rejects inputs above the fixed batch bound", () => {
    expect(
      documentEndpointsInputSchema.safeParse({
        endpoints: Array.from(
          { length: DOCUMENT_ENDPOINT_BATCH_SIZE + 1 },
          (_, index) => endpoint(`/route-${index}`),
        ),
        toolCallDescription: "oversized batch",
      }).success,
    ).toBe(false);
  });

  it("documents up to four endpoints through one bounded spawnMany call", async () => {
    const { ctx, rootPath, spawnMany } = context();
    const routes = ["/a", "/b", "/c", "/d"];

    const result = await executeBatch(ctx, {
      endpoints: routes.map(endpoint),
      toolCallDescription: "Document API routes",
    });

    expect(spawnMany).toHaveBeenCalledOnce();
    expect(spawnMany.mock.calls[0]?.[2]).toEqual({
      concurrency: DOCUMENT_ENDPOINT_BATCH_SIZE,
      abortSignal: undefined,
      scope: "batch-call",
    });
    expect(result).toMatchObject({
      success: true,
      succeeded: 4,
      failed: 0,
    });
    expect(result.endpoints.map((item) => item.routePath)).toEqual(routes);
    const appDir = join(rootPath, "assets", "api");
    expect(existsSync(appDir)).toBe(true);
    expect(readdirSync(appDir)).toHaveLength(4);
  });

  it("keeps successful siblings when one endpoint is rejected", async () => {
    const { ctx } = context();

    const result = await executeBatch(ctx, {
      endpoints: [endpoint("/ok"), endpoint("https://example.com/not-a-path")],
      toolCallDescription: "Document mixed routes",
    });

    expect(result).toMatchObject({
      success: true,
      succeeded: 1,
      failed: 1,
    });
    expect(result.endpoints[0]).toMatchObject({
      success: true,
      routePath: "/ok",
    });
    expect(result.endpoints[1]).toMatchObject({
      success: false,
      error: "routePath_is_url",
    });
  });

  it("releases the registry claim when endpoint enrichment is cancelled", async () => {
    const { ctx } = context();
    const abort = new AbortController();
    const cancellation = new DOMException("cancelled", "AbortError");
    abort.abort(cancellation);
    const unregister = vi.fn(async () => {});
    ctx.abortSignal = abort.signal;
    ctx.attackSurfaceRegistry = {
      register: vi.fn(async () => ({ duplicate: false })),
      unregister,
    } as never;

    await expect(
      createDocumentEndpointExecutor(ctx)({
        ...endpoint("/cancelled"),
        toolCallDescription: "Document cancelled endpoint",
      } satisfies DocumentEndpointInput),
    ).rejects.toBe(cancellation);
    expect(unregister).toHaveBeenCalledOnce();
  });
});
