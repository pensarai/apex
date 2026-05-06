import { tool } from "ai";
import { z } from "zod";
import { assertUrlInScope, ScopeViolationError } from "./scopeGuard";
import type { ToolContext } from "./types";

/**
 * Factory for the `test_endpoint_variations` tool.
 *
 * Tests multiple endpoint URLs for accessibility, useful for
 * probing authorization issues and mapping live routes.
 */
export function testEndpointVariations(ctx: ToolContext) {
  return tool({
    description: `Test multiple variations of an endpoint pattern with different parameters.

Use this to:
- Test an endpoint with multiple IDs to check for authorization issues
- Test related endpoints that follow similar patterns
- Systematically probe endpoint variations you've identified`,
    inputSchema: z.object({
      endpoints: z.array(z.string()).describe("Array of endpoint URLs to test"),
      sessionCookie: z
        .string()
        .optional()
        .describe("Session cookie if authentication required"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async (params) => {
      try {
        for (const endpoint of params.endpoints) {
          assertUrlInScope(endpoint, ctx);
        }
      } catch (e) {
        if (e instanceof ScopeViolationError) {
          return { success: false, message: e.message };
        }
        throw e;
      }

      try {
        const { endpoints, sessionCookie } = params;

        const results: Array<{
          endpoint: string;
          status: number;
          accessible: boolean;
          contentLength?: number;
          error?: string;
        }> = [];
        const accessible: Array<string> = [];
        const inaccessible: Array<string> = [];

        for (const endpoint of endpoints) {
          try {
            const request: RequestInit = { method: "GET" };
            if (sessionCookie) {
              request.headers = { Cookie: sessionCookie };
            }

            const result = await fetch(endpoint, request);
            const body = await result.text();

            results.push({
              endpoint,
              status: result.status,
              accessible: result.status >= 200 && result.status < 400,
              contentLength: body ? body.length : 0,
            });

            if (result.status >= 200 && result.status < 400) {
              accessible.push(endpoint);
            } else {
              inaccessible.push(endpoint);
            }
          } catch (error: unknown) {
            const errorMsg =
              error instanceof Error ? error.message : String(error);
            results.push({
              endpoint,
              status: 0,
              accessible: false,
              error: errorMsg,
            });
            inaccessible.push(endpoint);
          }
        }

        return {
          success: true,
          totalTested: endpoints.length,
          accessible: accessible.length,
          inaccessible: inaccessible.length,
          results,
          accessibleEndpoints: accessible,
          message: `Tested ${endpoints.length} endpoints. ${accessible.length} accessible, ${inaccessible.length} not accessible.`,
        };
      } catch (error: unknown) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          message: `Endpoint testing error: ${errorMsg}`,
        };
      }
    },
  });
}
