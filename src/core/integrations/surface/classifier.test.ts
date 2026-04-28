import { describe, it, expect } from "vitest";
import { classifyEndpoint } from "./classifier";
import type { ConsolidatedEndpoint } from "./types";

function makeEndpoint(
  overrides: Partial<ConsolidatedEndpoint> &
    Pick<ConsolidatedEndpoint, "framework" | "file" | "method">,
): ConsolidatedEndpoint {
  return {
    path: "/",
    handler: "handler",
    line: 1,
    auth: [],
    internal: false,
    ...overrides,
  };
}

describe("classifyEndpoint", () => {
  it("classifies Next.js App Router page.tsx as PAGE", () => {
    const ep = makeEndpoint({
      framework: "nextjs",
      file: "app/dashboard/page.tsx",
      method: ["GET"],
      path: "/dashboard",
    });

    const result = classifyEndpoint(ep);

    expect(result).toEqual({ method: ["PAGE"], isPage: true });
  });

  it("classifies Next.js Pages Router file as PAGE", () => {
    const ep = makeEndpoint({
      framework: "nextjs",
      file: "pages/index.tsx",
      method: ["GET"],
      path: "/",
    });

    const result = classifyEndpoint(ep);

    expect(result).toEqual({ method: ["PAGE"], isPage: true });
  });

  it("classifies Next.js App Router route.ts as API with original method", () => {
    const ep = makeEndpoint({
      framework: "nextjs",
      file: "app/api/users/route.ts",
      method: ["GET", "POST"],
      path: "/api/users",
    });

    const result = classifyEndpoint(ep);

    expect(result).toEqual({ method: ["GET", "POST"], isPage: false });
  });

  it("classifies Server Actions (ACTION) as API", () => {
    const ep = makeEndpoint({
      framework: "server_actions",
      file: "app/actions.ts",
      method: ["ACTION"],
      path: "createUser",
      handler: "createUser",
    });

    const result = classifyEndpoint(ep);

    expect(result).toEqual({ method: ["ACTION"], isPage: false });
  });

  it("classifies WebSocket endpoints as API", () => {
    const ep = makeEndpoint({
      framework: "express",
      file: "src/server.ts",
      method: ["WS"],
      path: "/ws/notifications",
    });

    const result = classifyEndpoint(ep);

    expect(result).toEqual({ method: ["WS"], isPage: false });
  });

  it("classifies Express GET endpoints as API", () => {
    const ep = makeEndpoint({
      framework: "express",
      file: "src/routes/users.ts",
      method: ["GET"],
      path: "/users",
      handler: "listUsers",
    });

    const result = classifyEndpoint(ep);

    expect(result).toEqual({ method: ["GET"], isPage: false });
  });

  it("preserves multiple methods for consolidated endpoints", () => {
    const ep = makeEndpoint({
      framework: "express",
      file: "src/routes/items.ts",
      method: ["GET", "POST"],
      path: "/items",
      handler: "itemsHandler",
    });

    const result = classifyEndpoint(ep);

    expect(result).toEqual({ method: ["GET", "POST"], isPage: false });
  });
});
