import { existsSync } from "node:fs";
import { extname, join, resolve } from "node:path";

const publicRoot = resolve(import.meta.dir, "public");

const projects = [
  { id: "alpha", name: "Alpha Migration", owner: "alice@example.test" },
  { id: "bravo", name: "Bravo Launch", owner: "bob@example.test" },
];

const users = [
  { id: "u_1", email: "admin@example.test", role: "admin" },
  { id: "u_2", email: "analyst@example.test", role: "analyst" },
];

const profile = {
  email: "analyst@example.test",
  displayName: "Vue Analyst",
  mfaEnabled: true,
};

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

function json(data: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(data, null, 2), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...init?.headers,
    },
  });
}

function readBody(request: Request): Promise<unknown> {
  return request.text().then((body) => {
    if (!body) return {};
    try {
      return JSON.parse(body);
    } catch {
      return {};
    }
  });
}

function staticResponse(pathname: string): Response {
  const relativePath = pathname === "/" ? "index.html" : pathname.slice(1);
  const filePath = resolve(publicRoot, relativePath);

  if (!(filePath === publicRoot || filePath.startsWith(`${publicRoot}/`))) {
    return new Response("Forbidden", { status: 403 });
  }

  if (existsSync(filePath)) {
    return new Response(Bun.file(filePath), {
      headers: {
        "content-type": MIME_TYPES[extname(filePath)] ?? "text/plain",
      },
    });
  }

  return new Response(Bun.file(join(publicRoot, "index.html")), {
    headers: { "content-type": MIME_TYPES[".html"] },
  });
}

const server = Bun.serve({
  port: Number(process.env.PORT ?? 4173),
  async fetch(request) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (pathname === "/api/session" && request.method === "GET") {
      return json({ authenticated: true, user: profile });
    }

    if (pathname === "/api/login" && request.method === "POST") {
      const body = await readBody(request);
      return json({ ok: true, received: body });
    }

    if (pathname === "/api/dashboard/summary" && request.method === "GET") {
      return json({ activeProjects: projects.length, openRisks: 3 });
    }

    if (pathname === "/api/projects" && request.method === "GET") {
      return json(projects);
    }

    const projectMatch = pathname.match(/^\/api\/projects\/([^/]+)$/);
    if (projectMatch && request.method === "GET") {
      const project = projects.find((item) => item.id === projectMatch[1]);
      return project
        ? json(project)
        : json({ error: "not_found" }, { status: 404 });
    }

    if (pathname === "/api/admin/users" && request.method === "GET") {
      return json(users);
    }

    if (pathname === "/api/settings/profile" && request.method === "GET") {
      return json(profile);
    }

    if (pathname.startsWith("/api/")) {
      return json({ error: "not_found" }, { status: 404 });
    }

    return staticResponse(pathname);
  },
});

console.log(`Vue enterprise mock listening on http://127.0.0.1:${server.port}`);
