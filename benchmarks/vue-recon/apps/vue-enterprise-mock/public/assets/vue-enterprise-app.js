const routes = [
  { path: "/", name: "home" },
  { path: "/login", name: "login" },
  { path: "/dashboard", name: "dashboard" },
  { path: "/projects", name: "projects" },
  { path: "/projects/:projectId", name: "project-detail" },
  { path: "/admin/users", name: "admin-users", meta: { requiresAdmin: true } },
  { path: "/settings/profile", name: "profile-settings" },
];

const apiBase = import.meta.env?.VITE_API_URL || "/api";

const http = {
  get(path) {
    return fetch(`${apiBase}${path}`).then((response) => response.json());
  },
  post(path, body) {
    return fetch(`${apiBase}${path}`, {
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
      method: "POST",
    }).then((response) => response.json());
  },
};

async function boot() {
  await fetch("/api/session");
  await http.get("/dashboard/summary");
  await http.get("/projects");
  await fetch(`/api/projects/${window.__PROJECT_ID__ || "alpha"}`);
  await http.get("/admin/users");
  await http.get("/settings/profile");

  // External telemetry should be ignored as third-party infrastructure.
  navigator.sendBeacon?.("https://telemetry.example.invalid/vue-enterprise");
}

document.querySelector("#login-form")?.addEventListener("submit", (event) => {
  event.preventDefault();
  void http.post("/login", {
    email: "analyst@example.test",
    password: "password123",
  });
});

window.__VUE_ROUTER__ = {
  getRoutes: () => routes,
  options: { routes },
};

window.__VUE_APP_CONFIG__ = {
  apiBase,
};

void boot();
