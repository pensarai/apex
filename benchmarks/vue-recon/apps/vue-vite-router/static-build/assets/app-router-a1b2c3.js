const routes = [
  { path: "/", component: "HomeView" },
  { path: "/dashboard", component: () => import("./dashboard-d4e5f6.js") },
  { path: "/dashboard/reports", component: () => import("./reports-f7g8h9.js") },
  { path: "/projects", component: "ProjectsView" },
  { path: "/projects/:projectId", component: () => import("./project-j1k2l3.js") },
  { path: "/settings/profile", component: () => import("./profile-m4n5o6.js") },
];

fetch("/api/session");
fetch("/api/projects");
fetch(`/api/projects/${window.__PROJECT_ID__ || "demo"}`);
fetch("/api/reports/monthly");

window.__VUE_ROUTER__ = {
  getRoutes: () => routes,
  options: { routes },
};
