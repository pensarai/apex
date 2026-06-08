const pages = [
  "/",
  "/admin",
  "/blog",
  "/blog/:slug",
  "/profile/settings",
];

useFetch("/api/me");
$fetch("/api/admin/audit-log");
useFetch("/api/blog/posts");
$fetch(`/api/blog/posts/${window.__BLOG_SLUG__ || "hello-vue"}`);
useFetch("/api/profile/settings");

window.__NUXT__ = {
  routes: pages,
  config: { public: { apiBase: "/api" } },
};
