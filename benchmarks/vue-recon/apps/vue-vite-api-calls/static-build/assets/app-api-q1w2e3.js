const apiBase = import.meta.env.VITE_API_URL || "/api";
const client = {
  get: (path) => fetch(`${apiBase}${path}`),
};

client.get("/account");
fetch(`${apiBase}/feature-flags`);
fetch(`/api/search?q=${encodeURIComponent("demo")}`);
fetch("/api/billing/invoices");
fetch(`/api/billing/invoices/${window.__INVOICE_ID__ || "inv_demo"}`);
fetch("https://analytics.example.invalid/collect", { method: "POST" });

window.__VUE_ROUTER__ = {
  getRoutes: () => [
    { path: "/" },
    { path: "/account" },
    { path: "/billing" },
  ],
};
