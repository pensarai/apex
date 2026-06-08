export default defineNuxtConfig({
  devtools: { enabled: false },
  routeRules: {
    "/admin": { ssr: false },
    "/blog/**": { swr: true },
  },
});
