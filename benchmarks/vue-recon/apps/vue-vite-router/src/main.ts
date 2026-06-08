import { createApp } from "vue";
import { createRouter, createWebHistory } from "vue-router";
import App from "./App.vue";
import { loadSession } from "./services/api";
import { routes } from "./router";

const router = createRouter({
  history: createWebHistory(),
  routes,
});

void loadSession();

createApp(App).use(router).mount("#app");
