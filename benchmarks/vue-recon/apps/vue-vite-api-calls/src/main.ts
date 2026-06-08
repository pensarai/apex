import { createApp } from "vue";
import { createRouter, createWebHistory } from "vue-router";
import App from "./App.vue";
import AccountView from "./views/AccountView.vue";
import BillingView from "./views/BillingView.vue";
import { loadAccount } from "./services/account";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", component: AccountView },
    { path: "/account", component: AccountView },
    { path: "/billing", component: BillingView },
  ],
});

void loadAccount();

createApp(App).use(router).mount("#app");
