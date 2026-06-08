import type { RouteRecordRaw } from "vue-router";
import HomeView from "./views/HomeView.vue";
import ProjectsView from "./views/ProjectsView.vue";

export const routes: RouteRecordRaw[] = [
  { path: "/", component: HomeView },
  {
    path: "/dashboard",
    component: () => import("./views/DashboardView.vue"),
    children: [
      {
        path: "reports",
        component: () => import("./views/ReportsView.vue"),
      },
    ],
  },
  { path: "/projects", component: ProjectsView },
  {
    path: "/projects/:projectId",
    component: () => import("./views/ProjectDetailView.vue"),
  },
  {
    path: "/settings/profile",
    component: () => import("./views/ProfileSettingsView.vue"),
  },
];
