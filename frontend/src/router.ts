// SPDX-License-Identifier: GPL-2.0-or-later
import { createRouter, createWebHashHistory } from "vue-router";
import Home from "@/views/Home.vue";

export const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/", name: "home", component: Home },
  ],
});
