<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<template>
  <div class="app-shell">
    <header class="app-header">
      <span class="app-title">{{ t("app.title") }}</span>
      <span
        v-if="version"
        class="app-version"
      >v{{ version }}</span>
      <span class="app-spacer" />
      <select
        v-model="locale"
        class="lang-select"
      >
        <option value="en">
          EN
        </option>
        <option value="tr">
          TR
        </option>
      </select>
    </header>
    <main class="app-main">
      <router-view />
    </main>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";

const { t, locale } = useI18n();
const version = ref<string | null>(null);

onMounted(async () => {
  try {
    const resp = await fetch("/api/version");
    if (resp.ok) {
      version.value = (await resp.json()).version;
    }
  } catch {
    /* backend not running yet */
  }
});
</script>

<style>
:root {
  font-family: ui-sans-serif, system-ui, sans-serif;
}
body, html, #app {
  margin: 0;
  height: 100%;
}
.app-shell {
  display: flex;
  flex-direction: column;
  height: 100vh;
}
.app-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem 1rem;
  border-bottom: 1px solid #e2e8f0;
}
.app-title { font-weight: 600; }
.app-version { color: #64748b; font-size: 0.85rem; }
.app-spacer { flex: 1; }
.app-main { flex: 1; overflow: auto; padding: 1rem; }
</style>
