<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<template>
  <section>
    <h2>{{ t("home.welcome") }}</h2>
    <p>{{ t("home.status_phase_0") }}</p>

    <div class="row">
      <label>API token:</label>
      <input
        v-model="token"
        type="password"
        placeholder="X-API-Token"
      >
      <button @click="refresh">
        {{ t("home.refresh") }}
      </button>
    </div>

    <h3>{{ t("home.privileges") }}</h3>
    <pre v-if="privileges">{{ JSON.stringify(privileges, null, 2) }}</pre>
    <p
      v-else-if="error"
      class="error"
    >
      {{ error }}
    </p>

    <h3>{{ t("home.interfaces") }}</h3>
    <table v-if="interfaces.length">
      <thead><tr><th>name</th><th>mac</th><th>description</th></tr></thead>
      <tbody>
        <tr
          v-for="i in interfaces"
          :key="i.name"
        >
          <td>{{ i.name }}</td><td>{{ i.mac ?? "-" }}</td><td>{{ i.description ?? "-" }}</td>
        </tr>
      </tbody>
    </table>
  </section>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { useI18n } from "vue-i18n";

const { t } = useI18n();
const token = ref(localStorage.getItem("ieee1905.token") ?? "");
const privileges = ref<unknown | null>(null);
const interfaces = ref<Array<{ name: string; mac: string | null; description: string | null }>>([]);
const error = ref<string | null>(null);

async function refresh() {
  localStorage.setItem("ieee1905.token", token.value);
  error.value = null;
  try {
    const headers = { "X-API-Token": token.value };
    const [p, i] = await Promise.all([
      fetch("/api/privileges", { headers }),
      fetch("/api/interfaces", { headers }),
    ]);
    if (!p.ok || !i.ok) {
      error.value = `auth failed (${p.status}/${i.status}) — check token`;
      return;
    }
    privileges.value = await p.json();
    interfaces.value = await i.json();
  } catch (e) {
    error.value = String(e);
  }
}
</script>

<style scoped>
.row { display: flex; gap: 0.5rem; align-items: center; margin: 1rem 0; }
input { padding: 0.25rem 0.5rem; }
button { padding: 0.25rem 0.75rem; cursor: pointer; }
table { border-collapse: collapse; }
th, td { border: 1px solid #cbd5e1; padding: 0.25rem 0.5rem; text-align: left; }
.error { color: #b91c1c; }
pre { background: #f1f5f9; padding: 0.5rem; border-radius: 4px; }
</style>
