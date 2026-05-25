// SPDX-License-Identifier: GPL-2.0-or-later
import { createI18n } from "vue-i18n";
import en from "./locales/en.json";
import tr from "./locales/tr.json";

export const i18n = createI18n({
  legacy: false,
  locale: "en",
  fallbackLocale: "en",
  messages: { en, tr },
});
