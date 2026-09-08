// Custom VitePress theme for the Dwara docs site.
//
// Extends the default theme and overrides the `Mermaid` global component
// (registered by vitepress-plugin-mermaid) with a local variant that fixes
// multi-line label clipping and adds zoom in/out/reset controls.
//
// The override works because VitePress calls the theme's `enhanceApp` hook
// after the plugin's transform has registered its component, so a later
// `app.component("Mermaid", ...)` call wins.
import DefaultTheme from "vitepress/theme";
import type { Theme } from "vitepress";
import { enhanceApp } from "vitepress/theme";
import Mermaid from "./Mermaid.vue";

import "./style.css";

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    // Override the plugin's Mermaid component with our enhanced version.
    app.component("Mermaid", Mermaid);
  },
} satisfies Theme;
