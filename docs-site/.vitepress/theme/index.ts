// Custom VitePress theme for the Dwara docs site.
//
// - Extends the default theme and overrides the `Mermaid` global component
//   (registered by vitepress-plugin-mermaid) with a local variant that fixes
//   multi-line label clipping and adds zoom in/out/reset controls. The
//   override works because VitePress calls the theme's `enhanceApp` hook
//   after the plugin's transform has registered its component, so a later
//   `app.component("Mermaid", ...)` call wins.
// - `Layout` wraps the default Layout to customize the home page hero and
//   wire scroll-reveal motion (see HomeLayout.vue).
// - Registers the home-page section components (used from index.md).
// - Self-hosted Outfit variable font (brand typeface, see branding/README.md).
import DefaultTheme from "vitepress/theme";
import type { Theme } from "vitepress";
import { enhanceApp } from "vitepress/theme";
import Mermaid from "./Mermaid.vue";
import HomeLayout from "./HomeLayout.vue";
import HomeBands from "./HomeBands.vue";
import HomeEditions from "./HomeEditions.vue";
import HomeFlags from "./HomeFlags.vue";
import HomePersonas from "./HomePersonas.vue";
import HomeFAQ from "./HomeFAQ.vue";

import "@fontsource-variable/outfit";
import "./style.css";

export default {
  extends: DefaultTheme,
  Layout: HomeLayout,
  enhanceApp({ app }) {
    // Override the plugin's Mermaid component with our enhanced version.
    app.component("Mermaid", Mermaid);
    // Home-page section components (referenced from index.md).
    app.component("HomeBands", HomeBands);
    app.component("HomeEditions", HomeEditions);
    app.component("HomeFlags", HomeFlags);
    app.component("HomePersonas", HomePersonas);
    app.component("HomeFAQ", HomeFAQ);
  },
} satisfies Theme;
