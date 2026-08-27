import defineVersionedConfig from "vitepress-versioning-plugin";
import { withMermaid } from "vitepress-plugin-mermaid";

// dwara end-user documentation site.
//
// Versioning model (vitepress-versioning-plugin): the root of this project
// (guide/, architecture/, reference/, index.md) is always the "unstable"
// docs tracked from the `main` branch. `versioning.latestVersion` below is
// the *label* shown for that root content in the version switcher — it is
// deliberately the string "unstable", not a semver, because the root
// tracks main rather than a specific release.
//
// When a release is tagged, run `npm run docs:freeze -- <version>` BEFORE
// tagging (see scripts/freeze-version.mjs and the docs-site README) to
// snapshot the current root content into versions/<version>/. That
// directory is then a permanently frozen copy of the docs as they existed
// at that release; the root keeps evolving as "unstable" for the next one.
export default withMermaid(
  defineVersionedConfig(
    {
      title: "dwara",
      description: "API gateway documentation",
      lastUpdated: true,
      cleanUrls: true,
      // Published as a GitHub Pages PROJECT site
      // (shristilabs.github.io/dwara/, not a user/org root site), so every
      // asset/link must be rooted at /dwara/ or the CSS/JS 404 under the
      // real path while looking fine in local dev (which serves from /).
      base: "/dwara/",
      // README.md is this project's own (GitHub-rendered) contributor
      // README, not a page of the published site.
      srcExclude: ["README.md"],

      versioning: {
        latestVersion: "unstable",
      },

      themeConfig: {
        logo: undefined,
        nav: [
          { text: "Guide", link: "/guide/getting-started" },
          { text: "Architecture", link: "/architecture/overview" },
          { text: "Reference", link: "/reference/environment-variables" },
          {
            text: "Developer docs",
            link: "https://github.com/shristilabs/dwara/tree/main/docs",
          },
          // The plugin injects the version switcher into the nav array at
          // build time; no explicit entry is needed here (versionSwitcher
          // defaults to enabled). See .vitepress/theme/index.ts for the
          // richer VersionSwitcher component wiring.
        ],

        sidebar: {
          "/guide/": [
            {
              text: "Guide",
              items: [
                { text: "Getting started", link: "/guide/getting-started" },
                { text: "Installation", link: "/guide/installation" },
                { text: "Configuration", link: "/guide/configuration" },
                {
                  text: "CORS, compression, limits",
                  link: "/guide/edge-policies",
                },
                { text: "Secrets", link: "/guide/secrets" },
                { text: "Deployment", link: "/guide/deployment" },
                { text: "Operations", link: "/guide/operations" },
                { text: "Observability", link: "/guide/observability" },
                { text: "Admin API", link: "/guide/admin-api" },
                { text: "CLI", link: "/guide/cli" },
              ],
            },
          ],
          "/architecture/": [
            {
              text: "Architecture",
              items: [{ text: "Overview", link: "/architecture/overview" }],
            },
          ],
          "/reference/": [
            {
              text: "Reference",
              items: [
                {
                  text: "Environment variables",
                  link: "/reference/environment-variables",
                },
                {
                  text: "Configuration schema",
                  link: "/reference/configuration-schema",
                },
              ],
            },
          ],
        },

        socialLinks: [
          { icon: "github", link: "https://github.com/shristilabs/dwara" },
        ],

        editLink: {
          pattern:
            "https://github.com/shristilabs/dwara/edit/main/docs-site/:path",
          text: "Edit this page on GitHub",
        },

        search: {
          provider: "local",
        },
      },

      mermaid: {
        // Theme follows the site's light/dark mode automatically
        // (vitepress-plugin-mermaid detects `dark` in the <body> class).
      },
    },
    __dirname,
  ),
);
