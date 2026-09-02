import defineVersionedConfig from "vitepress-versioning-plugin";
import { withMermaid } from "vitepress-plugin-mermaid";

// Dwara end-user documentation site.
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
      title: "Dwara",
      description: "API gateway documentation",
      lastUpdated: true,
      cleanUrls: true,
      // Published as a GitHub Pages PROJECT site
      // (shristilabs.github.io/dwara/, not a user/org root site), so every
      // asset/link must be rooted at /dwara/ or the CSS/JS 404 under the
      // real path while looking fine in local dev (which serves from /).
      base: "/dwara/",

      // Favicons and PWA manifest live in docs-site/public/ and are served
      // from the site base (/dwara/). <head> link hrefs are NOT rewritten by
      // VitePress, so they carry the /dwara/ prefix explicitly to match the
      // published path (and the dev server, which also serves under base).
      // The themeConfig.logo below IS rewritten with withBase, so it uses a
      // base-relative /mark-icon.svg.
      head: [
        ["link", { rel: "icon", href: "/dwara/favicon.ico", sizes: "any" }],
        [
          "link",
          { rel: "icon", type: "image/png", sizes: "32x32", href: "/dwara/favicon-32x32.png" },
        ],
        [
          "link",
          { rel: "icon", type: "image/png", sizes: "16x16", href: "/dwara/favicon-16x16.png" },
        ],
        [
          "link",
          { rel: "apple-touch-icon", sizes: "180x180", href: "/dwara/apple-touch-icon.png" },
        ],
        ["link", { rel: "manifest", href: "/dwara/site.webmanifest" }],
        ["meta", { name: "theme-color", content: "#1B1650" }],
      ],
      // README.md is this project's own (GitHub-rendered) contributor
      // README, not a page of the published site.
      srcExclude: ["README.md"],

      versioning: {
        latestVersion: "unstable",
      },

      themeConfig: {
        // The nav logo is the Dwara mark on its indigo squircle (an app
        // icon), served from docs-site/public/. VitePress rewrites this
        // with withBase, so it resolves to /dwara/mark-icon.svg in prod.
        logo: "/mark-icon.svg",
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
              text: "Getting started",
              link: "/guide/getting-started",
              items: [
                { text: "Getting started", link: "/guide/getting-started" },
                { text: "Installation", link: "/guide/installation" },
                { text: "Configuration", link: "/guide/configuration" },
              ],
            },
            {
              text: "Deployment and operations",
              link: "/guide/deployment-operations",
              collapsed: false,
              items: [
                { text: "Overview", link: "/guide/deployment-operations" },
                { text: "Deployment", link: "/guide/deployment" },
                { text: "Operations", link: "/guide/operations" },
                {
                  text: "Zero-downtime upgrade",
                  link: "/guide/zero-downtime-upgrade",
                },
                { text: "CLI", link: "/guide/cli" },
                { text: "Admin API", link: "/guide/admin-api" },
                {
                  text: "Web console",
                  link: "/guide/web-console",
                },
                {
                  text: "Agent-operable administration",
                  link: "/guide/agent-operable-admin",
                },
                {
                  text: "Terraform state tool",
                  link: "/guide/terraform-state",
                },
              ],
            },
            {
              text: "Routing and request handling",
              link: "/guide/routing",
              collapsed: false,
              items: [
                { text: "Overview", link: "/guide/routing" },
                {
                  text: "CORS, compression, and request limits",
                  link: "/guide/edge-policies",
                },
                {
                  text: "Transforms and security headers",
                  link: "/guide/transforms",
                },
                {
                  text: "Response field masking",
                  link: "/guide/masking",
                },
                { text: "Response caching", link: "/guide/caching" },
                { text: "API versioning", link: "/guide/api-versioning" },
                {
                  text: "Traffic splitting and sticky sessions",
                  link: "/guide/traffic-splitting",
                },
                { text: "gRPC and WebSockets", link: "/guide/grpc-websockets" },
                {
                  text: "HTTP/3 ingress",
                  link: "/guide/http3",
                },
                {
                  text: "Dynamic upstream discovery",
                  link: "/guide/dynamic-discovery",
                },
                {
                  text: "OpenAPI import and mock mode",
                  link: "/guide/openapi-import",
                },
                {
                  text: "Config import (NGINX, Kong, Envoy)",
                  link: "/guide/config-import",
                },
                {
                  text: "API aggregation",
                  link: "/guide/api-aggregation",
                },
                {
                  text: "AI gateway",
                  link: "/guide/ai-gateway",
                },
                {
                  text: "OpenAPI response validation",
                  link: "/guide/openapi-response-validation",
                },
                {
                  text: "CEL expressions",
                  link: "/guide/cel-expressions",
                },
                {
                  text: "Kubernetes Gateway API",
                  link: "/guide/kubernetes-gateway-api",
                },
                {
                  text: "GraphQL awareness",
                  link: "/guide/graphql",
                },
                {
                  text: "gRPC-Web and transcoding",
                  link: "/guide/grpc-web",
                },
                {
                  text: "Protocol translation",
                  link: "/guide/protocol-translation",
                },
                {
                  text: "L4 TCP/UDP proxying",
                  link: "/guide/l4-proxying",
                },
                {
                  text: "Nano-services (WASM handlers)",
                  link: "/guide/nano-services",
                },
                {
                  text: "Replay time-travel debugging",
                  link: "/guide/replay-debugging",
                },
                {
                  text: "A2A protocol",
                  link: "/guide/a2a-protocol",
                },
              ],
            },
            {
              text: "Traffic policy and resilience",
              link: "/guide/traffic-policy",
              collapsed: false,
              items: [
                { text: "Overview", link: "/guide/traffic-policy" },
                {
                  text: "Maintenance mode and dry-run",
                  link: "/guide/maintenance",
                },
                { text: "Admission queues", link: "/guide/admission-queue" },
                { text: "WAF-lite filtering", link: "/guide/waf-lite" },
                { text: "Consumer quotas", link: "/guide/quotas" },
                {
                  text: "Request hedging",
                  link: "/guide/request-hedging",
                },
                {
                  text: "Mirroring and fault injection",
                  link: "/guide/mirroring-fault-injection",
                },
              ],
            },
            {
              text: "Security and authentication",
              link: "/guide/security",
              collapsed: false,
              items: [
                { text: "Overview", link: "/guide/security" },
                { text: "Secrets", link: "/guide/secrets" },
                {
                  text: "HMAC request signing",
                  link: "/guide/hmac-signing",
                },
                { text: "OAuth2 and mTLS", link: "/guide/oauth2-mtls" },
                { text: "OpenID Connect", link: "/guide/oidc" },
                { text: "Authorization rules", link: "/guide/authorization" },
                {
                  text: "Cedar and OPA authorization",
                  link: "/guide/cedar-opa-authz",
                },
                {
                  text: "Post-quantum TLS",
                  link: "/guide/post-quantum-tls",
                },
                {
                  text: "FIPS mode",
                  link: "/guide/fips-mode",
                },
                {
                  text: "Proxy-Wasm plugins",
                  link: "/guide/proxy-wasm-plugins",
                },
                {
                  text: "Native plugin filters",
                  link: "/guide/native-plugins",
                },
                {
                  text: "Extism plugin development kit",
                  link: "/guide/extism-pdk",
                },
                {
                  text: "Plugin lifecycle",
                  link: "/guide/plugin-lifecycle",
                },
                {
                  text: "Plugin SDK",
                  link: "/guide/plugin-sdk",
                },
              ],
            },
            {
              text: "Observability and analytics",
              link: "/guide/observability-analytics",
              collapsed: false,
              items: [
                { text: "Overview", link: "/guide/observability-analytics" },
                { text: "Observability", link: "/guide/observability" },
                { text: "Analytics", link: "/guide/analytics" },
                {
                  text: "Analytics stream",
                  link: "/guide/analytics-stream",
                },
                {
                  text: "Alert and event webhooks",
                  link: "/guide/webhooks",
                },
                {
                  text: "OTel metrics export",
                  link: "/guide/otel-metrics-export",
                },
                {
                  text: "Synthetic monitoring",
                  link: "/guide/synthetic-monitoring",
                },
              ],
            },
            {
              text: "Enterprise features",
              link: "/guide/enterprise",
              collapsed: false,
              items: [
                { text: "Overview", link: "/guide/enterprise" },
                {
                  text: "Editions: OSS vs Enterprise",
                  link: "/guide/editions",
                },
                {
                  text: "Enterprise licensing",
                  link: "/guide/licensing",
                },
                {
                  text: "Distributed Redis rate limiter",
                  link: "/guide/redis-rate-limiter",
                },
                {
                  text: "Config convergence",
                  link: "/guide/config-convergence",
                },
                {
                  text: "Distributed cache",
                  link: "/guide/distributed-cache",
                },
                {
                  text: "Vault and KMS secrets",
                  link: "/guide/vault-kms-secrets",
                },
                {
                  text: "Workspaces, RBAC, and audit",
                  link: "/guide/workspaces-rbac-audit",
                },
                {
                  text: "Cluster sync (GA)",
                  link: "/guide/cluster-sync",
                },
                {
                  text: "CP/DP split",
                  link: "/guide/cp-dp-split",
                },
                {
                  text: "H3/QUIC upstream transport",
                  link: "/guide/h3-quic-upstream",
                },
                {
                  text: "Service mesh mode",
                  link: "/guide/service-mesh",
                },
                {
                  text: "API lifecycle and dev portal",
                  link: "/guide/api-lifecycle",
                },
                {
                  text: "Ent controller persistence",
                  link: "/guide/ent-controller-persistence",
                },
                {
                  text: "eBPF hooks (research spike)",
                  link: "/guide/ebpf-hooks",
                },
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
