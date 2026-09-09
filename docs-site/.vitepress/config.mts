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

      // Terminal-styled code fences for the home page quickstart. A fence
      // whose info string is `<lang>[terminal: title]` (e.g. ```sh[terminal:
      // dwara -- quickstart]) is rendered inside macOS-style window chrome
      // (traffic-light dots + title bar) instead of a plain code block; see
      // `.custom-block.terminal` in theme/style.css. The bracket marker is
      // explicit so ordinary fences are never affected. markdown.config runs
      // after VitePress's own fence plugins, so `fence` here is their final
      // rule and we delegate to it with the marker stripped.
      markdown: {
        config(md) {
          const fence = md.renderer.rules.fence!;
          md.renderer.rules.fence = (tokens, idx, options, env, self) => {
            const token = tokens[idx];
            const info = token.info || "";
            const match = info.match(/^(\S+?)\[terminal(?::\s*(.*))?\]$/);
            if (!match) return fence(tokens, idx, options, env, self);
            token.info = match[1];
            const inner = fence(tokens, idx, options, env, self);
            token.info = info;
            const title = match[2] || "terminal";
            return (
              `<div class="custom-block terminal">` +
              `<p class="custom-block-title">${md.utils.escapeHtml(title)}</p>` +
              inner +
              `</div>`
            );
          };
        },
      },

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
                {
                  text: "Concepts and taxonomy",
                  link: "/guide/concepts",
                },
                { text: "Configuration", link: "/guide/configuration" },
                { text: "First scenarios", link: "/guide/first-scenarios" },
              ],
            },
            {
              text: "Proxying and transport",
              link: "/guide/proxying-transport",
              collapsed: false,
              items: [
                { text: "Overview", link: "/guide/proxying-transport" },
                {
                  text: "Routing and matching",
                  link: "/guide/routing",
                },
                {
                  text: "Load balancing and traffic splitting",
                  link: "/guide/traffic-splitting",
                },
                {
                  text: "Dynamic upstream discovery",
                  link: "/guide/dynamic-discovery",
                },
                {
                  text: "gRPC and WebSockets",
                  link: "/guide/grpc-websockets",
                },
                { text: "HTTP/3 ingress", link: "/guide/http3" },
                {
                  text: "H3/QUIC upstream transport",
                  link: "/guide/h3-quic-upstream",
                },
                {
                  text: "L4 TCP/UDP proxying" +
                    '<span class="vp-sb-badge partial">partial</span>',
                  link: "/guide/l4-proxying",
                },
                {
                  text: "Post-quantum TLS",
                  link: "/guide/post-quantum-tls",
                },
              ],
            },
            {
              text: "Request and response control",
              link: "/guide/request-response-control",
              collapsed: false,
              items: [
                {
                  text: "Overview",
                  link: "/guide/request-response-control",
                },
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
              ],
            },
            {
              text: "Protocol translation and API management",
              link: "/guide/protocol-translation",
              collapsed: false,
              items: [
                {
                  text: "Overview",
                  link: "/guide/protocol-translation",
                },
                {
                  text: "gRPC-Web and transcoding",
                  link: "/guide/grpc-web",
                },
                {
                  text: "Protocol translation (REST, gRPC, GraphQL, SOAP)",
                  link: "/guide/protocol-translation",
                },
                {
                  text: "GraphQL awareness" +
                    '<span class="vp-sb-badge partial">partial</span>',
                  link: "/guide/graphql",
                },
                {
                  text: "API aggregation",
                  link: "/guide/api-aggregation",
                },
                {
                  text: "OpenAPI import and mock mode",
                  link: "/guide/openapi-import",
                },
                {
                  text: "OpenAPI response validation",
                  link: "/guide/openapi-response-validation",
                },
                {
                  text: "API lifecycle and dev portal" +
                    '<span class="vp-sb-badge partial">partial</span>',
                  link: "/guide/api-lifecycle",
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
              text: "Security and identity",
              link: "/guide/security",
              collapsed: false,
              items: [
                { text: "Overview", link: "/guide/security" },
                {
                  text: "Authentication methods",
                  link: "/guide/authentication-methods",
                },
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
                  text: "CEL expressions",
                  link: "/guide/cel-expressions",
                },
                { text: "Secrets and references", link: "/guide/secrets" },
                {
                  text: "ACME certificate automation" +
                    '<span class="vp-sb-badge experimental">experimental</span>',
                  link: "/guide/acme",
                },
                {
                  text: "FIPS mode",
                  link: "/guide/fips-mode",
                },
              ],
            },
            {
              text: "AI gateway",
              link: "/guide/ai-gateway",
              collapsed: false,
              items: [
                { text: "Overview", link: "/guide/ai-gateway" },
                {
                  text: "Routing policies",
                  link: "/guide/ai-routing-policies",
                },
                {
                  text: "Prompt experimentation",
                  link: "/guide/ai-prompt-experimentation",
                },
                {
                  text: "Token budgets and cost attribution",
                  link: "/guide/ai-token-budgets",
                },
                {
                  text: "Prompt and response logging",
                  link: "/guide/ai-prompt-logging",
                },
                {
                  text: "Governance and agent principals",
                  link: "/guide/ai-governance",
                },
                {
                  text: "Guardrails",
                  link: "/guide/ai-guardrails",
                },
                {
                  text: "Semantic caching",
                  link: "/guide/ai-semantic-caching",
                },
                {
                  text: "MCP gateway" +
                    '<span class="vp-sb-badge experimental">experimental</span>',
                  link: "/guide/ai-mcp-gateway",
                },
                {
                  text: "A2A protocol" +
                    '<span class="vp-sb-badge partial">partial</span>',
                  link: "/guide/a2a-protocol",
                },
              ],
            },
            {
              text: "Extensibility and plugins",
              link: "/guide/extensibility-overview",
              collapsed: false,
              items: [
                { text: "Overview", link: "/guide/extensibility-overview" },
                {
                  text: "Proxy-Wasm plugins",
                  link: "/guide/proxy-wasm-plugins",
                },
                {
                  text: "Native plugin filters",
                  link: "/guide/native-plugins",
                },
                {
                  text: "Extism plugin development kit" +
                    '<span class="vp-sb-badge experimental">experimental</span>',
                  link: "/guide/extism-pdk",
                },
                {
                  text: "Nano-services (WASM handlers)",
                  link: "/guide/nano-services",
                },
                {
                  text: "Plugin lifecycle",
                  link: "/guide/plugin-lifecycle",
                },
                {
                  text: "Plugin SDK",
                  link: "/guide/plugin-sdk",
                },
                {
                  text: "Extension traits",
                  link: "/guide/extension-traits",
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
              text: "Operations and management",
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
                {
                  text: "Replay time-travel debugging",
                  link: "/guide/replay-debugging",
                },
                {
                  text: "Config import (NGINX, Kong, Envoy)",
                  link: "/guide/config-import",
                },
                {
                  text: "Kubernetes Gateway API",
                  link: "/guide/kubernetes-gateway-api",
                },
              ],
            },
            {
              text: "Enterprise and fleet",
              link: "/guide/enterprise",
              collapsed: false,
              items: [
                { text: "Overview", link: "/guide/enterprise" },
                {
                  text: "Editions: OSS vs Enterprise",
                  link: "/guide/editions",
                },
                {
                  text: "Feature reference and maturity",
                  link: "/guide/feature-reference",
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
                  text: "Distributed cache",
                  link: "/guide/distributed-cache",
                },
                {
                  text: "Config convergence",
                  link: "/guide/config-convergence",
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
                  text: "CP/DP split",
                  link: "/guide/cp-dp-split",
                },
                {
                  text: "Cluster sync (GA)",
                  link: "/guide/cluster-sync",
                },
                {
                  text: "Ent controller persistence",
                  link: "/guide/ent-controller-persistence",
                },
                {
                  text: "Service mesh mode" +
                    '<span class="vp-sb-badge experimental">experimental</span>',
                  link: "/guide/service-mesh",
                },
              ],
            },
            {
              text: "Research and roadmap",
              link: "/guide/ebpf-hooks",
              collapsed: true,
              items: [
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
              items: [
                { text: "Overview", link: "/architecture/overview" },
                {
                  text: "Request pipeline",
                  link: "/architecture/request-pipeline",
                },
                {
                  text: "Connection and TLS",
                  link: "/architecture/connection-and-tls",
                },
                {
                  text: "Config, state, and extensions",
                  link: "/architecture/config-and-state",
                },
                {
                  text: "Error handling",
                  link: "/architecture/error-handling",
                },
                {
                  text: "Resilience",
                  link: "/architecture/resilience",
                },
                {
                  text: "Security",
                  link: "/architecture/security",
                },
                {
                  text: "AI gateway",
                  link: "/architecture/ai-gateway",
                },
                {
                  text: "Plugins and extensibility",
                  link: "/architecture/plugins-and-extensibility",
                },
                {
                  text: "Observability",
                  link: "/architecture/observability",
                },
              ],
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
