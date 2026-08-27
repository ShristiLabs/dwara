#!/usr/bin/env node
// Freezes the current "unstable" docs-site content into versions/<version>/,
// per the vitepress-versioning-plugin model: the root of docs-site/ always
// tracks `main` ("unstable"); tagging a release means permanently snapshotting
// that root content into a versioned folder before the tag is cut.
//
// Usage (from docs-site/): npm run docs:freeze -- 1.2.0
//
// This is a release step, not something CI runs automatically: run it,
// review the diff, commit it, THEN tag the release. That way the frozen
// snapshot is part of the same commit history as the release it documents.
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const version = process.argv[2];

if (!version) {
  console.error("usage: node scripts/freeze-version.mjs <version>  (e.g. 1.2.0, no leading v)");
  process.exit(1);
}
if (!/^\d+\.\d+\.\d+$/.test(version)) {
  console.error(`version must be a bare semver (e.g. "1.2.0"), got: ${version}`);
  process.exit(1);
}

const dest = join(root, "versions", version);
if (existsSync(dest)) {
  console.error(`versions/${version} already exists; refusing to overwrite. Remove it first if you need to re-freeze.`);
  process.exit(1);
}

// Top-level entries that belong to the "unstable" root content and get
// copied into the frozen version. Everything else (.vitepress/, versions/,
// node_modules/, public/, package*.json, scripts/) is either infra shared
// across all versions or must not be versioned.
const CONTENT_ENTRIES = ["index.md", "guide", "architecture", "reference"];

mkdirSync(dest, { recursive: true });
for (const entry of CONTENT_ENTRIES) {
  const src = join(root, entry);
  if (!existsSync(src)) continue;
  cpSync(src, join(dest, entry), { recursive: true });
}

// Build a default sidebar for the frozen version by reusing the current
// root sidebar structure recorded in .vitepress/config.mts. We can't `import`
// the TS config from a plain Node script without a bundler step, so we ship
// a minimal generated sidebar here; edit it by hand for anything more custom
// (see the plugin's sidebarPathResolver in .vitepress/config.mts).
const sidebarDir = join(root, ".vitepress", "sidebars", "versioned");
mkdirSync(sidebarDir, { recursive: true });
const sidebar = {
  "/guide/": [
    {
      text: "Guide",
      items: [
        { text: "Getting started", link: "/guide/getting-started" },
        { text: "Installation", link: "/guide/installation" },
        { text: "Configuration", link: "/guide/configuration" },
        { text: "Deployment", link: "/guide/deployment" },
        { text: "Operations", link: "/guide/operations" },
        { text: "Observability", link: "/guide/observability" },
        { text: "Admin API", link: "/guide/admin-api" },
        { text: "CLI", link: "/guide/cli" },
      ],
    },
  ],
  "/architecture/": [
    { text: "Architecture", items: [{ text: "Overview", link: "/architecture/overview" }] },
  ],
  "/reference/": [
    {
      text: "Reference",
      items: [
        { text: "Environment variables", link: "/reference/environment-variables" },
        { text: "Configuration schema", link: "/reference/configuration-schema" },
      ],
    },
  ],
};
writeFileSync(join(sidebarDir, `${version}.json`), `${JSON.stringify(sidebar, null, 2)}\n`);

console.log(`Froze docs-site content into versions/${version}/`);
console.log(`Wrote .vitepress/sidebars/versioned/${version}.json`);
console.log("Review the diff, commit it, then tag the release.");
