# dwara docs-site

The published end-user documentation site (OSS + enterprise operators),
built with [VitePress](https://vitepress.dev) and
[vitepress-versioning-plugin](https://vvp.imb11.dev). Published to
GitHub Pages by `.github/workflows/docs-site.yml`.

This is distinct from [`/docs`](../docs), which is internals-focused
documentation for dwara contributors. If you're writing about how a
feature works from the operator's point of view (how to configure it,
what it does at the wire level, what to watch in metrics/logs), it
belongs here. If you're writing about why it's implemented the way it
is, or how the code is organized, it belongs in `/docs`.

## Local development

```sh
cd docs-site
npm install
npm run docs:dev       # http://localhost:5173
```

```sh
npm run docs:build     # -> .vitepress/dist
npm run docs:preview   # serve the built output
```

## Structure

```
docs-site/
  index.md                    home page
  guide/                       task-oriented, end-user guides
  architecture/                high-level diagrams (mermaid)
  reference/                   generated/exhaustive reference material
  versions/                    frozen snapshots of past releases (see below)
  .vitepress/
    config.mts                 site + versioning + sidebar config
    sidebars/versioned/        one sidebar JSON per frozen version
  scripts/freeze-version.mjs   release-time versioning helper
```

Links between pages must be **relative** (e.g. `./configuration`, not
`/guide/configuration`) wherever practical — the versioning plugin
rewrites relative links per-version; absolute links only resolve
against whichever version they were written in.

## Versioning model

The root of this project (`index.md`, `guide/`, `architecture/`,
`reference/`) always tracks `main` and is labeled **`unstable`** in the
version switcher (`versioning.latestVersion` in `.vitepress/config.mts`).

When cutting a release:

```sh
npm run docs:freeze -- 1.2.0   # no leading "v"
```

This copies the current root content into `versions/1.2.0/` and
generates `.vitepress/sidebars/versioned/1.2.0.json` — a permanent,
frozen snapshot of the docs as they existed at that release. Review the
diff, commit it, **then** cut the `v1.2.0` git tag. The root keeps
evolving as `unstable` for the next release.

The version switcher in the site nav lists `unstable` plus every frozen
version under `versions/`.

## Publishing

`.github/workflows/docs-site.yml` builds and deploys to GitHub Pages on
every push to `main` that touches `docs-site/**`. Because all versions
(root + frozen `versions/`) are built from whatever is committed at
`main` in one pass, there's no separate per-tag deploy step — freezing
a version and committing it is what makes it show up on the published
site.
