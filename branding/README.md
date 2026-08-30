# Dwara brand assets

The Dwara product identity: logo, mark, wordmark, and favicon set. These
are the canonical copies checked into the Dwara repository. The source of
truth for the wider ShristiLabs product family lives in the separate
`branding` repository (`products/dwara/`); this directory is a snapshot
kept in sync so the Dwara repo is self-contained for documentation and
packaging.

## Identity

Dwara (द्वार — gateway/door) carries the ShristiLabs parent DNA — an indigo
base with a central bindu and geometric mark — with its own symbol and
accent:

| Role            | Hex       |
|-----------------|-----------|
| Indigo (deep)   | `#1B1650` |
| Indigo          | `#2E2A6B` |
| Teal (accent)   | `#12B5A5` |
| Cream           | `#FBF3E6` |

The symbol is a torana arch (a gateway) with traffic routed through it,
rendered in a teal gradient over the indigo squircle. Typeface: Outfit
(wordmark text is converted to outlines in the SVGs, so no font file is
required to render them).

## Structure

```
branding/
├── svg/                   source vectors (scalable, self-contained)
│   ├── mark-color.svg           symbol, gradient, transparent bg
│   ├── mark-icon.svg            symbol on indigo squircle (app/favicon)
│   ├── wordmark.svg             "Dwara" wordmark only
│   ├── logo-horizontal.svg      icon + wordmark (light bg)
│   ├── logo-horizontal-dark.svg # icon + wordmark (indigo bg)
│   └── logo-stacked.svg         icon above wordmark
├── png/                   raster exports of the logos/marks
└── favicon/               web icons, favicon.ico, manifest, <head> snippet
```

## Where these are used

- **docs-site** (`../docs-site/public/`): the favicons and the SVG logos
  are copied there and served as static assets. `.vitepress/config.mts`
  wires the favicon `<head>` links (under the `/dwara/` site base) and the
  nav `logo`; `index.md` shows the mark on the home hero.
- **README.md** (repo root): the horizontal PNG logo is rendered at the top
  of the GitHub-rendered README (GitHub does not display SVG images in
  READMEs, so the PNG is used there).

## Using the favicons elsewhere

Copy everything in `favicon/` to a web root, then paste
[`favicon/head-snippet.html`](./favicon/head-snippet.html) into the page
`<head>`. The snippet uses root-absolute paths (`/favicon.ico`); adjust to
match the deployment's base path (the docs-site copy under
`docs-site/public/` already carries base-relative manifest paths).
