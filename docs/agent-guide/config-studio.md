# Config studio

`tools/config-studio/` -- single-file, offline browser tool for generating
and editing gateway YAML.

## Rules

- **`index.html` is a build artifact.** Never hand-edit. Edit
  `src/app.template.html`, run `python3 tools/config-studio/build.py`
  (stdlib only), commit both.
- **Regenerate with the schema.** Any change to `config-reference.json` must
  rebuild the tool in the same commit (the build inlines the schema).
- The build scrubs `DW-###` references from help text. Never strip them from
  `config-reference.json` itself (must match `dwara schema` output for CI).
- `vendor/js-yaml.min.js` is vendored (js-yaml 4.1.0, MIT). Upgrades are a
  deliberate license-and-size review.
- Must stay offline: no CDN scripts, no runtime fetches, no node build step.
- Verify by rebuilding, opening in browser, and confirming templates pass
  `dwara-cli validate`.

## Quickstart sanity check

`quickstart/oss/`: boots gateway + demo upstream over TLS.

```sh
cd quickstart/oss && ../gen-certs.sh && docker compose up
curl --cacert ../certs/server.crt https://localhost:8443/
```

Linux hosts: `sudo chown -R 65532:65532 quickstart/certs`.

`quickstart/enterprise/`: CP/DP split topology (ports 9443/9444). Needs
`vendor-licensing.sh` first.
