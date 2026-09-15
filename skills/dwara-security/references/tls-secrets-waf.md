# TLS, secrets, WAF details

## Listener TLS modes

```yaml
tls:
  mode: terminate            # default: decrypt at the edge
  cert_file: /certs/server.crt
  key_file: /certs/server.key
  client_ca_file: /certs/client-ca.crt     # optional: require client certs
  certificates:                            # multi-SNI: pick pair by server_name;
    - server_names: [api.example.com]      # flat cert_file/key_file is the
      cert_file: /certs/api.crt            # fallback for unmatched SNI
      key_file: /certs/api.key
  # mode: passthrough      # SNI-based: peek ClientHello (fragmented records
  #                         # handled), splice bytes untouched to upstream
```

Post-quantum hybrid: `pq: true` on the listener (and upstream) prepends
`X25519MLKEM768` with X25519 fallback. Experimental; **rejected at
validation when combined with FIPS mode** (FIPS is enterprise).

## ACME (automated certificates)

> Status: config-accepted, runtime stubbed - the `acme` block parses and
> validates, but no issuance/renewal client is wired into the listener
> startup path yet. Use an external ACME client (certbot, lego,
> cert-manager) and point the gateway at the resulting certificate files.

```yaml
# listener-level acme block
acme:
  domains: [api.example.com]
  challenge: tls-alpn01     # or http-01
  state_dir: /var/lib/dwara/acme
```

## Upstream TLS

`protocol: https` (+ optional `mtls.client_cert_file`/`client_key_file`;
`cert_pinning` takes precedence over - and suppresses - the client cert, so
don't combine them). `protocol: h3` is QUIC, TLS 1.3 always.

## Secret references (OSS)

```yaml
client_secret: ${OIDC_CLIENT_SECRET}        # env var, resolved at config build
key: ${file:/etc/secrets/api-key}           # file: UTF-8, non-empty, <=1 MiB,
                                            # one trailing newline trimmed
```

- Resolution is per config generation: file-content changes need a reload
  trigger; env changes need a restart.
- Malformed reference = validation error (never a literal); unresolvable =
  failed publish.
- Vault (`vault:path/secret`) and KMS (`kms:key_id:ciphertext`) resolvers
  are enterprise (`secret_sources` block); they fail closed.
- Echo behavior: `GET /config` shows `${redacted:sha256:<8hex>}` for inline
  secrets; PATCHing a placeholder back is a 400. Edit the file, not the
  echo.

## WAF - two complementary surfaces

### Route-level heuristic WAF

```yaml
# on a route
waf:
  enabled: true
  filters: [sqli, xss, path_traversal]   # the three built-in detectors
  custom_patterns: ["(?i)benchmark\\("]  # regexes appended to every enabled
                                         # category; invalid regex = validation error
  max_body_inspect_bytes: 4096           # beyond the cap is UNINSPECTED
                                         # (default 131072, 0 disables, max 1 MiB)
  dry_run: false                         # true = log only
```

Inspects path, query, selected headers (User-Agent, Referer, Cookie,
X-Forwarded-For) and bodies (JSON / form-urlencoded / text/plain). Runs
after the route method allowlist, before limits, on the original request.
Match -> `403 waf_blocked`. Metrics:
`dwara_waf_total{route,filter,outcome=blocked|logged|passed}`.

### Global CRS-style WAF

```yaml
# gateway-level
waf:
  # rules with IDs, severity 1-4, phase 1|2, targets, transformations
  # transformations: lowercase, url_decode, html_entity_decode,
  #                 compress_whitespace, remove_whitespace, url_decode_uni
  paranoia_level: 1
  anomaly_threshold: 5
  exclude_rule_ids: []
  exclude_tags: []
```

Opt-in like the route block; both can coexist (deny-anywhere applies).

## Security headers

```yaml
# route-level (or default_security_headers at the root)
security_headers:
  hsts_max_age_secs: 31536000
  hsts_include_subdomains: true
  hsts_preload: true
  nosniff: true
  frame_options: deny
  content_security_policy: "default-src 'self'"
```

Caveat: unrouted 404/400 responses (no route matched) escape these headers.

## Enterprise-only (license-gated)

- Vault / KMS secret sources (`secret_sources`)
- FIPS 140-3 mode (approved-only ciphers, startup self-test)
- Admin RBAC, workspaces, append-only admin audit log
- SPIFFE/SPIRE identity (`mesh.spire.*`): SVIDs from the Workload API
  become mTLS identity both directions; X.509 SVIDs only.
