# ACME certificate automation

Dwara can automate TLS certificate issuance and renewal from
[ACME](https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment) (Automated Certificate Management Environment) certificate
authorities like [Let's Encrypt](https://letsencrypt.org/), so
operators do not need to manually provision and rotate certificates.

::: warning Implementation status
The `acme` feature is **config-accepted, runtime stubbed**. The config
schema (`AcmeConfig`) parses and validates, and validation warns when
the feature is off, but the ACME client itself is not yet implemented.
No account registration, challenge completion, certificate issuance,
or renewal task is wired into the listener startup path. A future
change will add an ACME client dependency (rustls-acme or instant-acme,
license-checked against `deny.toml`) and connect `build_acme_state` to
the TLS listener. Until then, use an external ACME client (certbot,
lego, cert-manager) and point the gateway at the resulting certificate
files. See the alternatives section below.
:::

## When to use this

Use ACME when you want the gateway to obtain and renew its own TLS
certificates without an external certificate manager (certbot, lego,
cert-manager). This is most useful for internet-facing deployments
where the gateway terminates TLS directly on port 443.

## Enabling

ACME is feature-gated behind the `acme` cargo feature (default OFF).
The config block is always accepted by the parser; when the feature is
OFF, validation warns that the block is inert.

```sh
cargo build --features acme -p dwara-bin
```

## Configuration

Add an `acme` block to a listener's TLS configuration:

```yaml
listeners:
  - name: https
    protocol: https
    address: 0.0.0.0
    port: 443
    tls:
      mode: terminate
      acme:
        domains:
          - api.example.com
          - www.example.com
        contact:
          - admin@example.com
        challenge: tls-alpn-01
        staging: false
        state_dir: ./acme-state
```

| Field | Default | Description |
|---|---|---|
| `domains` | (required) | Domain names to obtain certificates for. |
| `contact` | (required) | Email addresses for ACME account registration. |
| `challenge` | `tls-alpn-01` | ACME challenge type: `tls-alpn-01` or `http-01`. |
| `staging` | `false` | Use the Let's Encrypt staging directory (for testing; avoids rate limits). |
| `state_dir` | `./acme-state` | Directory for persisting the ACME account key and issued certificates. |

## Challenge types

- **`tls-alpn-01`** (default): the TLS terminator handles the challenge
  during the TLS handshake on port 443. No separate HTTP listener is
  needed. This is the recommended default because it works behind most
  load balancers and in containerized environments where port 80 is not
  available.
- **`http-01`**: requires a separate HTTP listener on port 80 (or port
  forwarding from a load balancer). Use this only when the TLS-ALPN-01
  challenge is not viable.

## Staging vs production

Set `staging: true` to use the Let's Encrypt staging directory. Staging
certificates are not trusted by browsers but are not subject to the
production rate limits. Test your ACME configuration with staging
first, then switch to `staging: false` (or remove the field) for
production.

## Runtime behavior (intended design)

The following describes the intended runtime behavior once the ACME
client is implemented. None of this is wired today (see the status
note at the top of this page).

1. The ACME client loads or creates an account key (persisted to
   `state_dir`).
2. Registers the account with the directory using `contact`.
3. For each domain: orders a certificate, completes the challenge,
   finalizes the order, and downloads the issued certificate.
4. Installs the certificate into the SNI resolver.
5. Schedules renewal at 2/3 of the certificate's validity period.
6. On failure: logs the error and retries with exponential backoff.
   Existing certificates continue to serve.

## Alternatives

- **External ACME client (certbot, lego, acme.sh):** run an external
  ACME client and place certificates in the gateway's cert paths. No
  gateway-integrated automation, but avoids adding an ACME client to
  the gateway binary.
- **cert-manager (Kubernetes):** use cert-manager to obtain
  certificates and mount them as secrets. Decouples certificate
  management from the gateway.
- **Commercial CA with API:** use a commercial CA's API instead of
  ACME. Non-standard; vendor lock-in.

## Tradeoffs

- Let's Encrypt rate limits: 50 certificates per domain per week. Use
  `staging: true` for testing.
- TLS-ALPN-01 requires port 443 to be directly reachable by the CA's
  validation servers.
- The ACME client will add a dependency to the gateway binary (gated
  behind the `acme` feature) once implemented; today the feature is
  flag-only with no dependency.

## See also

- [Security and authentication](./security)
- [Configuration](./configuration)
- [Feature reference](./feature-reference)
