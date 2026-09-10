# mTLS handshake failures

mTLS handshake failures occur when the gateway and the client cannot
establish a mutual TLS connection. The gateway requires a valid client
certificate, and the client requires a valid server certificate.

## Symptoms

- Client receives `TLS handshake failed` or a connection reset.
- The gateway logs a TLS error with the client's IP.
- Metrics show `dwara_tls_handshake_failures_total` increasing.

## Likely causes

### Client certificate not provided

The gateway requires a client certificate, but the client did not
send one.

**Diagnose:**

```sh
# Check TLS handshake metrics
curl -k https://127.0.0.1:2019/metrics | grep dwara_tls_handshake

# Test with curl (provide a client cert)
curl -k --cert client.crt --key client.key https://127.0.0.1:8443/
```

**Fix:** Configure the client to send its certificate. For curl:

```sh
curl --cert client.crt --key client.key --cacert ca.crt https://...
```

### Client certificate not trusted

The client's certificate is not signed by a CA the gateway trusts.

**Diagnose:**

```sh
# Check the gateway's mTLS trust configuration
curl -k https://127.0.0.1:2019/config | jq '.listeners[] | select(.tls.mutual)'
```

**Fix:** Add the client's CA to the listener's `mutual.trust` block:

```yaml
listeners:
  - name: mtls
    tls:
      mutual:
        trust:
          - file: /etc/dwara/ca/client-ca.crt
        required: true
```

### Server certificate expired

The gateway's server certificate has expired.

**Diagnose:**

```sh
# Check the server certificate
openssl x509 -in /etc/dwara/certs/server.crt -noout -dates
```

**Fix:** Renew the server certificate and place it at the
configured path. The gateway hot-reloads certificates from the file
system, so no restart is needed.

### Client certificate expired

The client's certificate has expired.

**Diagnose:**

```sh
# Check the client certificate
openssl x509 -in client.crt -noout -dates
```

**Fix:** Renew the client certificate and provide the new one to
the client.

### SNI mismatch

The client sent an SNI hostname that does not match any configured
listener or certificate.

**Diagnose:**

```sh
# Test with the correct SNI
curl -k --resolve my-hostname:443:127.0.0.1 https://my-hostname:443/
```

**Fix:** Ensure the client sends the correct SNI hostname. If the
gateway uses SNI-based routing, the SNI must match a configured
listener's `sni` field or a certificate's `sni_names`.

### Protocol version mismatch

The client and gateway cannot agree on a TLS protocol version.

**Diagnose:**

```sh
# Test with a specific TLS version
curl -k --tlsv1.2 --tls-max 1.2 https://...
curl -k --tlsv1.3 --tls-max 1.3 https://...
```

**Fix:** Ensure the gateway supports the TLS version the client
requires. Configure the listener's `tls.min_version` and
`tls.max_version`:

```yaml
listeners:
  - name: main
    tls:
      min_version: tls1.2
      max_version: tls1.3
```

## See also

- [Authentication methods](../authentication-methods)
- [Operations](../operations)
