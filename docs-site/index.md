---
layout: home

hero:
  name: Dwara
  text: API gateway
  tagline: A high-performance reverse-proxy API gateway written in Rust.
  image:
    src: /mark-color.svg
    alt: Dwara mark
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: Architecture overview
      link: /architecture/overview
    - theme: alt
      text: View on GitHub
      link: https://github.com/shristilabs/dwara

features:
  - title: Reverse proxy dataplane
    details: Streaming HTTP/1.1 and HTTP/2 proxying, TLS termination (multi-SNI) and SNI passthrough, routing and rewrites, load balancing with passive and active health checks.
  - title: Traffic policy
    details: Retries and timeouts, circuit breaking, load shedding, and local rate limiting, all attachable at global, listener, service, route, or consumer scope.
  - title: Auth and admin
    details: API key, Basic, JWT (JWKS), and mTLS client-certificate authentication; IP ACL authorization; an mTLS-only admin API for live config inspection and patching.
---
