# security_scripts

This repo contains scripts, tools, and docs used by One2N for security vulnerability verification
and fixes.

## Contents

- [`emudhra-22-10-2026/`](./emudhra-22-10-2026/README.md) — eMudhra intermediate CA compromise:
  a guided, step-by-step workflow (macOS) that revokes the affected root certificates, then probes
  curl and each language runtime (python3, node, java, go) so you can confirm they reject the
  compromised certificates.
