# Changelog

## Unreleased

## 0.3.0 — 2026-10-04

- Update the VM provider to Dekopon SDK and broker 0.33.0 and HTTP client 1.1.0; keep the existing buffered `send` behavior and broker-owned bearer authorization.

## 0.2.0 — 2026-10-03

- Migrate VM commands to typed SDK stdio streams and the required owner `baseUrl` setting.
- Preserve broker-owned bearer authorization and combined argv/stdin limits; pin Dekopon core crates to published 0.31.0.
