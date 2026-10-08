# Changelog

## Unreleased

- `vm.artifact.read` attaches `.png`, `.jpg` and `.jpeg` artifacts as chat assets: the full GET streams into an asset in 64 KiB reads and attaches only when the bytes match `Content-Length` within the 8 MiB asset cap. The output is the existing metadata with `"attached": true`; other paths read as before. Help names the fetch-then-send flow.
- Pin Dekopon SDK and broker crates to 0.36.0.

## 0.3.0 — 2026-10-04

- Update the VM provider to Dekopon SDK and broker 0.33.0 and HTTP client 1.1.0; keep the existing buffered `send` behavior and broker-owned bearer authorization.

## 0.2.0 — 2026-10-03

- Migrate VM commands to typed SDK stdio streams and the required owner `baseUrl` setting.
- Preserve broker-owned bearer authorization and combined argv/stdin limits; pin Dekopon core crates to published 0.31.0.
