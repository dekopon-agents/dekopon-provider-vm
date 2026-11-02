# Changelog

## Unreleased

## 0.7.1 — 2026-11-02

- `ssh --secret` takes `drn:secret:<path>` secret DRNs and refuses the legacy `drn:<authority>:secret:<realm>:<path>` spelling; `ssh --help` names the new spelling.
- A schema-invalid capability input is refused with a field-level diagnostic (for example `invalid input: jobId: missing field`) instead of `the input does not match the capability's input schema`.
- Pin Dekopon SDK and broker crates to 0.83.0.

## 0.7.0 — 2026-11-02

- The vm provider ships a `vm` Agent Skill covering browse, record, job polling, artifact listing and asset send.
- `ssh --job JOBID --wait SECONDS` (1–25) waits on the server for a job: `vm.job.get` gains an optional `waitSeconds`, sent as `Prefer: wait=<seconds>`.
- `ssh --artifacts PROFILE` with no path lists the artifacts again instead of failing input validation.
- `ssh --help` shows the provider's help, which names `--wait` and points at the jail's own `browse --help`.
- Pin Dekopon SDK and broker crates to 0.75.0, with rustls-webpki 0.103.16 and Wasmtime 49.0.5.

## 0.6.0 — 2026-10-16

- MP4 jail artifacts attach as SHA-256-verified video assets (8 MiB cap) without sending them to chat.
- Explicit null artifact paths fail as invalid-input before contacting the VM.
- Build with patched rustls 0.23.46 and Wasmtime 49.0.3.

## 0.5.0 — 2026-10-08

- Harden required VM owner `baseUrl` validation with SDK Base.
- Pin Dekopon SDK and testkit to 0.38.0.

## 0.4.0 — 2026-10-08

- `vm.artifact.read` attaches `.png`, `.jpg` and `.jpeg` artifacts as chat assets: the full GET streams into an asset in 64 KiB reads and attaches only when the bytes match `Content-Length` within the 8 MiB asset cap. The output is the existing metadata with `"attached": true`; other paths read as before. Help names the fetch-then-send flow.
- Pin Dekopon SDK and broker crates to 0.36.0.
- `examples/broker.yaml` drops `maxOutputBytes` from capability constraints, where brokerd 0.36 refuses it.

## 0.3.0 — 2026-10-04

- Update the VM provider to Dekopon SDK and broker 0.33.0 and HTTP client 1.1.0; keep the existing buffered `send` behavior and broker-owned bearer authorization.

## 0.2.0 — 2026-10-03

- Migrate VM commands to typed SDK stdio streams and the required owner `baseUrl` setting.
- Preserve broker-owned bearer authorization and combined argv/stdin limits; pin Dekopon core crates to published 0.31.0.
