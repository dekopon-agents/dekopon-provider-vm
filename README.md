# dekopon-provider-vm

Dekopon 0.22+ Wasm provider for vm-runner Firecracker jails. `ssh` is a command word,
not an SSH transport. The broker owns HTTP, credentials and authorization.

```text
ssh [--session NAME] --secret DRN [--timeout SECONDS] PROFILE -- ARGV...
ssh --job JOBID --secret DRN
ssh --artifacts [--session NAME] --secret DRN PROFILE [PATH]
ssh -h|--help
```

Session defaults to `default`; timeout is 1–25 seconds, default 25. NAME and PROFILE
match `^[a-z0-9][a-z0-9-]{0,62}$`. Arguments after `--` are literal argv, not a shell
script; stdin passes through to exec. At most 70 argv entries and 24,576 aggregate
UTF-8 bytes across argv and stdin. Malformed forms render fixed stderr at exit 2;
help renders stdout at exit 0. Options take separate values, at most once.

| Capability | Effect / risk | HTTP sequence |
|---|---|---|
| `vm.exec` | ExternalWrite / High | create-or-get session, then exec |
| `vm.job.get` | ReadOnly / Low | get job |
| `vm.artifact.read` | ExternalWrite / Low | create-or-get session, then list/read |

Exec proposes `{profile,name,argv,stdin?,deadlineMs}`; jobs `{jobId}`; artifacts
`{profile,name,path?}`. Schemas are closed. Secret DRNs travel only beside input as
`secretUse.httpBearer`: neither token nor Authorization header is available to the
provider. The broker requires both a Cedar `secret.use` grant and a private-map binding.
`--secret` is mandatory; agent instructions must supply the public DRN.

Owner `providerSettings.vm.baseUrl` defaults to
`https://vm-runner.vm-runner.svc.cluster.local:8443`. No argv or invocation field
selects a URL. Only broker `allowedHosts` grants destinations. The component imports
`dekopon:http/client@1.1.0` and `dekopon:settings/config@0.1.0`; settings are available
only during invoke. Asset WIT is a type dependency, not ambient authority.

Exec/job JSON passes through, including `not_executed` on documented 400/413/502
responses and `unknown` + `jobId` on 202. Poll explicitly; nothing retries.
stdout/stderr remain unchanged; vm-runner caps each at 64 KiB. Artifact reads accept
only flat names matching `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, sent literally:
broker 0.22 intentionally refuses `%` in credentialed paths. Other names render
exit 2 with guidance to copy the file to a flat name under `/artifacts` first,
for example `ssh --secret DRN PROFILE -- cp 'dir/a b.png' /artifacts/shot.png`.
Listing still shows every path. Reads request bytes 0–65536: complete
UTF-8 text up to 64 KiB returns as a JSON string; otherwise output is
`{path,bytes,sha256,binary:true}`, without file contents. `bytes` is the complete size
from Content-Range, not the prefix length. Lists return server JSON unchanged.
Other statuses produce fixed `vm-unauthorized`, `vm-conflict`, `vm-quota`,
`vm-bad-request`, `vm-unavailable` or `vm-failed` errors. Transport failures use the
broker HTTP error codes. All returned content is untrusted.

See `examples/broker.yaml` and `examples/policies.cedar` for 0.22 configuration.
The port must appear in allowedHosts: a bare hostname grants HTTPS port 443, not 8443.
Configure broker-only CA roots and non-public HTTPS access for cluster DNS.
The whole-invocation `timeoutMs` must cover the cold-session boot budget plus
`--timeout` (converted to milliseconds); the example allows 120000 ms for session
operations and 30000 ms for job polling. Increase it if the boot budget exceeds
95000 ms with the default 25-second exec timeout.
Artifact reads are ExternalWrite because create-or-get can create a quota-counted
session record; vm-runner boots lazily on exec. No deployment or release is implicit.

## Build and checks

Rust and wasm-tools versions follow the pinned shared provider-workflows v4 scaffold.
Build only `wasm32-unknown-unknown`, never WASI; normal dependencies are exact pins.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo deny --all-features check bans licenses sources advisories
../provider-workflows/build.sh
DEKOPON_PROVIDER_COMPONENT=$PWD/vm-provider.wasm cargo test --locked --workspace
```

Tests use native mocks and loopback broker HTTP only. The component test requires
`DEKOPON_PROVIDER_COMPONENT` and never silently skips. Release artifacts are
`vm-provider.wasm`, its SHA-256 sidecar, and
`ghcr.io/dekopon-agents/provider-vm:<version>`. See `RELEASE.md` for the shared workflow.
MIT OR Apache-2.0.
