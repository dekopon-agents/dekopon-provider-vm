# Release runbook

The tag workflow is the only publisher. Do not commit generated Wasm, use `cargo publish`,
push an OCI artifact by hand, or create a release manually. The current
[shared release workflow](https://github.com/dekopon-agents/provider-workflows/blob/main/.github/workflows/release.yml)
is authoritative; check it before each release.

1. Prepare the package version and its lockfile entry in a reviewed PR. Run the README's
   acceptance commands and confirm `ci / validate` is green on the final head.
   The independent two-copy reproducibility comparison is currently disabled in CI and release.
2. Before tagging, verify the version is unused as a Git tag, a draft or published GitHub
   release, and `ghcr.io/dekopon-agents/provider-vm:<version>`. The OCI tag omits the `v` prefix.
   The workflow does not check for an existing OCI tag before pushing it.
3. After merge and explicit release authorization, push an annotated `vX.Y.Z` tag on the
   approved `main` commit. The workflow checks annotation, event SHA, package version, and
   main ancestry. Release preparation alone does not authorize merging or tagging.
4. The workflow runs formatting, dependency policy, host/wasm clippy, component build/checksum,
   real-component tests, and SBOM generation, then attests the component and SBOM. It creates
   or reuses a draft, verifies its exact assets and bytes, publishes and verifies one OCI
   `application/wasm` layer, and finalizes the GitHub release. Stable releases become latest.
5. Confirm all release jobs succeed, including anonymous download/checksum and commit-bound
   provenance verification. GitHub assets must be exactly `vm-provider.wasm`,
   `vm-provider.wasm.sha256`, and `vm-provider.cdx.json`; the OCI layer digest must match
   the component checksum. No `latest` or `staging` OCI tag is created.

A published release is refused. An existing draft may be reused only when its checked assets
match. Draft-job failure attempts to remove only a draft created by that job; the current
workflow has no general rollback for later OCI publication or finalization failures.
