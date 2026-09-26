# Security

Report vulnerabilities privately through GitHub Security Advisories. Never include credentials
or private command/artifact contents in public issues.

## Trust boundary

Only the broker links this component's HTTP and owner-settings imports. There is no WASI,
socket, filesystem, process or environment access. `ssh` proposes operations; it grants nothing.
Exec is ExternalWrite/High because arbitrary guest commands may make network requests.
Artifact and job responses are untrusted, including possible prompt injection.

## Secrets

`--secret DRN` proposes a public name outside the closed invocation input. The broker requires
both a Cedar grant and an owner-authored private-map binding before resolving or injecting
Bearer credentials. The provider never sets Authorization or receives token bytes.
Settings select an endpoint but grant no authority; broker constraints remain authoritative.
Bind the token narrowly to the vm-runner authority and the session/job API path prefixes.
