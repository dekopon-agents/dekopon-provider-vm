//! Broker-wired real-component VM job read; no VM write or public endpoint.
use async_trait::async_trait;
use dekopon_broker::{
    AuthenticatedContext, Broker, BrokerLimits, CapabilityRoute, ConstraintCatalog, ConstraintSet,
    CredentialStore, IdentityDirectory, InMemoryAuditLog, InvocationRequest, PolicyEngine,
    PolicyWorld, SecretCatalog, SecretMaterial, SecretResolutionError, SecretResolver,
    SecretUseBinding,
};
use dekopon_broker_host::{
    BrokerHostLimits, BrokerHostOptions, BrokerProviderRegistry, CommandRunOutcome,
    asset::AssetInputs,
};
use dekopon_broker_protocol::{Streams, TraceParent};
use dekopon_capability::{
    AssetConstraints, ExecutionConstraints, HttpConstraints, HttpPathRule, InvocationOutcome,
};
use dekopon_core::{Actor, SecretDrn, SecretSinkKind};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    os::{
        fd::OwnedFd,
        unix::{fs::FileExt, net::UnixStream},
    },
    path::PathBuf,
    sync::Arc,
    thread,
    time::Duration,
};

const SECRET: &str = "drn:com.xrl:secret:test:vm/token";
const TOKEN: &str = "broker-only-test-token";
#[derive(Debug)]
struct Resolver;
#[async_trait]
impl SecretResolver for Resolver {
    async fn resolve(&self, _: &SecretDrn) -> Result<SecretMaterial, SecretResolutionError> {
        Ok(SecretMaterial::new(TOKEN.as_bytes().to_vec()))
    }
}
fn component() -> PathBuf {
    std::env::var_os("DEKOPON_PROVIDER_COMPONENT")
        .expect("built component")
        .into()
}
fn context() -> AuthenticatedContext {
    AuthenticatedContext::attested(
        "caller".parse().unwrap(),
        Actor::Agent {
            agent: "vm-test".parse().unwrap(),
        },
        "gateway".parse().unwrap(),
        "slack.example.user".parse().unwrap(),
    )
    .unwrap()
}
fn streams() -> (AssetInputs, UnixStream) {
    let (stdout, peer) = UnixStream::pair().unwrap();
    (
        AssetInputs {
            streams: Some(Streams {
                stdin: None,
                stdout: OwnedFd::from(stdout),
            }),
            ..AssetInputs::default()
        },
        peer,
    )
}
async fn broker(
    authority: &str,
    deny: bool,
    asset_root: Option<&std::path::Path>,
) -> Broker<InMemoryAuditLog> {
    let prefix = if asset_root.is_some() {
        "/runner/api"
    } else {
        ""
    };
    let mut registry = BrokerProviderRegistry::load_with_options(
        [component()],
        BrokerHostLimits {
            max_http_response_bytes: 9 * 1024 * 1024,
            ..BrokerHostLimits::default()
        },
        None,
        &BrokerHostOptions {
            provider_settings: Arc::new(BTreeMap::from([(
                "vm".parse().unwrap(),
                json!({"baseUrl":format!("http://{authority}{prefix}/")}).to_string(),
            )])),
            ..BrokerHostOptions::default()
        },
    )
    .await
    .unwrap();
    if let Some(root) = asset_root {
        registry.set_assets(dekopon_http_host::asset::AssetDirectory::new(
            root.to_owned(),
            20 * 1024 * 1024,
        ));
    }
    let capabilities = registry.manifests().next().unwrap().capabilities.clone();
    let world = PolicyWorld::new(
        ["caller".parse().unwrap()],
        capabilities
            .iter()
            .map(|c| (c.id.clone(), "vm".parse().unwrap())),
    )
    .unwrap()
    .with_secrets([SECRET.parse().unwrap()]);
    let policy = format!(
        r#"
        @id("invoke") permit(principal == Dekopon::Principal::"caller", action, resource == Dekopon::Provider::"vm");
        @id("secret") permit(principal == Dekopon::Principal::"caller", action == Dekopon::Action::"secret.use", resource == Dekopon::Secret::"{SECRET}") when {{ context.provider == "vm" && context.sink == "httpBearer" }};
        {}
    "#,
        if deny {
            r#"@id("deny-token") forbid(principal, action == Dekopon::Action::"secret.use", resource);"#
        } else {
            ""
        }
    );
    let bindings = capabilities
        .iter()
        .map(|c| SecretUseBinding {
            binding_id: c.id.to_string(),
            secret: SECRET.parse().unwrap(),
            capability: c.id.clone(),
            sink: SecretSinkKind::HttpBearer,
            basic_username: None,
            allowed_hosts: vec![authority.into()],
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_paths: ["/v1/sessions", "/v1/jobs"]
                .into_iter()
                .map(|p| HttpPathRule::SegmentPrefix {
                    path: format!("{prefix}{p}"),
                })
                .collect(),
            allow_query: false,
            max_injections: 2,
        })
        .collect();
    let catalog = ConstraintCatalog::new(capabilities.into_iter().map(|c| {
        let artifact = c.id.as_str() == "vm.artifact.read";
        (
            c.id,
            ConstraintSet {
                route: CapabilityRoute::Generic,
                provider: "vm".parse().unwrap(),
                effect: c.effect,
                risk: c.risk,
                credential: None,
                constraints: ExecutionConstraints {
                    timeout_ms: 10000,
                    http: Some(HttpConstraints {
                        allowed_hosts: vec![authority.into()],
                        allowed_methods: vec!["GET".into(), "POST".into()],
                        max_requests: 2,
                        max_request_bytes: 200000,
                        max_response_bytes: if artifact { 9 * 1024 * 1024 } else { 1048576 },
                        allow_plaintext_loopback: true,
                        propagate_trace: false,
                    }),
                    asset: artifact.then_some(AssetConstraints {
                        attach: true,
                        remove: false,
                        send: false,
                    }),
                    ..ExecutionConstraints::default()
                },
            },
        )
    }))
    .unwrap();
    Broker::new(
        registry,
        "broker".parse().unwrap(),
        "test".into(),
        PolicyEngine::new(&policy, &world).unwrap(),
        catalog,
        CredentialStore::empty(),
        IdentityDirectory::empty(),
        Arc::new(InMemoryAuditLog::new(32).unwrap()),
        BrokerLimits::default(),
    )
    .unwrap()
    .with_secret_catalog(SecretCatalog::new(bindings, Arc::new(Resolver)).unwrap())
    .unwrap()
}
fn request(
    id: &str,
    input: Value,
    secret_use: Option<dekopon_core::SecretUseProposal>,
) -> InvocationRequest {
    InvocationRequest {
        id: id.parse().unwrap(),
        capability: "vm.job.get".parse().unwrap(),
        input,
        secret_use,
        trace_parent: TraceParent::new([7; 16], [3; 8], 1).unwrap(),
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn cedar_denies_before_http_and_permitted_job_get_injects_exactly_one_bearer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let denied = broker(&authority, true, None).await;
    let words = ["--job", "job-1", "--secret", SECRET].map(str::to_owned);
    let CommandRunOutcome::Proposed {
        capability,
        input,
        secret_use,
    } = denied
        .run_command(&context(), None, None, "ssh", &words, false)
        .await
        .unwrap()
    else {
        panic!("expected proposal")
    };
    assert_eq!(capability.as_str(), "vm.job.get");
    assert!(!input.to_string().contains(SECRET));
    let result = denied
        .invoke(
            &context(),
            None,
            None,
            request("deny", input.clone(), secret_use.clone()),
            AssetInputs::default(),
        )
        .await
        .unwrap();
    assert_eq!(result.result.outcome, InvocationOutcome::Denied);
    assert_eq!(result.result.error.as_deref(), Some("secret-denied"));
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    let server = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.set_nonblocking(false).unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let mut buf = [0; 4096];
            let size = stream.read(&mut buf).unwrap();
            assert_ne!(size, 0);
            request.extend_from_slice(&buf[..size]);
            assert!(request.len() < 32768);
        }
        let body = br#"{"state":"running"}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
        String::from_utf8(request).unwrap()
    });
    let permitted = broker(&authority, false, None).await;
    let (assets, mut stdout) = streams();
    let result = permitted
        .invoke(
            &context(),
            None,
            None,
            request("permit", input, secret_use),
            assets,
        )
        .await
        .unwrap();
    assert_eq!(
        result.result.outcome,
        InvocationOutcome::Succeeded,
        "{:?}",
        result.result.error
    );
    let mut output = Vec::new();
    stdout.read_to_end(&mut output).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&output).unwrap(),
        json!({"state":"running"})
    );
    let wire = server.join().unwrap();
    assert!(wire.starts_with("GET /v1/jobs/job-1 HTTP/1.1\r\n"));
    assert_eq!(
        wire.to_ascii_lowercase()
            .matches("authorization: bearer broker-only-test-token\r\n")
            .count(),
        1
    );
    assert_eq!(
        wire.to_ascii_lowercase().matches("authorization:").count(),
        1
    );
    assert!(!wire.contains(SECRET));
}

#[tokio::test(flavor = "multi_thread")]
async fn component_attaches_complete_mp4_without_a_send_grant() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let bytes: Vec<u8> = (0..150_000).map(|i| (i % 251) as u8).collect();
    let digest = hex::encode(Sha256::digest(&bytes));
    let expected = bytes.clone();
    let header_digest = digest.clone();
    let server = thread::spawn(move || {
        let mut paths = Vec::new();
        for index in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let mut buf = [0; 4096];
                let n = stream.read(&mut buf).unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buf[..n]);
                assert!(request.len() < 32768);
            }
            let header_end = request
                .windows(4)
                .position(|part| part == b"\r\n\r\n")
                .unwrap()
                + 4;
            let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|n| n.parse::<usize>().ok())
                })
                .unwrap_or(0);
            while request.len() - header_end < length {
                let mut buf = [0; 4096];
                let n = stream.read(&mut buf).unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buf[..n]);
            }
            paths.push(headers);
            if index == 0 {
                let body = br#"{"sessionId":"session-1"}"#;
                write!(
                    stream,
                    "HTTP/1.1 201 Created\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(body).unwrap();
            } else {
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nsha256: {header_digest}\r\nConnection: close\r\n\r\n", bytes.len()).unwrap();
                for chunk in bytes.chunks(65_536) {
                    stream.write_all(chunk).unwrap();
                }
            }
        }
        paths
    });
    let root = tempfile::tempdir().unwrap();
    let broker = broker(&authority, false, Some(root.path())).await;
    let (assets, mut stdout) = streams();
    let mut call = request(
        "mp4",
        json!({"profile":"travel","name":"default","path":"clip.mp4"}),
        Some(dekopon_core::SecretUseProposal::HttpBearer {
            secret: SECRET.parse().unwrap(),
        }),
    );
    call.capability = "vm.artifact.read".parse().unwrap();
    let result = broker
        .invoke(&context(), None, None, call, assets)
        .await
        .unwrap();
    assert_eq!(
        result.result.outcome,
        InvocationOutcome::Succeeded,
        "{:?}",
        result.result.error
    );
    let mut output = Vec::new();
    stdout.read_to_end(&mut output).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&output).unwrap(),
        json!({"path":"clip.mp4","bytes":expected.len(),"sha256":digest,"binary":true,"attached":true})
    );
    assert_eq!(result.assets.attached.len(), 1);
    assert!(result.assets.sent.is_empty());
    let attached = &result.assets.attached[0];
    assert_eq!(attached.content_type, "video/mp4");
    assert_eq!(attached.bytes, expected.len() as u64);
    assert_eq!(attached.sha256, digest);
    let mut actual = vec![0; expected.len()];
    assert_eq!(
        result.assets.files[0]
            .file()
            .read_at(&mut actual, 0)
            .unwrap(),
        expected.len()
    );
    assert_eq!(actual, expected);
    let paths = server.join().unwrap();
    assert_eq!(paths.len(), 2);
    for (wire, method, path) in [
        (&paths[0], "POST", "/runner/api/v1/sessions"),
        (
            &paths[1],
            "GET",
            "/runner/api/v1/sessions/session-1/artifacts/clip.mp4",
        ),
    ] {
        assert_eq!(
            wire.lines().next(),
            Some(format!("{method} {path} HTTP/1.1").as_str())
        );
        let lower = wire.to_ascii_lowercase();
        assert!(
            lower
                .lines()
                .any(|line| line == format!("host: {authority}"))
        );
        let request_target = wire
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        assert_eq!(
            format!("http://{authority}{request_target}"),
            format!("http://{authority}{path}")
        );
        assert_eq!(lower.matches("authorization:").count(), 1);
        assert!(lower.contains(&format!("authorization: bearer {TOKEN}")));
        assert!(
            !wire.contains(SECRET),
            "no guest-supplied DRN may travel to the VM"
        );
    }
    assert!(!paths[1].to_ascii_lowercase().contains("range:"));
}
