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
use dekopon_capability::{ExecutionConstraints, HttpConstraints, HttpPathRule, InvocationOutcome};
use dekopon_core::{Actor, SecretDrn, SecretSinkKind};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    os::{fd::OwnedFd, unix::net::UnixStream},
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
async fn broker(authority: &str, deny: bool) -> Broker<InMemoryAuditLog> {
    let registry = BrokerProviderRegistry::load_with_options(
        [component()],
        BrokerHostLimits::default(),
        None,
        &BrokerHostOptions {
            provider_settings: Arc::new(BTreeMap::from([(
                "vm".parse().unwrap(),
                json!({"baseUrl":format!("http://{authority}")}).to_string(),
            )])),
            ..BrokerHostOptions::default()
        },
    )
    .await
    .unwrap();
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
                .map(|p| HttpPathRule::SegmentPrefix { path: p.into() })
                .collect(),
            allow_query: false,
            max_injections: 2,
        })
        .collect();
    let catalog = ConstraintCatalog::new(capabilities.into_iter().map(|c| {
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
                        max_response_bytes: 1048576,
                        allow_plaintext_loopback: true,
                        propagate_trace: false,
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
    let denied = broker(&authority, true).await;
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
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
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
    let permitted = broker(&authority, false).await;
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
