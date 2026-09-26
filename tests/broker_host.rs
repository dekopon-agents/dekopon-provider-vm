//! Loopback fixtures require the built component; no test may contact a public endpoint.

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
use dekopon_broker_protocol::TraceParent;
use dekopon_capability::{ExecutionConstraints, HttpConstraints, HttpPathRule, InvocationOutcome};
use dekopon_core::{Actor, SecretDrn, SecretSinkKind};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

const SECRET: &str = "drn:com.xrl:secret:test:vm/token";
#[derive(Debug)]
struct Resolver;
#[async_trait]
impl SecretResolver for Resolver {
    async fn resolve(&self, _: &SecretDrn) -> Result<SecretMaterial, SecretResolutionError> {
        Ok(SecretMaterial::new(b"broker-only-test-token".to_vec()))
    }
}
fn component() -> PathBuf {
    std::env::var_os("DEKOPON_PROVIDER_COMPONENT")
        .expect("build component first")
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
async fn registry(authority: &str) -> BrokerProviderRegistry {
    BrokerProviderRegistry::load_with_options(
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
    .unwrap()
}
async fn broker(authority: &str, extra_policy: &str) -> Broker<InMemoryAuditLog> {
    let registry = registry(authority).await;
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
        {extra_policy}
    "#
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
                    max_output_bytes: 1048576,
                    http: Some(HttpConstraints {
                        allowed_hosts: vec![authority.into()],
                        allowed_methods: vec!["GET".into(), "POST".into()],
                        max_requests: 2,
                        max_request_bytes: 200000,
                        max_response_bytes: 1048576,
                        allow_plaintext_loopback: true,
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

fn serve(
    listener: TcpListener,
    responses: Vec<(String, Vec<u8>)>,
) -> thread::JoinHandle<Vec<String>> {
    thread::spawn(move || {
        let mut requests = Vec::new();
        for (headers, body) in responses {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0; 4096];
                let n = stream.read(&mut chunk).unwrap();
                assert_ne!(n, 0);
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&bytes[..end]);
                    let length = head
                        .lines()
                        .find_map(|s| {
                            s.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(|s| s.parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
                assert!(bytes.len() < 200000);
            }
            requests.push(String::from_utf8(bytes).unwrap());
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        }
        requests
    })
}
#[tokio::test(flavor = "multi_thread")]
async fn broker_injects_bearer_for_exact_sequences_and_keeps_resolution_local() {
    for (args, expected_path, expected_body, output) in [
        (
            vec!["travel", "--", "echo", "hi"],
            "/v1/sessions/session-1/exec",
            Some(json!({"argv":["echo","hi"],"stdin":"piped","deadlineMs":25000})),
            json!({"outcome":"executed","exitCode":0,"stdout":"hi\n","stderr":"","truncated":false}),
        ),
        (
            vec!["--job", "job-1"],
            "/v1/jobs/job-1",
            None,
            json!({"state":"running"}),
        ),
        (
            vec!["--artifacts", "travel"],
            "/v1/sessions/session-1/artifacts",
            None,
            json!([{"path":"dir/a b.txt","bytes":1,"sha256":"a".repeat(64)}]),
        ),
        (
            vec!["--artifacts", "travel", "Shot_1.txt"],
            "/v1/sessions/session-1/artifacts/Shot_1.txt",
            None,
            json!("artifact text"),
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let broker = broker(&listener.local_addr().unwrap().to_string(), "").await;
        let mut words = vec!["--secret".to_owned(), SECRET.into()];
        words.extend(args.iter().map(|s| (*s).into()));
        let CommandRunOutcome::Proposed {
            capability,
            input,
            secret_use,
        } = broker
            .run_command(&context(), None, None, "ssh", &words, Some("piped"))
            .await
            .unwrap()
        else {
            panic!("proposal")
        };
        assert!(!input.to_string().contains(SECRET));
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
        let mut responses = Vec::new();
        if capability.as_str() != "vm.job.get" {
            responses.push((
                String::new(),
                serde_json::to_vec(&json!({"sessionId":"session-1"})).unwrap(),
            ));
        }
        responses.push((
            String::new(),
            if let Some(text) = output.as_str() {
                text.as_bytes().to_vec()
            } else {
                serde_json::to_vec(&output).unwrap()
            },
        ));
        let server = serve(listener, responses);
        let result = broker
            .invoke(
                &context(),
                None,
                None,
                InvocationRequest {
                    id: "case".parse().unwrap(),
                    capability,
                    input,
                    secret_use,
                    trace_parent: TraceParent::new([7; 16], [3; 8], 1).unwrap(),
                },
                AssetInputs::default(),
            )
            .await;
        let wire = server.join();
        let result = result.unwrap();
        assert_eq!(
            result.result.outcome,
            InvocationOutcome::Succeeded,
            "{args:?}: {result:?}"
        );
        let wire = wire.unwrap();
        assert_eq!(result.result.output, Some(output));
        assert_eq!(wire.len(), if args[0] == "--job" { 1 } else { 2 });
        for request in &wire {
            assert_eq!(
                request
                    .to_ascii_lowercase()
                    .matches("authorization: bearer broker-only-test-token\r\n")
                    .count(),
                1
            );
        }
        if wire.len() == 2 {
            assert!(wire[0].starts_with("POST /v1/sessions HTTP/1.1\r\n"));
            assert_eq!(
                serde_json::from_str::<Value>(wire[0].split_once("\r\n\r\n").unwrap().1).unwrap(),
                json!({"profile":"travel","name":"default"})
            );
        }
        let last = wire.last().unwrap();
        assert!(last.starts_with(&format!(
            "{} {expected_path} HTTP/1.1\r\n",
            if expected_body.is_some() {
                "POST"
            } else {
                "GET"
            }
        )));
        let body = last.split_once("\r\n\r\n").unwrap().1;
        if let Some(expected) = expected_body {
            assert_eq!(serde_json::from_str::<Value>(body).unwrap(), expected);
        } else {
            assert!(body.is_empty());
        }
        if args.len() == 3 && args[0] == "--artifacts" {
            assert!(
                last.to_ascii_lowercase()
                    .contains("range: bytes=0-65536\r\n")
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn nested_and_spaced_artifacts_render_guidance_without_any_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let registry = registry(&listener.local_addr().unwrap().to_string()).await;
    for path in ["dir/a.txt", "a b.txt"] {
        let args = ["--artifacts", "--secret", SECRET, "travel", path].map(str::to_owned);
        let outcome = registry.run_command("ssh", &args, None).await.unwrap();
        assert!(
            matches!(outcome, CommandRunOutcome::Rendered { status: 2, stdout, stderr } if stdout.is_empty() && stderr == "ssh: artifact reads require a flat name; copy the file to a flat name under /artifacts first (e.g. ssh --secret DRN PROFILE -- cp 'dir/a b.png' /artifacts/shot.png)\n")
        );
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cedar_secret_deny_refuses_before_any_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let capability = "vm.job.get".parse().unwrap();
    let broker = broker(&authority, r#"@id("deny-token") forbid(principal, action == Dekopon::Action::"secret.use", resource);"#).await;
    let result = broker
        .invoke(
            &context(),
            None,
            None,
            InvocationRequest {
                id: "deny".parse().unwrap(),
                capability,
                input: json!({"jobId":"job-1"}),
                secret_use: Some(dekopon_core::SecretUseProposal::HttpBearer {
                    secret: SECRET.parse().unwrap(),
                }),
                trace_parent: TraceParent::new([7; 16], [3; 8], 1).unwrap(),
            },
            AssetInputs::default(),
        )
        .await
        .unwrap();
    assert_eq!(result.result.outcome, InvocationOutcome::Denied);
    assert_eq!(result.result.error.as_deref(), Some("secret-denied"));
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}
