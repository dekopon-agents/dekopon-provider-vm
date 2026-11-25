use async_trait::async_trait;
use dekopon_broker::{
    AuthenticatedContext, Broker, BrokerLimits, CapabilityRoute, ConstraintCatalog, ConstraintSet,
    DefaultSecretSink, DefaultSecretUse, IdentityDirectory, InMemoryAuditLog, PolicyEngine,
    PolicyWorld, SecretCatalog, SecretMaterial, SecretResolutionError, SecretResolver,
    SecretUseBinding,
};
use dekopon_broker_host::{
    BrokerHostLimits, BrokerHostOptions, BrokerProviderRegistry, asset::AssetInputs,
};
use dekopon_broker_protocol::Streams;
use dekopon_capability::{AssetConstraints, ExecutionConstraints, HttpConstraints, HttpPathRule};
use dekopon_core::{Actor, SecretDrn, SecretSinkKind};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    net::TcpListener,
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::PathBuf,
    sync::Arc,
    thread,
    time::Duration,
};

pub const SECRET: &str = "drn:secret:vm/token";
pub const TOKEN: &str = "broker-only-test-token";
#[derive(Debug)]
struct Resolver;
#[async_trait]
impl SecretResolver for Resolver {
    async fn resolve(&self, _: &SecretDrn) -> Result<SecretMaterial, SecretResolutionError> {
        Ok(SecretMaterial::new(TOKEN.as_bytes().to_vec()))
    }
}
pub fn component() -> PathBuf {
    std::env::var_os("DEKOPON_PROVIDER_COMPONENT")
        .expect("built component")
        .into()
}
pub fn context() -> AuthenticatedContext {
    AuthenticatedContext::attested(
        "caller".parse().unwrap(),
        Actor::Agent {
            agent: "vm-test".parse().unwrap(),
        },
        "gateway".parse().unwrap(),
        "drn:slack:user:example:user".parse().unwrap(),
    )
    .unwrap()
}
pub fn streams() -> (AssetInputs, UnixStream) {
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
pub async fn broker(
    authority: &str,
    prefix: &str,
    deny: bool,
    asset_root: Option<&std::path::Path>,
    agent_default: bool,
) -> Broker<InMemoryAuditLog> {
    const DEFAULT_SECRET: &str = "drn:secret:vm/fallback-token";
    let secret_drns: Vec<SecretDrn> = std::iter::once(SECRET)
        .chain(agent_default.then_some(DEFAULT_SECRET))
        .map(|drn| drn.parse().unwrap())
        .collect();
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
    .with_secrets(secret_drns.iter().cloned());
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
    let methods = |id: &str| match id {
        "vm.session.list" => vec!["GET".into()],
        "vm.session.close" => vec!["GET".into(), "DELETE".into()],
        _ => vec!["GET".into(), "POST".into()],
    };
    let request_limit = |id: &str| if id == "vm.session.list" { 1 } else { 2 };
    let bindings = capabilities
        .iter()
        .flat_map(|capability| {
            secret_drns.iter().enumerate().map(move |(index, drn)| {
                let id = capability.id.as_str();
                let allowed_paths = match id {
                    "vm.session.list" => vec![HttpPathRule::Exact {
                        path: format!("{prefix}/v1/sessions"),
                    }],
                    "vm.session.close" => vec![HttpPathRule::SegmentPrefix {
                        path: format!("{prefix}/v1/sessions"),
                    }],
                    _ => ["/v1/sessions", "/v1/jobs"]
                        .into_iter()
                        .map(|p| HttpPathRule::SegmentPrefix {
                            path: format!("{prefix}{p}"),
                        })
                        .collect(),
                };
                SecretUseBinding {
                    binding_id: format!("{id}-{index}"),
                    secret: drn.clone(),
                    capabilities: BTreeSet::from([capability.id.clone()]),
                    sink: SecretSinkKind::HttpBearer,
                    basic_username: None,
                    allowed_hosts: vec![authority.into()],
                    allowed_methods: methods(id),
                    allowed_paths,
                    allow_query: false,
                    max_injections: request_limit(id),
                }
            })
        })
        .collect();
    let catalog = ConstraintCatalog::new(capabilities.into_iter().map(|c| {
        let id = c.id.as_str();
        let artifact = id == "vm.artifact.read";
        let allowed_methods = methods(id);
        let max_requests = request_limit(id);
        (
            c.id,
            ConstraintSet {
                route: CapabilityRoute::Generic,
                provider: "vm".parse().unwrap(),
                effect: c.effect,
                risk: c.risk,
                default_secret_use: agent_default.then(|| DefaultSecretUse {
                    drn: DEFAULT_SECRET.parse().unwrap(),
                    sink: DefaultSecretSink::HttpBearer,
                }),
                constraints: ExecutionConstraints {
                    timeout_ms: 10000,
                    http: Some(HttpConstraints {
                        allowed_hosts: vec![authority.into()],
                        allowed_methods,
                        max_requests,
                        max_request_bytes: 200000,
                        max_response_bytes: if artifact { 9 * 1024 * 1024 } else { 1048576 },
                        allow_plaintext_loopback: true,
                        propagate_trace: false,
                        request_templates: Vec::new(),
                        signed_download: None,
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
    let catalog = if agent_default {
        catalog.with_agent_secrets(BTreeMap::from([(
            "vm-test".parse().unwrap(),
            BTreeMap::from([(DEFAULT_SECRET.parse().unwrap(), SECRET.parse().unwrap())]),
        )]))
    } else {
        catalog
    };
    Broker::new(
        registry,
        "broker".parse().unwrap(),
        PolicyEngine::new(&policy, &world).unwrap(),
        catalog,
        IdentityDirectory::empty(),
        Arc::new(InMemoryAuditLog::new(32).unwrap()),
        BrokerLimits::default(),
    )
    .unwrap()
    .with_secret_catalog(SecretCatalog::new(bindings, Arc::new(Resolver)).unwrap())
    .unwrap()
}
/// Answers one loopback connection per response, in order; returns each request's head.
pub fn serve(listener: TcpListener, responses: Vec<Vec<u8>>) -> thread::JoinHandle<Vec<String>> {
    thread::spawn(move || {
        let mut paths = Vec::new();
        for response in responses {
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
            for chunk in response.chunks(65_536) {
                stream.write_all(chunk).unwrap();
            }
        }
        paths
    })
}
