//! Broker-wired real-component VM secret and artifact checks.
mod support;

use dekopon_broker::{Broker, InMemoryAuditLog, InvocationRequest};
use dekopon_broker_host::{CommandRunOutcome, asset::AssetInputs};
use dekopon_broker_protocol::TraceParent;
use dekopon_capability::InvocationOutcome;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::FileExt,
    thread,
    time::Duration,
};
use support::{SECRET, TOKEN, context, serve, streams};

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
    support::broker(authority, prefix, deny, asset_root, false).await
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
    let permitted = broker(&authority, false, None).await;
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
    let session = br#"{"sessionId":"session-1"}"#;
    let mut created = format!(
        "HTTP/1.1 201 Created\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        session.len()
    )
    .into_bytes();
    created.extend_from_slice(session);
    let mut clip = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nsha256: {digest}\r\nConnection: close\r\n\r\n",
        bytes.len()
    )
    .into_bytes();
    clip.extend_from_slice(&bytes);
    let server = serve(listener, vec![created, clip]);
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

#[tokio::test(flavor = "multi_thread")]
async fn the_artifacts_command_with_no_path_lists_through_the_built_component() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let response = |status: &str, body: &[u8]| {
        let mut bytes = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        bytes.extend_from_slice(body);
        bytes
    };
    let server = serve(
        listener,
        vec![
            response("201 Created", br#"{"sessionId":"session-1"}"#),
            response("200 OK", br#"["clip.mp4","notes/a.txt"]"#),
        ],
    );
    let broker = broker(&authority, false, None).await;
    let words = ["--artifacts", "--secret", SECRET, "travel"].map(str::to_owned);
    let CommandRunOutcome::Proposed {
        capability,
        input,
        secret_use,
    } = broker
        .run_command(&context(), None, None, "ssh", &words, false)
        .await
        .unwrap()
    else {
        panic!("expected proposal")
    };
    assert_eq!(capability.as_str(), "vm.artifact.read");
    let mut call = request("list", input, secret_use);
    call.capability = capability;
    let (assets, mut stdout) = streams();
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
        json!(["clip.mp4", "notes/a.txt"])
    );
    let paths = server.join().unwrap();
    assert_eq!(
        paths
            .iter()
            .map(|wire| wire.lines().next().unwrap())
            .collect::<Vec<_>>(),
        [
            "POST /v1/sessions HTTP/1.1",
            "GET /v1/sessions/session-1/artifacts HTTP/1.1"
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wait_read_through_the_broker_sends_one_prefer_header_under_the_query_free_binding() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let body = br#"{"exitCode":7,"outcome":"executed","stderr":"","stdout":"smoke result","truncated":false}"#;
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    let server = serve(listener, vec![response]);
    // The asset-root broker serves under /runner/api; its job binding keeps allowQuery false.
    let root = tempfile::tempdir().unwrap();
    let broker = broker(&authority, false, Some(root.path())).await;
    let words = ["--job", "job-1", "--wait", "20", "--secret", SECRET].map(str::to_owned);
    let CommandRunOutcome::Proposed {
        input, secret_use, ..
    } = broker
        .run_command(&context(), None, None, "ssh", &words, false)
        .await
        .unwrap()
    else {
        panic!("expected proposal")
    };
    let (assets, mut stdout) = streams();
    let result = broker
        .invoke(
            &context(),
            None,
            None,
            request("wait", input, secret_use),
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
        serde_json::from_slice::<Value>(body).unwrap()
    );
    let wires = server.join().unwrap();
    assert_eq!(wires.len(), 1);
    let wire = wires[0].to_ascii_lowercase();
    assert_eq!(
        wires[0].lines().next(),
        Some("GET /runner/api/v1/jobs/job-1 HTTP/1.1")
    );
    assert_eq!(wire.matches("\r\nprefer:").count(), 1);
    assert!(wire.contains("\r\nprefer: wait=20\r\n"));
    assert_eq!(wire.matches("authorization:").count(), 1);
    assert!(wire.contains(&format!("authorization: bearer {TOKEN}\r\n")));
    assert!(!wires[0].contains(SECRET));
}
#[tokio::test(flavor = "multi_thread")]
async fn the_legacy_authority_realm_spelling_is_refused_in_the_guest_before_any_http() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let broker = broker(&authority, false, None).await;
    let words = [
        "--job",
        "job-1",
        "--secret",
        "drn:com.xrl:secret:test:vm/token",
    ]
    .map(str::to_owned);
    let refused = broker
        .run_command(&context(), None, None, "ssh", &words, false)
        .await
        .unwrap();
    let CommandRunOutcome::Failed { error } = refused else {
        panic!("expected the fixed --secret refusal, got {refused:?}")
    };
    assert_eq!(
        (error.code.as_str(), error.message.as_str()),
        ("usage", "ssh: --secret requires one bare secret DRN\n")
    );
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}
