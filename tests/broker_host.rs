//! Real component conformance and broker-wired session commands.
mod support;

use dekopon_broker::InvocationRequest;
use dekopon_broker_host::CommandRunOutcome;
use dekopon_broker_protocol::TraceParent;
use dekopon_capability::InvocationOutcome;
use dekopon_provider_sdk::provider::Response;
use dekopon_provider_sdk_testkit::{Harness, HttpScript, conformance};
use dekopon_vm_provider::Vm;
use serde_json::{Value, json};
use std::{io::Read, net::TcpListener};
use support::{TOKEN, broker, component, context, serve, streams};

#[test]
fn component_conforms_and_requires_settings_before_vm_effect() {
    conformance::<Vm>(component()).expect("real component conformance");
    let output = Harness::<Vm>::get(component())
        .call("vm.job.get", json!({"jobId":"job-1"}))
        .expect("missing settings is a guest refusal");
    assert_ne!(output.status, 0);
    assert!(output.stdout.is_empty());
    assert!(output.stderr.contains("provider settings"));
    assert!(output.http_calls.is_empty());
    for settings in [
        json!({}),
        json!({"baseUrl":"https://fixture.example.test?query=1"}),
        json!({"baseUrl":"https://user@fixture.example.test"}),
        json!({"baseUrl":"https://fixture.example.test#fragment"}),
        json!({"baseUrl":"ftp://fixture.example.test"}),
        json!({"baseUrl":"fixture.example.test"}),
        json!({"baseUrl":42}),
        json!({"baseUrl":"https://fixture.example.test","unknown":true}),
    ] {
        let output = Harness::<Vm>::get(component())
            .settings(settings)
            .call("vm.job.get", json!({"jobId":"job-1"}))
            .unwrap();
        assert_ne!(output.status, 0);
        assert!(output.stdout.is_empty());
        assert!(output.stderr.contains("settings"), "{}", output.stderr);
        assert!(output.http_calls.is_empty());
    }
    let harness = Harness::<Vm>::get(component()).http(HttpScript::new(
        "localhost",
        "GET",
        Response {
            status: 200,
            headers: vec![],
            body: br#"{"state":"running"}"#.to_vec(),
        },
    ));
    let origin = harness.origin().unwrap().to_owned();
    let output = harness
        .settings(json!({"baseUrl":format!("{origin}/runner/api/")}))
        .call("vm.job.get", json!({"jobId":"job-1"}))
        .unwrap();
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert_eq!(output.http_calls.len(), 1);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        json!({"state":"running"})
    );
    assert_eq!(Harness::<Vm>::compiled_identities(), 1);
    for input in [
        json!({"profile":null,"name":"default","path":"clip.mp4"}),
        json!({"profile":"travel","name":null,"path":"clip.mp4"}),
        json!({"profile":"travel","name":"default","path":"dir/clip.mp4"}),
        json!({"profile":"travel","name":"default","path":null}),
    ] {
        let output = Harness::<Vm>::get(component())
            .settings(json!({"baseUrl":"https://fixture.example.test"}))
            .call("vm.artifact.read", input)
            .unwrap();
        assert_ne!(output.status, 0);
        assert!(output.http_calls.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn session_list_close_and_exec_use_the_agents_default_through_the_built_component() {
    const OLD_ID: &str = "019ac2bb-8b40-7a42-9e71-b01ded52c601";
    const NEW_ID: &str = "019ac2bb-8b40-7a42-9e71-b01ded52c602";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let prefix = "/runner/api";
    let listing = json!([{
        "sessionId": OLD_ID, "name": "default", "profile": "travel", "state": "ready"
    }])
    .to_string();
    let created = json!({
        "sessionId": NEW_ID, "name": "default", "profile": "travel", "shape": "fixture", "state": "pending"
    })
    .to_string();
    let executed = json!({
        "outcome": "executed", "exitCode": 0, "stdout": "ok\n", "stderr": "", "truncated": false
    });
    let response = |status, body: &str| {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    };
    let server = serve(
        listener,
        vec![
            response("200 OK", &listing),
            response("200 OK", &listing),
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_vec(),
            response("201 Created", &created),
            response("200 OK", &executed.to_string()),
        ],
    );
    let broker = broker(&authority, prefix, false, None, true).await;
    let context = context();
    for (id, words, expected_capability, expected_output) in [
        (
            "list-sessions",
            &["--list"][..],
            "vm.session.list",
            json!([{"name":"default","profile":"travel","state":"ready"}]),
        ),
        (
            "close-session",
            &["--close"],
            "vm.session.close",
            json!({"name":"default","state":"closed"}),
        ),
        ("exec", &["travel", "--", "pwd"], "vm.exec", executed),
    ] {
        let words: Vec<_> = words.iter().map(|word| (*word).to_owned()).collect();
        let CommandRunOutcome::Proposed {
            capability,
            input,
            secret_use,
        } = broker
            .run_command(&context, None, None, "ssh", &words, false)
            .await
            .unwrap()
        else {
            panic!("expected proposal for {words:?}");
        };
        assert_eq!(capability.as_str(), expected_capability);
        assert_eq!(secret_use, None);
        let (assets, mut stdout) = streams();
        let result = broker
            .invoke(
                &context,
                None,
                None,
                InvocationRequest {
                    id: id.parse().unwrap(),
                    capability,
                    input,
                    secret_use,
                    trace_parent: TraceParent::new([7; 16], [3; 8], 1).unwrap(),
                },
                assets,
            )
            .await
            .unwrap();
        assert_eq!(
            result.result.outcome,
            InvocationOutcome::Succeeded,
            "{id}: {:?}",
            result.result.error
        );
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&output).unwrap(),
            expected_output
        );
    }
    let requests = server.join().unwrap();
    assert_eq!(
        requests
            .iter()
            .map(|head| head.lines().next().unwrap())
            .collect::<Vec<_>>(),
        [
            format!("GET {prefix}/v1/sessions HTTP/1.1"),
            format!("GET {prefix}/v1/sessions HTTP/1.1"),
            format!("DELETE {prefix}/v1/sessions/{OLD_ID} HTTP/1.1"),
            format!("POST {prefix}/v1/sessions HTTP/1.1"),
            format!("POST {prefix}/v1/sessions/{NEW_ID}/exec HTTP/1.1"),
        ]
    );
    for request in requests {
        let head = request.to_ascii_lowercase();
        assert_eq!(
            head.lines()
                .filter(|line| line.starts_with("authorization:"))
                .collect::<Vec<_>>(),
            [format!("authorization: bearer {TOKEN}")]
        );
        assert!(
            head.lines()
                .any(|line| line == format!("host: {authority}"))
        );
    }
}
