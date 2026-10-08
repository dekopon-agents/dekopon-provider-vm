#![doc = "Authored synthetic VM job cassette replay and owner settings validation."]

use dekopon_provider_sdk::provider::{Header, Response};
use dekopon_provider_sdk_testkit::{HttpScript, Native};
use dekopon_vm_provider::Vm;
use serde_json::{Value, json};

#[test]
fn authored_job_cassette_replays_with_exact_owner_routing() {
    let exchange: Value =
        serde_json::from_str(include_str!("cassettes/vm/0001-GET-v1-jobs-job-1.json")).unwrap();
    assert_eq!(exchange["version"], 1);
    assert_eq!(exchange["request"]["query"], Value::Null);
    for (base, host, uri) in [
        (
            "https://vm-runner.vm-runner.svc.cluster.local:8443",
            "vm-runner.vm-runner.svc.cluster.local:8443",
            "https://vm-runner.vm-runner.svc.cluster.local:8443/v1/jobs/job-1",
        ),
        (
            "https://fixture.example.test/runner/api/",
            "fixture.example.test",
            "https://fixture.example.test/runner/api/v1/jobs/job-1",
        ),
    ] {
        let native = Native::<Vm>::new()
            .settings(json!({"baseUrl": base}))
            .http(HttpScript::new(
                host,
                "GET",
                Response {
                    status: exchange["response"]["status"].as_u64().unwrap() as u16,
                    headers: vec![
                        Header::text(
                            "content-type",
                            exchange["response"]["headers"]["content-type"]
                                .as_str()
                                .unwrap(),
                        )
                        .unwrap(),
                    ],
                    body: serde_json::to_vec(&exchange["response"]["body"]["json"]).unwrap(),
                },
            ));
        let output = native.call("vm.job.get", r#"{"jobId":"job-1"}"#);
        assert_eq!(output.status, 0, "{}", output.stderr);
        let requests = native.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, exchange["request"]["method"]);
        assert_eq!(requests[0].uri, uri);
        assert_eq!(
            requests[0].uri,
            format!(
                "{}{}",
                base.trim_end_matches('/'),
                exchange["request"]["path"].as_str().unwrap()
            )
        );
        assert!(requests[0].body.is_empty());
        for name in ["accept", "authorization"] {
            assert!(
                !requests[0]
                    .headers
                    .iter()
                    .any(|h| h.name.eq_ignore_ascii_case(name))
            );
            assert!(exchange["request"]["headers"].get(name).is_none());
        }
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            json!({"state":"running"})
        );
    }
}

#[test]
fn invalid_or_missing_owner_settings_never_send_requests() {
    let mut settings = vec![None, Some(json!({}))];
    settings.extend([
        json!({"baseUrl":"https://fixture.example.test?q=1"}),
        json!({"baseUrl":"https://user@fixture.example.test"}),
        json!({"baseUrl":"https://fixture.example.test#fragment"}),
        json!({"baseUrl":"ftp://fixture.example.test"}),
        json!({"baseUrl":"fixture.example.test"}),
        json!({"baseUrl":"https://"}),
        json!({"baseUrl":"https://fixture.example.test /"}),
        json!({"baseUrl":42}),
        json!({"baseUrl":null}),
        json!({"baseUrl":"https://fixture.example.test","endpoint":"https://other.example.test"}),
        json!({"base_url":"https://fixture.example.test"}),
    ].into_iter().map(Some));
    for settings in settings {
        let native = Native::<Vm>::new();
        let native = match settings {
            Some(settings) => native.settings(settings),
            None => native,
        };
        let output = native.call("vm.job.get", r#"{"jobId":"job-1"}"#);
        assert_ne!(output.status, 0);
        assert!(output.stdout.is_empty());
        assert!(output.stderr.contains("settings"), "{}", output.stderr);
        assert!(native.requests().is_empty());
    }
}
