//! Real component conformance and refusal before any VM HTTP effect.
use dekopon_provider_sdk::provider::Response;
use dekopon_provider_sdk_testkit::{Harness, HttpScript, conformance};
use dekopon_vm_provider::Vm;
use serde_json::json;
use std::path::PathBuf;

fn component() -> PathBuf {
    std::env::var_os("DEKOPON_PROVIDER_COMPONENT")
        .expect("build the component with provider-workflows/build.sh first")
        .into()
}

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
}
