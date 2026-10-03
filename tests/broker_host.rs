//! Real component conformance and refusal before any VM HTTP effect.
use dekopon_provider_sdk_testkit::{Harness, conformance};
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
    assert_eq!(Harness::<Vm>::compiled_identities(), 1);
}
