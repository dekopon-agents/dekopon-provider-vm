#![doc = "Built-component job polls against vm-runner job-wait's JobStatus bodies."]

use dekopon_provider_sdk::CommandRunOutcome;
use dekopon_provider_sdk::provider::{Header, Response, command};
use dekopon_provider_sdk_testkit::{Harness, HttpScript};
use dekopon_vm_provider::Vm;
use serde_json::{Value, json};

const SECRET: &str = "drn:com.xrl:secret:test:vm/token";

fn component() -> std::path::PathBuf {
    std::env::var_os("DEKOPON_PROVIDER_COMPONENT")
        .expect("built component")
        .into()
}

#[test]
fn a_wait_poll_through_the_built_component_reads_running_then_the_result() {
    // JobStatus bodies from vm-runner's openapi: ControllerRunning, then ExecResult.
    for (wait, body) in [
        (None, json!({"state":"running"})),
        (
            Some("20"),
            json!({"exitCode":7,"outcome":"executed","stderr":"","stdout":"smoke result","truncated":false}),
        ),
    ] {
        let mut words = vec!["--job", "job-1"];
        words.extend(
            wait.map(|seconds| ["--wait", seconds])
                .into_iter()
                .flatten(),
        );
        words.extend(["--secret", SECRET]);
        let words: Vec<String> = words.into_iter().map(str::to_owned).collect();
        let CommandRunOutcome::Proposed {
            capability, input, ..
        } = command::<Vm>(&words, false)
        else {
            panic!("expected proposal")
        };
        let run = Harness::<Vm>::get(component()).http(HttpScript::new(
            "localhost",
            "GET",
            Response {
                status: 200,
                headers: vec![Header::text("content-type", "application/json").unwrap()],
                body: serde_json::to_vec(&body).unwrap(),
            },
        ));
        let base = format!("{}/runner/api/", run.origin().unwrap());
        let output = run
            .settings(json!({"baseUrl": base}))
            .call(capability.as_str(), input)
            .unwrap();
        assert_eq!(output.status, 0, "{}", output.stderr);
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            body
        );
        assert_eq!(output.http_calls.len(), 1);
        let request = output.http_request.unwrap();
        assert_eq!(request.method, "GET");
        let query = if wait.is_some() { "?waitMs=20000" } else { "" };
        assert_eq!(request.uri, format!("{base}v1/jobs/job-1{query}"));
        assert!(
            !request
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("authorization"))
        );
    }
}
