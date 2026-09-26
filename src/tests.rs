use super::*;
use dekopon_provider_sdk::SecretUseProposal;

const SECRET: &str = "drn:com.xrl:secret:test:vm/token";
fn words(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}
fn proposal(args: &[&str], stdin: Option<&str>) -> dekopon_provider_sdk::CommandInvocation {
    let CommandRun::Proposal(v) = command::run(&words(args), stdin) else {
        panic!("expected proposal")
    };
    assert_eq!(
        v.secret_use,
        Some(SecretUseProposal::HttpBearer {
            secret: SECRET.parse().unwrap()
        })
    );
    assert!(!v.input.to_string().contains(SECRET));
    v
}
#[test]
fn every_form_proposes_only_its_closed_input_and_secret_use() {
    let manifest = Vm::manifest();
    assert_eq!(manifest.command_words, ["ssh"]);
    assert_eq!(manifest.id.as_str(), "vm");
    assert_eq!(
        manifest
            .capabilities
            .iter()
            .map(|c| (c.id.as_str(), c.effect, c.risk))
            .collect::<Vec<_>>(),
        vec![
            ("vm.exec", EffectKind::ExternalWrite, RiskLevel::High),
            ("vm.job.get", EffectKind::ReadOnly, RiskLevel::Low),
            ("vm.artifact.read", EffectKind::ReadOnly, RiskLevel::Low),
        ]
    );
    assert!(
        manifest
            .capabilities
            .iter()
            .all(|c| c.input_schema["additionalProperties"] == false)
    );
    let v = proposal(
        &["--secret", SECRET, "travel", "--", "echo", "--help"],
        Some("piped"),
    );
    assert_eq!(v.capability.as_str(), "vm.exec");
    assert_eq!(
        v.input,
        json!({"profile":"travel", "name":"default", "argv":["echo","--help"], "stdin":"piped", "deadlineMs":25000})
    );
    let v = proposal(
        &[
            "--session",
            "trip-1",
            "--timeout",
            "1",
            "--secret",
            SECRET,
            "travel",
            "--",
            "pwd",
        ],
        None,
    );
    assert_eq!(v.input["name"], "trip-1");
    assert_eq!(v.input["deadlineMs"], 1000);
    let v = proposal(&["--job", "job-1", "--secret", SECRET], None);
    assert_eq!(v.capability.as_str(), "vm.job.get");
    assert_eq!(v.input, json!({"jobId":"job-1"}));
    for tail in [vec!["travel"], vec!["travel", "Shot_1.txt"]] {
        let mut args = vec!["--artifacts", "--secret", SECRET];
        args.extend(tail);
        let v = proposal(&args, None);
        assert_eq!(v.capability.as_str(), "vm.artifact.read");
        assert_eq!(v.input["name"], "default");
    }
}
#[test]
fn malformed_forms_render_fixed_usage_without_echoing_values() {
    for args in [
        vec![],
        vec!["--secret"],
        vec!["--secret", "private-sentinel"],
        vec!["--secret", SECRET, "--secret", SECRET],
        vec!["--job"],
        vec!["--job", "x", "--job", "y"],
        vec!["--artifacts", "--artifacts"],
        vec!["--job", "x", "--artifacts"],
        vec!["--artifacts", "--job", "x"],
        vec!["--session"],
        vec!["--timeout"],
        vec!["--timeout", "0"],
        vec!["--timeout", "26"],
        vec!["--timeout", "nan"],
        vec!["--timeout", "+1"],
        vec!["--timeout", "1", "--timeout", "1"],
        vec!["--session", "a", "--session", "b"],
        vec!["--session", "Bad", "travel", "--", "pwd"],
        vec!["--wat"],
        vec!["--secret=x"],
        vec!["Travel", "--", "pwd"],
        vec!["-bad", "--", "pwd"],
        vec!["travel"],
        vec!["travel", "extra", "--", "pwd"],
        vec!["travel", "--"],
        vec!["travel", "--", ""],
        vec!["travel", "--", "a\0b"],
        vec!["--job", "../x"],
        vec!["--job", "x", "profile"],
        vec!["--job", "x", "--session", "a"],
        vec!["--job", "x", "--timeout", "1"],
        vec!["--job", "x", "--", "pwd"],
        vec!["--artifacts"],
        vec!["--artifacts", "travel", "a", "b"],
        vec!["--artifacts", "travel", "../x"],
        vec!["--artifacts", "travel", "--timeout", "1"],
        vec!["--artifacts", "travel", "--", "x"],
    ] {
        let mut args = words(&args);
        if !args.iter().any(|a| a.starts_with("--secret")) && !args.is_empty() {
            args.splice(0..0, words(&["--secret", SECRET]));
        }
        let CommandRun::Rendered {
            stdout,
            stderr,
            status,
        } = command::run(&args, None)
        else {
            panic!("accepted {args:?}")
        };
        assert_eq!(status, 2, "{args:?}");
        assert!(stdout.is_empty());
        assert!(
            stderr == "ssh: --secret requires one bare secret DRN\n"
                || stderr.starts_with("usage: ssh ")
                || stderr == command::ARTIFACT_PATH
        );
        assert!(!stderr.contains("private-sentinel"));
    }
}
#[test]
fn help_is_local_and_input_caps_include_stdin() {
    assert!(
        matches!(command::run(&words(&["travel", "--", "pwd"]), None), CommandRun::Rendered { status: 2, stderr, .. } if stderr == "ssh: --secret requires one bare secret DRN\n")
    );
    for flag in ["-h", "--help"] {
        assert!(
            matches!(command::run(&words(&[flag]), None), CommandRun::Rendered { status: 0, stderr, .. } if stderr.is_empty())
        );
    }
    for args in [
        vec!["x".into(); 71],
        vec!["x".repeat(command::MAX_BYTES + 1)],
    ] {
        assert!(matches!(
            command::run(&args, None),
            CommandRun::Rendered { status: 2, .. }
        ));
    }
    assert!(matches!(
        command::run(
            &words(&["--secret", SECRET, "travel", "--", "cat"]),
            Some(&"x".repeat(command::MAX_BYTES))
        ),
        CommandRun::Rendered { status: 2, .. }
    ));
    for invalid in ["", "A", "-a", "a_b", &"a".repeat(64)] {
        assert!(!command::name(invalid));
    }
    assert!(command::name(&"a".repeat(63)));
}
fn response(status: u16, body: Value) -> Response {
    Response {
        status,
        headers: vec![],
        body: serde_json::to_vec(&body).unwrap(),
    }
}
#[test]
fn exec_preserves_all_contract_outcomes_and_never_sets_authorization() {
    for (status, body) in [
        (
            200,
            json!({"outcome":"executed","stdout":"\u{0000}raw\n","stderr":"err","exitCode":7,"truncated":false}),
        ),
        (202, json!({"outcome":"unknown","jobId":"job-1"})),
        (
            400,
            json!({"outcome":"not_executed","reason":"bad_argv","truncated":false}),
        ),
        (
            413,
            json!({"outcome":"not_executed","reason":"too_large","truncated":false}),
        ),
        (
            502,
            json!({"outcome":"not_executed","reason":"boot_failed","truncated":false}),
        ),
    ] {
        let mut calls = Vec::new();
        let result = invoke_with(
            &"vm.exec".parse().unwrap(),
            json!({"profile":"travel","name":"default","argv":["pwd"],"deadlineMs":25000}),
            DEFAULT_BASE,
            |r| {
                calls.push(r);
                Ok(if calls.len() == 1 {
                    response(201, json!({"sessionId":"session-1"}))
                } else {
                    response(status, body.clone())
                })
            },
        )
        .unwrap();
        assert_eq!(result, body);
        assert_eq!(calls.len(), 2);
        assert!(
            calls
                .iter()
                .all(|r| r.headers.iter().all(|h| h.name != "authorization"))
        );
    }
}
#[test]
fn status_and_transport_failures_are_fixed_and_not_retried() {
    for (status, body, code) in [
        (401, json!({}), "vm-unauthorized"),
        (409, json!({}), "vm-conflict"),
        (400, json!({"reason":"quota"}), "vm-quota"),
        (400, json!({}), "vm-bad-request"),
        (503, json!({}), "vm-unavailable"),
        (500, json!({}), "vm-failed"),
        (302, json!({}), "vm-failed"),
    ] {
        let mut count = 0;
        let err = invoke_with(
            &"vm.exec".parse().unwrap(),
            json!({"profile":"travel","name":"default","argv":["pwd"],"deadlineMs":1000}),
            DEFAULT_BASE,
            |_| {
                count += 1;
                Ok(response(status, body.clone()))
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), code);
        assert_eq!(count, 1);
    }
    for (kind, code) in [
        (HttpErrorCode::Denied, "http-denied"),
        (HttpErrorCode::Timeout, "http-timeout"),
        (HttpErrorCode::Connect, "http-failed"),
    ] {
        assert_eq!(
            map_http_error(HttpError {
                code: kind,
                message: "private-sentinel".into()
            })
            .code(),
            code
        );
    }
}
#[test]
fn artifact_projection_returns_whole_small_text_or_metadata_without_bytes() {
    assert_eq!(
        artifact(
            Response {
                status: 416,
                headers: vec![Header::text("content-range", "bytes */0").unwrap()],
                body: vec![]
            },
            "empty"
        )
        .unwrap(),
        json!("")
    );
    for (body, status, total, text) in [
        (b"hello".to_vec(), 200, 5, true),
        (vec![255], 200, 1, false),
        (vec![b'x'; 65537], 206, 999999, false),
    ] {
        let headers = vec![
            Header::text("sha256", "a".repeat(64)).unwrap(),
            Header::text(
                "content-range",
                format!("bytes 0-{}/{total}", body.len() - 1),
            )
            .unwrap(),
        ];
        let output = artifact(
            Response {
                status,
                headers,
                body,
            },
            "file",
        )
        .unwrap();
        assert_eq!(
            output,
            if text {
                json!("hello")
            } else {
                json!({"path":"file","bytes":total,"sha256":"a".repeat(64),"binary":true})
            }
        );
    }
}
#[test]
fn artifact_names_are_flat_unreserved_and_refused_before_http() {
    for path in [
        "",
        ".hidden",
        "a/b",
        "a b",
        "a%20b",
        "a\\b",
        "x?y",
        "é",
        "-a",
        &"a".repeat(129),
    ] {
        let args = words(&["--artifacts", "--secret", SECRET, "travel", path]);
        assert!(
            matches!(command::run(&args, None), CommandRun::Rendered { status: 2, stdout, stderr } if stdout.is_empty() && stderr == command::ARTIFACT_PATH)
        );
        assert_eq!(
            invoke_with(
                &"vm.artifact.read".parse().unwrap(),
                json!({"profile":"travel","name":"default","path":path}),
                DEFAULT_BASE,
                |_| panic!("no HTTP")
            )
            .unwrap_err()
            .code(),
            "invalid-input"
        );
    }
    assert!(command::path(&"a".repeat(128)));
}
#[test]
fn closed_inputs_refuse_extra_authority_and_invalid_values_before_http() {
    for value in [
        json!({"jobId":"x","url":"https://evil"}),
        json!({"jobId":"x","secret":SECRET}),
        json!({"jobId":"../x"}),
        json!({"jobId":null}),
    ] {
        assert_eq!(
            invoke_with(
                &"vm.job.get".parse().unwrap(),
                value,
                DEFAULT_BASE,
                |_| panic!("no HTTP")
            )
            .unwrap_err()
            .code(),
            "invalid-input"
        );
    }
}
