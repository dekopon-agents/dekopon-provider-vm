use super::*;
use dekopon_provider_sdk::{CommandRunOutcome, SecretUseProposal};

const SECRET: &str = "drn:com.xrl:secret:test:vm/token";
fn words(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}
fn command(args: &[&str], piped: bool) -> CommandRunOutcome {
    provider::command::<Vm>(&words(args), piped)
}
fn proposal(args: &[&str], piped: bool) -> (String, Value) {
    let CommandRunOutcome::Proposed {
        capability,
        input,
        secret_use,
    } = command(args, piped)
    else {
        panic!("expected proposal")
    };
    assert_eq!(
        secret_use,
        Some(SecretUseProposal::HttpBearer {
            secret: SECRET.parse().unwrap()
        })
    );
    assert!(!input.to_string().contains(SECRET));
    (capability.to_string(), input)
}
#[test]
fn manifest_preserves_identity_effects_and_closed_schemas() {
    let m = provider::manifest::<Vm>().unwrap();
    assert_eq!(m.id.as_str(), "vm");
    assert_eq!(m.command_words, ["ssh"]);
    assert_eq!(
        m.capabilities
            .iter()
            .map(|c| (c.id.as_str(), c.effect, c.risk))
            .collect::<Vec<_>>(),
        [
            ("vm.exec", EffectKind::ExternalWrite, RiskLevel::High),
            ("vm.job.get", EffectKind::ReadOnly, RiskLevel::Low),
            (
                "vm.artifact.read",
                EffectKind::ExternalWrite,
                RiskLevel::Low
            ),
        ]
    );
    assert!(
        m.capabilities
            .iter()
            .all(|c| c.input_schema["additionalProperties"] == false)
    );
}
#[test]
fn proposals_defer_pipe_and_keep_job_and_artifact_identity() {
    let args = ["--secret", SECRET, "travel", "--", "echo", "hi"];
    let (id, input) = proposal(&args, true);
    assert_eq!(id, "vm.exec");
    assert_eq!(
        input,
        json!({"profile":"travel","name":"default","argv":["echo","hi"],"stdinPiped":true,"stdinBudget":command::MAX_BYTES - args.iter().map(|a| a.len()).sum::<usize>(),"deadlineMs":25000})
    );
    assert!(!input.to_string().contains("piped-payload"));
    assert_eq!(
        proposal(&["--job", "job-1", "--secret", SECRET], false),
        ("vm.job.get".into(), json!({"jobId":"job-1"}))
    );
    assert_eq!(
        proposal(
            &["--artifacts", "--secret", SECRET, "travel", "Shot_1.txt"],
            false
        )
        .0,
        "vm.artifact.read"
    );
    for path in ["dir/a.txt", "a b.txt", "../x"] {
        assert!(!matches!(
            command(&["--artifacts", "--secret", SECRET, "travel", path], false),
            CommandRunOutcome::Proposed { .. }
        ));
    }
    for args in [
        vec!["--secret", SECRET, "--timeout", "26", "travel", "--", "pwd"],
        vec!["--secret", SECRET, "--job", "../x"],
    ] {
        assert!(!matches!(
            command(&args, false),
            CommandRunOutcome::Proposed { .. }
        ));
    }
}
fn response(status: u16, body: Value) -> Response {
    Response {
        status,
        headers: vec![],
        body: serde_json::to_vec(&body).unwrap(),
    }
}
#[test]
fn exec_keeps_job_status_and_never_sets_authorization() {
    for (status, body) in [
        (
            200,
            json!({"outcome":"executed","stdout":"raw\n","stderr":"err","exitCode":7,"truncated":false}),
        ),
        (202, json!({"outcome":"unknown","jobId":"job-1"})),
        (
            400,
            json!({"outcome":"not_executed","reason":"bad_argv","truncated":false}),
        ),
        (
            502,
            json!({"outcome":"not_executed","reason":"boot_failed","truncated":false}),
        ),
    ] {
        let mut calls = Vec::new();
        let result = invoke_with(
            "vm.exec",
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
fn validation_and_settings_reject_before_effect() {
    for value in [
        json!({"jobId":"../x"}),
        json!({"jobId":"x","secret":SECRET}),
    ] {
        assert_eq!(
            invoke_with("vm.job.get", value, DEFAULT_BASE, |_| panic!(
                "HTTP before validation"
            ))
            .unwrap_err()
            .code()
            .as_str(),
            "invalid-input"
        );
    }
    assert_eq!(
        invoke_with(
            "vm.job.get",
            json!({"jobId":"x"}),
            "http://user@invalid",
            |_| panic!("HTTP before settings")
        )
        .unwrap_err()
        .code()
        .as_str(),
        "invalid-settings"
    );
    for value in [
        json!({"profile":"travel","name":"default","argv":["cat"],"deadlineMs":25000,"stdinPiped":true}),
        json!({"profile":"travel","name":"default","argv":["cat"],"deadlineMs":25000,"stdinPiped":true,"stdinBudget":command::MAX_BYTES}),
        json!({"profile":"travel","name":"default","argv":["cat"],"deadlineMs":25000,"stdinBudget":1}),
    ] {
        assert_eq!(
            invoke_with("vm.exec", value, DEFAULT_BASE, |_| panic!(
                "HTTP before budget validation"
            ))
            .unwrap_err()
            .code()
            .as_str(),
            "invalid-input"
        );
    }
    assert!(serde_json::from_str::<Settings>("{bad").is_err());
    assert!(serde_json::from_str::<Settings>("{}").is_err());
    assert_eq!(
        serde_json::from_str::<Settings>(r#"{"baseUrl":"https://vm.example"}"#)
            .unwrap()
            .base_url,
        "https://vm.example"
    );
}
#[test]
fn transport_and_artifact_bounds_keep_fixed_failures() {
    assert_eq!(
        map_http_error(HttpError {
            code: HttpErrorCode::Denied,
            message: "private-sentinel".into()
        })
        .code()
        .as_str(),
        "http-denied"
    );
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
    assert_eq!(
        artifact(
            Response {
                status: 200,
                headers: vec![],
                body: b"hello".to_vec()
            },
            "file"
        )
        .unwrap(),
        json!("hello")
    );
}

#[test]
fn native_invoke_reads_pipe_only_after_proposal_and_requires_valid_settings() {
    use dekopon_provider_sdk::provider::{NativeStdio, Port, invoke_native, with_port};
    use std::{
        io,
        sync::{Arc, Mutex},
    };
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl io::Write for Sink {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct Host {
        settings: Option<String>,
        calls: Arc<Mutex<Vec<Request>>>,
    }
    impl Port for Host {
        fn now_unix_millis(&mut self) -> u64 {
            0
        }
        fn now_nanos(&mut self) -> u64 {
            0
        }
        fn fill_random(&mut self, bytes: &mut [u8]) {
            bytes.fill(0);
        }
        fn settings(&mut self) -> Option<String> {
            self.settings.clone()
        }
        fn send(&mut self, r: Request) -> Result<Response, HttpError> {
            let mut calls = self.calls.lock().unwrap();
            calls.push(r);
            Ok(if calls.len() == 1 {
                response(201, json!({"sessionId":"session-1"}))
            } else {
                response(202, json!({"outcome":"unknown","jobId":"job-1"}))
            })
        }
        fn stream(
            &mut self,
            _: dekopon_provider_sdk::provider::StreamedRequest<'_>,
        ) -> Result<dekopon_provider_sdk::provider::StreamedResponse, HttpError> {
            panic!("no asset HTTP")
        }
    }
    let (_, proposal) = proposal(&["--secret", SECRET, "travel", "--", "cat"], true);
    let wire = proposal.to_string();
    for (settings, stdin, expected) in [
        (None, b"piped".to_vec(), 1),
        (Some("{bad".into()), b"piped".to_vec(), 1),
        (
            Some(format!(r#"{{"baseUrl":"{DEFAULT_BASE}"}}"#)),
            vec![b'x'; command::MAX_BYTES],
            1,
        ),
        (
            Some(format!(r#"{{"baseUrl":"{DEFAULT_BASE}"}}"#)),
            b"piped".to_vec(),
            0,
        ),
    ] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let output = Arc::new(Mutex::new(Vec::new()));
        let exit = with_port(
            Host {
                settings,
                calls: calls.clone(),
            },
            || {
                invoke_native::<Vm>(
                    "vm.exec",
                    &wire,
                    NativeStdio {
                        stdin: Some(Box::new(io::Cursor::new(stdin))),
                        stdout: Box::new(Sink(output.clone())),
                    },
                )
            },
        );
        assert_eq!(exit.status, expected, "{}", exit.stderr);
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), if expected == 0 { 2 } else { 0 });
        if expected == 0 {
            assert_eq!(
                serde_json::from_slice::<Value>(&calls[1].body).unwrap()["stdin"],
                "piped"
            );
            assert_eq!(
                serde_json::from_slice::<Value>(&output.lock().unwrap()).unwrap()["jobId"],
                "job-1"
            );
        } else {
            assert!(output.lock().unwrap().is_empty());
        }
    }
    let argv = ["--secret", SECRET, "travel", "--", "cat"];
    let full_argv_bytes = argv.iter().map(|s| s.len()).sum::<usize>();
    let (_, proposal) = self::proposal(&argv, true);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let output = Arc::new(Mutex::new(Vec::new()));
    let exit = with_port(
        Host {
            settings: Some(format!(r#"{{"baseUrl":"{DEFAULT_BASE}"}}"#)),
            calls: calls.clone(),
        },
        || {
            invoke_native::<Vm>(
                "vm.exec",
                &proposal.to_string(),
                NativeStdio {
                    stdin: Some(Box::new(io::Cursor::new(vec![
                        b'x';
                        command::MAX_BYTES
                            - full_argv_bytes
                            + 1
                    ]))),
                    stdout: Box::new(Sink(output.clone())),
                },
            )
        },
    );
    assert_ne!(
        exit.status, 0,
        "argv + piped stdin must stay within the original combined limit"
    );
    assert!(
        calls.lock().unwrap().is_empty(),
        "no session before rejecting the oversized pipe"
    );
    assert!(output.lock().unwrap().is_empty());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let exit = with_port(
        Host {
            settings: Some(format!(r#"{{"baseUrl":"{DEFAULT_BASE}"}}"#)),
            calls: calls.clone(),
        },
        || {
            invoke_native::<Vm>(
                "vm.artifact.read",
                &json!({"profile":"travel","name":"default","path":"shot.png"}).to_string(),
                NativeStdio {
                    stdin: None,
                    stdout: Box::new(Sink(output.clone())),
                },
            )
        },
    );
    assert_ne!(
        exit.status, 0,
        "artifact reads need the component asset grant"
    );
    assert!(calls.lock().unwrap().is_empty());
}

#[derive(Default)]
struct Log {
    requests: Vec<Request>,
    streamed: Vec<Request>,
    allocated: Vec<String>,
    reads: Vec<usize>,
    writes: Vec<usize>,
    attached: Vec<(String, Vec<u8>)>,
    released_writers: usize,
    released_bodies: usize,
}
type Shared = std::rc::Rc<std::cell::RefCell<Log>>;
struct Body {
    bytes: Vec<u8>,
    cursor: std::cell::Cell<usize>,
    log: Shared,
}
impl Drop for Body {
    fn drop(&mut self) {
        self.log.borrow_mut().released_bodies += 1;
    }
}
struct Writer {
    content_type: String,
    bytes: std::cell::RefCell<Vec<u8>>,
    attached: std::cell::Cell<bool>,
    log: Shared,
}
impl Drop for Writer {
    fn drop(&mut self) {
        if !self.attached.get() {
            self.log.borrow_mut().released_writers += 1;
        }
    }
}
struct Fake {
    log: Shared,
    artifact: Option<(u16, Vec<Header>, Vec<u8>)>,
    text: Response,
}
impl Transport for Fake {
    type Handle = Body;
    type Writer = Writer;
    fn send(&mut self, request: Request) -> Result<Response, HttpError> {
        let mut log = self.log.borrow_mut();
        log.requests.push(request);
        Ok(if log.requests.len() == 1 {
            response(201, json!({"sessionId":"session-1"}))
        } else {
            Response {
                status: self.text.status,
                headers: self.text.headers.clone(),
                body: self.text.body.clone(),
            }
        })
    }
    fn stream(&mut self, request: Request) -> Result<(u16, Vec<Header>, Body), HttpError> {
        self.log.borrow_mut().streamed.push(request);
        let (status, headers, bytes) = self.artifact.take().expect("no streamed read expected");
        Ok((
            status,
            headers,
            Body {
                bytes,
                cursor: 0.into(),
                log: self.log.clone(),
            },
        ))
    }
    fn read(&mut self, body: &Body, buffer: &mut [u8]) -> Result<usize, AssetError> {
        assert!(buffer.len() <= 65_536);
        let start = body.cursor.get();
        let n = buffer.len().min(body.bytes.len() - start);
        buffer[..n].copy_from_slice(&body.bytes[start..start + n]);
        body.cursor.set(start + n);
        self.log.borrow_mut().reads.push(n);
        Ok(n)
    }
    fn allocate(&mut self, content_type: &str) -> Result<Writer, AssetError> {
        self.log.borrow_mut().allocated.push(content_type.into());
        Ok(Writer {
            content_type: content_type.into(),
            bytes: Vec::new().into(),
            attached: false.into(),
            log: self.log.clone(),
        })
    }
    fn write_all(&mut self, writer: &Writer, bytes: &[u8]) -> Result<(), AssetError> {
        assert!(bytes.len() <= 65_536);
        self.log.borrow_mut().writes.push(bytes.len());
        writer.bytes.borrow_mut().extend_from_slice(bytes);
        Ok(())
    }
    fn attach(&mut self, writer: Writer) -> Result<(), AssetError> {
        writer.attached.set(true);
        self.log
            .borrow_mut()
            .attached
            .push((writer.content_type.clone(), writer.bytes.take()));
        Ok(())
    }
}
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
fn image(status: u16, length: Option<u64>, bytes: Vec<u8>) -> Option<(u16, Vec<Header>, Vec<u8>)> {
    let mut headers = vec![Header::text("sha256", DIGEST).unwrap()];
    if let Some(length) = length {
        headers.push(Header::text("Content-Length", length.to_string()).unwrap());
    }
    Some((status, headers, bytes))
}
fn read_artifact(
    path: &str,
    artifact: Option<(u16, Vec<Header>, Vec<u8>)>,
    text: Response,
) -> (Result<Value, VmError>, Shared) {
    let log = Shared::default();
    let result = invoke_with(
        "vm.artifact.read",
        json!({"profile":"travel","name":"default","path":path}),
        DEFAULT_BASE,
        Fake {
            log: log.clone(),
            artifact,
            text,
        },
    );
    (result, log)
}

#[test]
fn png_and_jpeg_artifacts_attach_their_full_bytes_in_64k_reads() {
    for (path, content_type, size) in [
        ("shot.png", "image/png", 150_000_usize),
        ("Photo.JPG", "image/jpeg", 65_536),
        ("page.jpeg", "image/jpeg", 7),
    ] {
        let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let (result, log) = read_artifact(
            path,
            image(200, Some(size as u64), bytes.clone()),
            response(500, json!(null)),
        );
        assert_eq!(
            result.unwrap(),
            json!({"path":path,"bytes":size,"sha256":DIGEST,"binary":true,"attached":true})
        );
        let log = log.borrow();
        assert_eq!(log.requests.len(), 1, "only session creation is buffered");
        assert_eq!(log.streamed.len(), 1);
        let get = &log.streamed[0];
        assert_eq!(get.method, "GET");
        assert!(
            get.uri
                .ends_with(&format!("/v1/sessions/session-1/artifacts/{path}"))
        );
        assert!(get.headers.iter().all(|h| h.name != "range"));
        assert_eq!(log.allocated, [content_type]);
        assert_eq!(log.attached, [(content_type.to_owned(), bytes)]);
        assert!(log.reads.iter().all(|&n| n <= 65_536));
        assert_eq!(log.reads.len(), size.div_ceil(65_536) + 1);
        assert_eq!(log.writes.iter().sum::<usize>(), size);
        assert_eq!((log.released_writers, log.released_bodies), (0, 1));
    }
}

#[test]
fn failed_image_reads_attach_nothing_and_release_the_writer_and_body() {
    let limit = 8 * 1024 * 1024;
    for (artifact, code, allocated) in [
        (
            image(200, Some(100), vec![1; 50]),
            "artifact-length-mismatch",
            1,
        ),
        (
            image(200, Some(50), vec![1; 100]),
            "artifact-length-mismatch",
            1,
        ),
        (
            image(404, Some(9), b"not found".to_vec()),
            "vm-bad-request",
            0,
        ),
        (image(503, None, vec![]), "vm-unavailable", 0),
        (image(200, None, vec![1; 10]), "invalid-response", 0),
        (
            image(200, Some(limit + 1), vec![1; limit as usize + 1]),
            "asset-too-large",
            0,
        ),
    ] {
        let (result, log) = read_artifact("shot.png", artifact, response(500, json!(null)));
        assert_eq!(result.unwrap_err().code().as_str(), code);
        let log = log.borrow();
        assert!(log.attached.is_empty(), "{code}");
        assert_eq!(log.allocated.len(), allocated, "{code}");
        assert_eq!(
            (log.released_writers, log.released_bodies),
            (allocated, 1),
            "{code}"
        );
    }
}

#[test]
fn other_artifact_paths_keep_the_ranged_text_or_metadata_read() {
    let text = Response {
        status: 200,
        headers: vec![],
        body: b"hello".to_vec(),
    };
    let (result, log) = read_artifact("notes.txt", None, text);
    assert_eq!(result.unwrap(), json!("hello"));
    let binary = Response {
        status: 206,
        headers: vec![
            Header::text("content-range", "bytes 0-65536/200000").unwrap(),
            Header::text("sha256", DIGEST).unwrap(),
        ],
        body: vec![0xff; 65_537],
    };
    for path in ["shot.webp", "shot.png.txt", "png", "blob"] {
        let (result, log) = read_artifact(
            path,
            None,
            Response {
                status: binary.status,
                headers: binary.headers.clone(),
                body: binary.body.clone(),
            },
        );
        assert_eq!(
            result.unwrap(),
            json!({"path":path,"bytes":200000,"sha256":DIGEST,"binary":true})
        );
        let log = log.borrow();
        assert!(log.streamed.is_empty() && log.allocated.is_empty());
        assert!(
            log.requests[1]
                .headers
                .iter()
                .any(|h| h.name == "range" && h.value == b"bytes=0-65536")
        );
    }
    let log = log.borrow();
    assert!(log.streamed.is_empty() && log.allocated.is_empty());
}
