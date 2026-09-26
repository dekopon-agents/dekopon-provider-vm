//! Broker-only imports deliberately prevent execution under a direct, non-broker host.

use dekopon_provider_http::{Header, HttpError, HttpErrorCode, Request, Response, method};
use dekopon_provider_sdk::{
    CapabilityId, CommandRun, EffectKind, Provider, ProviderApiVersion, ProviderCapability,
    ProviderError, ProviderManifest, RiskLevel,
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;
use serde_json::{Value, json};

mod command;

const DEFAULT_BASE: &str = "https://vm-runner.vm-runner.svc.cluster.local:8443";
const TEXT_LIMIT: usize = 65_536;

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "provider",
        generate_all,
        pub_export_macro: true,
    });
}

struct Vm;

#[derive(Clone, Copy)]
enum Operation {
    Exec,
    Job,
    Artifact,
}

impl Operation {
    fn id(self) -> &'static str {
        match self {
            Self::Exec => "vm.exec",
            Self::Job => "vm.job.get",
            Self::Artifact => "vm.artifact.read",
        }
    }

    fn parse(id: &str) -> Result<Self, ProviderError> {
        match id {
            "vm.exec" => Ok(Self::Exec),
            "vm.job.get" => Ok(Self::Job),
            "vm.artifact.read" => Ok(Self::Artifact),
            _ => Err(error("unsupported-capability")),
        }
    }
}

impl Provider for Vm {
    fn manifest() -> ProviderManifest {
        ProviderManifest {
            api_version: ProviderApiVersion::V1Alpha1,
            id: "vm".parse().expect("static provider ID"),
            description: "Runs commands and reads results in vm-runner jails.".into(),
            command_words: vec!["ssh".into()],
            capabilities: [Operation::Exec, Operation::Job, Operation::Artifact]
                .into_iter()
                .map(|op| ProviderCapability {
                    id: op.id().parse().expect("static capability ID"),
                    description: match op {
                        Operation::Exec => "Run argv in a named jail session.",
                        Operation::Job => "Read an asynchronous job result.",
                        Operation::Artifact => "List or read jail artifacts.",
                    }
                    .into(),
                    effect: match op {
                        Operation::Exec => EffectKind::ExternalWrite,
                        _ => EffectKind::ReadOnly,
                    },
                    risk: match op {
                        Operation::Exec => RiskLevel::High,
                        _ => RiskLevel::Low,
                    },
                    input_schema: schema(op),
                })
                .collect(),
        }
    }

    fn run_command(argv: &[String], stdin: Option<&str>) -> Result<CommandRun, ProviderError> {
        Ok(command::run(argv, stdin))
    }

    fn invoke(capability: &CapabilityId, input: Value) -> Result<Value, ProviderError> {
        let settings = bindings::dekopon::settings::config::get();
        let settings: Settings = settings
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| error("invalid-settings"))?
            .unwrap_or_default();
        invoke_with(
            capability,
            input,
            &settings.base_url,
            dekopon_provider_http::send,
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Settings {
    #[serde(default = "default_base")]
    base_url: String,
}

fn default_base() -> String {
    DEFAULT_BASE.into()
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            base_url: default_base(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecInput {
    profile: String,
    name: String,
    argv: Vec<String>,
    stdin: Option<String>,
    deadline_ms: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactInput {
    profile: String,
    name: String,
    path: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JobInput {
    job_id: String,
}

enum Input {
    Exec(ExecInput),
    Job(JobInput),
    Artifact(ArtifactInput),
}

fn input(op: Operation, value: Value) -> Result<Input, ProviderError> {
    let invalid = || error("invalid-input");
    match op {
        Operation::Exec => {
            let v: ExecInput = serde_json::from_value(value).map_err(|_| invalid())?;
            if !command::name(&v.profile)
                || !command::name(&v.name)
                || v.argv.is_empty()
                || v.argv[0].is_empty()
                || v.argv.len() > command::MAX_ARGV
                || !(1_000..=25_000).contains(&v.deadline_ms)
                || v.argv.iter().any(|a| a.contains('\0'))
                || v.argv.iter().map(String::len).sum::<usize>()
                    + v.stdin.as_ref().map_or(0, String::len)
                    > command::MAX_BYTES
            {
                return Err(invalid());
            }
            Ok(Input::Exec(v))
        }
        Operation::Job => {
            let v: JobInput = serde_json::from_value(value).map_err(|_| invalid())?;
            if !command::job_id(&v.job_id) {
                return Err(invalid());
            }
            Ok(Input::Job(v))
        }
        Operation::Artifact => {
            let v: ArtifactInput = serde_json::from_value(value).map_err(|_| invalid())?;
            if !command::name(&v.profile)
                || !command::name(&v.name)
                || v.path.as_deref().is_some_and(|p| !command::path(p))
            {
                return Err(invalid());
            }
            Ok(Input::Artifact(v))
        }
    }
}

fn invoke_with(
    capability: &CapabilityId,
    value: Value,
    base: &str,
    mut send: impl FnMut(Request) -> Result<Response, HttpError>,
) -> Result<Value, ProviderError> {
    let input = input(Operation::parse(capability.as_str())?, value)?;
    // Settings are owner-authored, but only the broker's allowedHosts grants a destination.
    if !(base.starts_with("https://") || base.starts_with("http://"))
        || base.contains(['?', '#', '@'])
        || base.bytes().any(|b| b.is_ascii_whitespace())
    {
        return Err(error("invalid-settings"));
    }
    let base = base.trim_end_matches('/');
    let mut call = |verb, path: &str, body: Option<Value>, range: Option<&str>| {
        let mut request =
            Request::new(verb, format!("{base}{path}")).map_err(|_| error("invalid-settings"))?;
        if let Some(body) = body {
            request.body = serde_json::to_vec(&body).map_err(|_| error("invalid-input"))?;
            request.headers.push(
                Header::text("content-type", "application/json")
                    .map_err(|_| error("invalid-header"))?,
            );
        }
        if let Some(range) = range {
            request
                .headers
                .push(Header::text("range", range).map_err(|_| error("invalid-header"))?);
        }
        send(request).map_err(map_http_error)
    };
    let (profile, name) = match &input {
        Input::Job(job) => {
            let response = call(
                method::GET,
                &format!("/v1/jobs/{}", encode(&job.job_id)),
                None,
                None,
            )?;
            return json_response(response, &[200, 502]);
        }
        Input::Exec(v) => (&v.profile, &v.name),
        Input::Artifact(v) => (&v.profile, &v.name),
    };
    let session = json_response(
        call(
            method::POST,
            "/v1/sessions",
            Some(json!({"profile": profile, "name": name})),
            None,
        )?,
        &[200, 201],
    )?;
    let id = session
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|id| command::job_id(id))
        .ok_or_else(|| error("invalid-response"))?;
    let prefix = format!("/v1/sessions/{}", encode(id));
    match input {
        Input::Exec(v) => {
            let mut body = json!({"argv": v.argv, "deadlineMs": v.deadline_ms});
            if let Some(stdin) = v.stdin {
                body["stdin"] = stdin.into();
            }
            // These non-2xx bodies are ExecResult, not transport failures, in vm-runner's OpenAPI.
            json_response(
                call(method::POST, &format!("{prefix}/exec"), Some(body), None)?,
                &[200, 202, 400, 413, 502],
            )
        }
        Input::Artifact(v) => match v.path {
            None => json_response(
                call(method::GET, &format!("{prefix}/artifacts"), None, None)?,
                &[200, 502],
            ),
            Some(path) => {
                let response = call(
                    method::GET,
                    &format!("{prefix}/artifacts/{path}"),
                    None,
                    Some("bytes=0-65536"),
                )?;
                artifact(response, &path)
            }
        },
        Input::Job(_) => unreachable!("job returned before session creation"),
    }
}

fn encode(value: &str) -> String {
    const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    utf8_percent_encode(value, SEGMENT).to_string()
}

fn json_response(response: Response, allowed: &[u16]) -> Result<Value, ProviderError> {
    if !allowed.contains(&response.status) {
        return Err(status_error(&response));
    }
    serde_json::from_slice(&response.body).map_err(|_| error("invalid-response"))
}

fn status_error(response: &Response) -> ProviderError {
    error(match response.status {
        401 | 403 => "vm-unauthorized",
        409 => "vm-conflict",
        429 => "vm-quota",
        400 if serde_json::from_slice::<Value>(&response.body)
            .ok()
            .is_some_and(|v| v["reason"] == "quota") =>
        {
            "vm-quota"
        }
        400 | 404 | 413 | 416 | 422 => "vm-bad-request",
        503 | 504 => "vm-unavailable",
        _ => "vm-failed",
    })
}

fn artifact(response: Response, path: &str) -> Result<Value, ProviderError> {
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(&h.value).ok())
    };
    if response.status == 416 && header("content-range") == Some("bytes */0") {
        return Ok(json!(""));
    }
    if !matches!(response.status, 200 | 206) {
        return Err(status_error(&response));
    }
    let bytes = if response.status == 206 {
        header("content-range")
            .and_then(|s| s.strip_prefix("bytes 0-"))
            .and_then(|s| s.split_once('/'))
            .and_then(|(end, total)| {
                let end: u64 = end.parse().ok()?;
                let total: u64 = total.parse().ok()?;
                (end.checked_add(1) == Some(response.body.len() as u64) && total > end)
                    .then_some(total)
            })
    } else {
        Some(response.body.len() as u64)
    }
    .ok_or_else(|| error("invalid-response"))?;
    if bytes <= TEXT_LIMIT as u64
        && bytes == response.body.len() as u64
        && let Ok(text) = std::str::from_utf8(&response.body)
    {
        return Ok(json!(text));
    }
    let sha256 = header("sha256")
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| error("invalid-response"))?;
    Ok(json!({"path": path, "bytes": bytes, "sha256": sha256, "binary": true}))
}

fn map_http_error(failure: HttpError) -> ProviderError {
    error(match failure.code {
        HttpErrorCode::Denied | HttpErrorCode::HostCallLimit => "http-denied",
        HttpErrorCode::RequestTooLarge => "request-too-large",
        HttpErrorCode::ResponseTooLarge => "response-too-large",
        HttpErrorCode::Timeout => "http-timeout",
        HttpErrorCode::InvalidUri => "invalid-uri",
        HttpErrorCode::InvalidHeader => "invalid-header",
        HttpErrorCode::InvalidMethod
        | HttpErrorCode::Dns
        | HttpErrorCode::Connect
        | HttpErrorCode::Tls
        | HttpErrorCode::Protocol
        | HttpErrorCode::Internal => "http-failed",
    })
}

fn error(code: &'static str) -> ProviderError {
    ProviderError::new(code, code)
}

fn schema(op: Operation) -> Value {
    let name = json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,62}$"});
    let mut value = json!({"type": "object", "additionalProperties": false, "properties": {}});
    match op {
        Operation::Job => {
            value["properties"] =
                json!({"jobId": {"type": "string", "pattern": "^[A-Za-z0-9-]{1,128}$"}});
            value["required"] = json!(["jobId"]);
        }
        Operation::Exec | Operation::Artifact => {
            value["properties"] = json!({"profile": name, "name": name});
            value["required"] = json!(["profile", "name"]);
            match op {
                Operation::Exec => {
                    value["properties"]["argv"] = json!({"type": "array", "minItems": 1, "maxItems": 70, "items": {"type": "string", "maxLength": 24576}});
                    value["properties"]["stdin"] = json!({"type": "string", "maxLength": 24576});
                    value["properties"]["deadlineMs"] =
                        json!({"type": "integer", "minimum": 1000, "maximum": 25000});
                    value["required"] = json!(["profile", "name", "argv", "deadlineMs"]);
                }
                Operation::Artifact => {
                    value["properties"]["path"] =
                        json!({"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"})
                }
                Operation::Job => unreachable!(),
            }
        }
    }
    value
}

dekopon_provider_sdk::export_provider_with_cli!(Vm, bindings);

#[cfg(test)]
mod tests;
