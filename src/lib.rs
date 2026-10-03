//! Broker-only imports deliberately prevent execution under a direct, non-broker host.

use dekopon_provider_sdk::provider::{
    self, Capability, Code, Failure, Header, Http, HttpError, HttpErrorCode, Proposal, Provider,
    Request, Response, Settings as ProviderSettings, Stdout, Usage, method,
};
use dekopon_provider_sdk::{EffectKind, RiskLevel};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use serde_json::{Value, json};
use std::{fmt, io::Read};

mod command;

#[cfg(test)]
const DEFAULT_BASE: &str = "https://vm-runner.vm-runner.svc.cluster.local:8443";
const TEXT_LIMIT: usize = 65_536;

/// Broker-authorized VM provider.
pub struct Vm;
/// Runs an argv in a named jail.
pub struct Exec;
/// Fetches a job's status.
pub struct Job;
/// Lists or reads an artifact.
pub struct Artifact;

/// The ssh argv grammar.
pub struct VmArgs {
    words: Vec<String>,
}
#[derive(clap::Parser)]
#[command(name = "ssh", about = "Broker-authorized commands in vm-runner jails")]
struct RawArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
    words: Vec<String>,
}
impl clap::CommandFactory for VmArgs {
    fn command() -> clap::Command {
        RawArgs::command()
    }
    fn command_for_update() -> clap::Command {
        RawArgs::command_for_update()
    }
}
impl clap::FromArgMatches for VmArgs {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        let raw = <RawArgs as clap::FromArgMatches>::from_arg_matches(matches)?;
        let mut index = 0;
        while index < raw.words.len() {
            let word = &raw.words[index];
            if word == "--" {
                break;
            }
            if matches!(
                word.as_str(),
                "--secret" | "--session" | "--timeout" | "--job"
            ) {
                index += 2;
                continue;
            }
            if word.starts_with('-') && !matches!(word.as_str(), "--artifacts" | "-h" | "--help") {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::UnknownArgument,
                    "unsupported ssh option",
                ));
            }
            index += 1;
        }
        Ok(Self { words: raw.words })
    }
    fn from_arg_matches_mut(matches: &mut clap::ArgMatches) -> Result<Self, clap::Error> {
        Self::from_arg_matches(matches)
    }
    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
    fn update_from_arg_matches_mut(
        &mut self,
        matches: &mut clap::ArgMatches,
    ) -> Result<(), clap::Error> {
        self.update_from_arg_matches(matches)
    }
}
impl clap::Parser for VmArgs {}

#[derive(Debug)]
/// Stable credential-free VM failure.
#[derive(Clone)]
pub struct VmError(&'static str);
impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl Failure for VmError {
    fn code(&self) -> Code {
        Code::new(self.0)
    }
}
fn error(code: &'static str) -> VmError {
    VmError(code)
}

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

    fn parse(id: &str) -> Result<Self, VmError> {
        match id {
            "vm.exec" | "exec" => Ok(Self::Exec),
            "vm.job.get" | "job.get" => Ok(Self::Job),
            "vm.artifact.read" | "artifact.read" => Ok(Self::Artifact),
            _ => Err(error("unsupported-capability")),
        }
    }
}

impl Provider for Vm {
    const ID: &'static str = "vm";
    const COMMAND_WORDS: &'static [&'static str] = &["ssh"];
    const DESCRIPTION: &'static str = "Runs commands and reads results in vm-runner jails.";
    type Args = VmArgs;
    type Capabilities = (Exec, Job, Artifact);
    fn propose(args: VmArgs, stdin_piped: bool) -> Result<Proposal<Self>, Usage> {
        command::propose(&args.words, stdin_piped)
    }
}

macro_rules! capability {
    ($ty:ident, $name:literal, $desc:literal, $effect:expr, $risk:expr, $input:ty) => {
        impl Capability for $ty {
            type Provider = Vm;
            const NAME: &'static str = $name;
            const DESCRIPTION: &'static str = $desc;
            const EFFECT: EffectKind = $effect;
            const RISK: RiskLevel = $risk;
            type Input = $input;
            type Needs = (Http, ProviderSettings<Settings>);
            type Error = VmError;
            fn run(
                input: Self::Input,
                (http, settings): Self::Needs,
                out: &mut Stdout,
            ) -> Result<(), VmError> {
                run_with(
                    Operation::parse(Self::NAME)?,
                    serde_json::to_value(input).map_err(|_| error("invalid-input"))?,
                    &settings.into_inner().base_url,
                    |r| http.send(r),
                    out,
                )
            }
        }
    };
}
capability!(
    Exec,
    "exec",
    "Run argv in a named jail session.",
    EffectKind::ExternalWrite,
    RiskLevel::High,
    ExecInput
);
capability!(
    Job,
    "job.get",
    "Read an asynchronous job result.",
    EffectKind::ReadOnly,
    RiskLevel::Low,
    JobInput
);
capability!(
    Artifact,
    "artifact.read",
    "List or read jail artifacts.",
    EffectKind::ExternalWrite,
    RiskLevel::Low,
    ArtifactInput
);

/// Required owner-authored VM runner configuration.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    base_url: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Closed VM execution input.
pub struct ExecInput {
    #[schemars(regex(pattern = "^[a-z0-9][a-z0-9-]{0,62}$"))]
    pub(crate) profile: String,
    #[schemars(regex(pattern = "^[a-z0-9][a-z0-9-]{0,62}$"))]
    pub(crate) name: String,
    #[schemars(length(min = 1, max = 70))]
    pub(crate) argv: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) stdin_piped: bool,
    /// Remaining original argv + stdin byte allowance. Only an argv proposal sets this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) stdin_budget: Option<usize>,
    #[schemars(range(min = 1000, max = 25000))]
    pub(crate) deadline_ms: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Closed VM artifact input.
pub struct ArtifactInput {
    #[schemars(regex(pattern = "^[a-z0-9][a-z0-9-]{0,62}$"))]
    pub(crate) profile: String,
    #[schemars(regex(pattern = "^[a-z0-9][a-z0-9-]{0,62}$"))]
    pub(crate) name: String,
    #[schemars(regex(pattern = "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"))]
    pub(crate) path: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Closed VM job input.
pub struct JobInput {
    #[schemars(regex(pattern = "^[A-Za-z0-9-]{1,128}$"))]
    pub(crate) job_id: String,
}

enum Input {
    Exec(ExecInput),
    Job(JobInput),
    Artifact(ArtifactInput),
}

fn input(op: Operation, value: Value) -> Result<Input, VmError> {
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
                || v.argv.iter().map(String::len).sum::<usize>() > command::MAX_BYTES
                || (v.stdin_piped != v.stdin_budget.is_some())
                || v.stdin_budget.is_some_and(|budget| {
                    budget > command::MAX_BYTES - v.argv.iter().map(String::len).sum::<usize>()
                })
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
    capability: &str,
    value: Value,
    base: &str,
    mut send: impl FnMut(Request) -> Result<Response, HttpError>,
) -> Result<Value, VmError> {
    let input = input(Operation::parse(capability)?, value)?;
    // Settings are owner-authored, but only the broker's allowedHosts grants a destination.
    if !(base.starts_with("https://") || base.starts_with("http://"))
        || base.contains(['?', '#', '@'])
        || base.bytes().any(|b| b.is_ascii_whitespace())
    {
        return Err(error("invalid-settings"));
    }
    let base = base.trim_end_matches('/');
    // Read and validate bounded piped data before the first VM effect (session creation).
    let stdin_text = if let Input::Exec(v) = &input {
        if v.stdin_piped {
            let budget = v.stdin_budget.ok_or_else(|| error("invalid-input"))?;
            let mut raw = Vec::new();
            provider::stdin()
                .ok_or_else(|| error("invalid-input"))?
                .take((budget + 1) as u64)
                .read_to_end(&mut raw)
                .map_err(|_| error("invalid-input"))?;
            if raw.len() > budget {
                return Err(error("invalid-input"));
            }
            Some(String::from_utf8(raw).map_err(|_| error("invalid-input"))?)
        } else {
            None
        }
    } else {
        None
    };
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
            if let Some(stdin) = stdin_text {
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

fn json_response(response: Response, allowed: &[u16]) -> Result<Value, VmError> {
    if !allowed.contains(&response.status) {
        return Err(status_error(&response));
    }
    serde_json::from_slice(&response.body).map_err(|_| error("invalid-response"))
}

fn status_error(response: &Response) -> VmError {
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

fn artifact(response: Response, path: &str) -> Result<Value, VmError> {
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

fn map_http_error(failure: HttpError) -> VmError {
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

fn run_with(
    op: Operation,
    input: Value,
    base: &str,
    send: impl FnMut(Request) -> Result<Response, HttpError>,
    out: &mut Stdout,
) -> Result<(), VmError> {
    let result = invoke_with(op.id(), input, base, send)?;
    // One bounded vm-runner response; no returned value side channel.
    serde_json::to_writer(out, &result).map_err(|_| error("output-closed"))
}

#[allow(unsafe_code)]
mod export {
    dekopon_provider_sdk::export!(super::Vm);
}

#[cfg(test)]
mod tests;
