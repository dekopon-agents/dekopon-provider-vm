//! Broker-only imports deliberately prevent execution under a direct, non-broker host.

use dekopon_provider_sdk::asset::{self, AssetError, AssetErrorCode, Encoding};
use dekopon_provider_sdk::provider::endpoint::Base;
use dekopon_provider_sdk::provider::{
    self, Assets, Capability, Code, Failure, Header, Http, HttpError, HttpErrorCode, Proposal,
    Provider, Request, Response, Settings as ProviderSettings, Stdout, StreamedRequest, Usage,
    method,
};
use dekopon_provider_sdk::{EffectKind, RiskLevel};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{convert::Infallible, fmt, io::Read};

mod command;

// The `vm` Agent Skill: untrusted model text that grants nothing.
dekopon_provider_sdk::skills!("vm/SKILL.md");

#[cfg(test)]
const DEFAULT_BASE: &str = "https://vm-runner.vm-runner.svc.cluster.local:8443";
const TEXT_LIMIT: usize = 65_536;
const CHUNK: usize = 65_536;
const ASSET_LIMIT: u64 = 8 * 1024 * 1024;
const ATTACH_TYPES: [(&str, &str); 4] = [
    (".mp4", "video/mp4"),
    (".png", "image/png"),
    (".jpg", "image/jpeg"),
    (".jpeg", "image/jpeg"),
];

/// Broker-authorized VM provider.
pub struct Vm;
/// Runs an argv in a named jail.
pub struct Exec;
/// Fetches a job's status.
pub struct Job;
/// Lists or reads an artifact.
pub struct Artifact;
/// Lists the caller's sessions.
pub struct SessionList;
/// Closes one named session.
pub struct SessionClose;

/// The ssh argv grammar.
pub struct VmArgs {
    words: Vec<String>,
}
#[derive(clap::Parser)]
#[command(
    name = "ssh",
    about = "Broker-authorized commands in vm-runner jails",
    override_help = command::HELP
)]
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
                "--secret" | "--session" | "--timeout" | "--job" | "--wait"
            ) {
                index += 2;
                continue;
            }
            if word.starts_with('-')
                && !matches!(
                    word.as_str(),
                    "--artifacts" | "--list" | "--close" | "-h" | "--help"
                )
            {
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
pub struct VmError(VmFailure);

#[derive(Debug, Clone)]
enum VmFailure {
    Fixed(&'static str),
    Quota {
        sessions_in_use: u64,
        max_sessions: u32,
    },
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            VmFailure::Fixed(code) => f.write_str(code),
            VmFailure::Quota {
                sessions_in_use,
                max_sessions,
            } => {
                let noun = if max_sessions == 1 {
                    "instance"
                } else {
                    "instances"
                };
                write!(
                    f,
                    "could not reach host: you're at {sessions_in_use} of {max_sessions} running {noun} allowed. close another session to use another host"
                )
            }
        }
    }
}
impl Failure for VmError {
    fn code(&self) -> Code {
        Code::new(match self.0 {
            VmFailure::Fixed(code) => code,
            VmFailure::Quota { .. } => "vm-quota",
        })
    }
}
fn error(code: &'static str) -> VmError {
    VmError(VmFailure::Fixed(code))
}

#[derive(Clone, Copy)]
enum Operation {
    Exec,
    Job,
    Artifact,
    List,
    Close,
}

impl Operation {
    fn id(self) -> &'static str {
        match self {
            Self::Exec => "vm.exec",
            Self::Job => "vm.job.get",
            Self::Artifact => "vm.artifact.read",
            Self::List => "vm.session.list",
            Self::Close => "vm.session.close",
        }
    }

    fn parse(id: &str) -> Result<Self, VmError> {
        match id {
            "vm.exec" | "exec" => Ok(Self::Exec),
            "vm.job.get" | "job.get" => Ok(Self::Job),
            "vm.artifact.read" | "artifact.read" => Ok(Self::Artifact),
            "vm.session.list" | "session.list" => Ok(Self::List),
            "vm.session.close" | "session.close" => Ok(Self::Close),
            _ => Err(error("unsupported-capability")),
        }
    }
}

impl Provider for Vm {
    const ID: &'static str = "vm";
    const COMMAND_WORDS: &'static [&'static str] = &["ssh"];
    const DESCRIPTION: &'static str = "Runs commands and reads results in vm-runner jails.";
    type Args = VmArgs;
    type Capabilities = (Exec, Job, Artifact, SessionList, SessionClose);
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
impl Capability for Artifact {
    type Provider = Vm;
    const NAME: &'static str = "artifact.read";
    const DESCRIPTION: &'static str = "List or read jail artifacts.";
    const EFFECT: EffectKind = EffectKind::ExternalWrite;
    const RISK: RiskLevel = RiskLevel::Low;
    type Input = ArtifactInput;
    type Needs = (Http, Assets, ProviderSettings<Settings>);
    type Error = VmError;
    fn run(
        input: Self::Input,
        (http, assets, settings): Self::Needs,
        out: &mut Stdout,
    ) -> Result<(), VmError> {
        run_with(
            Operation::Artifact,
            serde_json::to_value(input).map_err(|_| error("invalid-input"))?,
            &settings.into_inner().base_url,
            Host { http, assets },
            out,
        )
    }
}

capability!(
    SessionList,
    "session.list",
    "List the caller's jail sessions.",
    EffectKind::ReadOnly,
    RiskLevel::Low,
    ListInput
);
capability!(
    SessionClose,
    "session.close",
    "Close a named jail session and wait for its pod to go away.",
    EffectKind::ExternalWrite,
    RiskLevel::Low,
    CloseInput
);

trait Transport {
    type Handle;
    type Writer;
    fn send(&mut self, request: Request) -> Result<Response, HttpError>;
    fn stream(&mut self, request: Request) -> Result<(u16, Vec<Header>, Self::Handle), HttpError>;
    fn read(&mut self, handle: &Self::Handle, buffer: &mut [u8]) -> Result<usize, AssetError>;
    fn allocate(&mut self, content_type: &str) -> Result<Self::Writer, AssetError>;
    fn write_all(&mut self, writer: &Self::Writer, bytes: &[u8]) -> Result<(), AssetError>;
    fn attach(&mut self, writer: Self::Writer) -> Result<(), AssetError>;
}

struct Host {
    http: Http,
    assets: Assets,
}
impl Transport for Host {
    type Handle = asset::Handle;
    type Writer = asset::Writer;
    fn send(&mut self, request: Request) -> Result<Response, HttpError> {
        self.http.send(request)
    }
    fn stream(&mut self, request: Request) -> Result<(u16, Vec<Header>, Self::Handle), HttpError> {
        let response = self.http.stream(StreamedRequest {
            method: request.method,
            uri: request.uri,
            headers: request.headers,
            body: Vec::new(),
        })?;
        Ok((response.status, response.headers, response.body))
    }
    fn read(&mut self, handle: &Self::Handle, buffer: &mut [u8]) -> Result<usize, AssetError> {
        handle.read(buffer)
    }
    fn allocate(&mut self, content_type: &str) -> Result<Self::Writer, AssetError> {
        self.assets.allocate(content_type, Encoding::Identity)
    }
    fn write_all(&mut self, writer: &Self::Writer, bytes: &[u8]) -> Result<(), AssetError> {
        writer.write_all(bytes)
    }
    fn attach(&mut self, writer: Self::Writer) -> Result<(), AssetError> {
        self.assets.attach(writer).map(drop)
    }
}

/// Exec and job hold no asset grant, so a buffered sender never reaches the attach path.
impl<F: FnMut(Request) -> Result<Response, HttpError>> Transport for F {
    type Handle = Infallible;
    type Writer = Infallible;
    fn send(&mut self, request: Request) -> Result<Response, HttpError> {
        self(request)
    }
    fn stream(&mut self, _: Request) -> Result<(u16, Vec<Header>, Infallible), HttpError> {
        Err(HttpError {
            code: HttpErrorCode::Denied,
            message: "no asset grant".into(),
        })
    }
    fn read(&mut self, handle: &Infallible, _: &mut [u8]) -> Result<usize, AssetError> {
        match *handle {}
    }
    fn allocate(&mut self, _: &str) -> Result<Infallible, AssetError> {
        Err(AssetError {
            code: AssetErrorCode::Denied,
            message: "no asset grant".into(),
        })
    }
    fn write_all(&mut self, writer: &Infallible, _: &[u8]) -> Result<(), AssetError> {
        match *writer {}
    }
    fn attach(&mut self, writer: Infallible) -> Result<(), AssetError> {
        match writer {}
    }
}

/// Required owner-authored VM runner configuration.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    base_url: Base,
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
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) path: Option<String>,
}

/// An optional field is absent or a value; an explicit `null` is refused.
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Closed VM job input.
pub struct JobInput {
    #[schemars(regex(pattern = "^[A-Za-z0-9-]{1,128}$"))]
    pub(crate) job_id: String,
    /// Server-side wait bound, sent as `Prefer: wait=<seconds>`; absent reads at once.
    #[schemars(range(min = 1, max = 25))]
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) wait_seconds: Option<u32>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Closed session-list input.
pub struct ListInput {}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Closed session-close input.
pub struct CloseInput {
    #[schemars(regex(pattern = "^[a-z0-9][a-z0-9-]{0,62}$"))]
    pub(crate) name: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ListedSession {
    #[serde(skip_serializing)]
    session_id: String,
    name: String,
    profile: String,
    state: SessionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<SessionEndReason>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SessionState {
    Pending,
    Ready,
    Down,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SessionEndReason {
    Idle,
    MaxSeconds,
    BootFailure,
    Duplicate,
    Terminal,
    Closed,
}

#[derive(Deserialize)]
struct CloseRefusal {
    error: CloseCode,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CloseCode {
    UnknownSession,
    SessionDeleteFailed,
    SessionDeleteTimeout,
}

enum Input {
    Exec(ExecInput),
    Job(JobInput),
    Artifact(ArtifactInput),
    List,
    Close(CloseInput),
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
            if !command::job_id(&v.job_id) || v.wait_seconds.is_some_and(|s| !(1..=25).contains(&s))
            {
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
        Operation::List => {
            let _: ListInput = serde_json::from_value(value).map_err(|_| invalid())?;
            Ok(Input::List)
        }
        Operation::Close => {
            let v: CloseInput = serde_json::from_value(value).map_err(|_| invalid())?;
            if !command::name(&v.name) {
                return Err(invalid());
            }
            Ok(Input::Close(v))
        }
    }
}

fn invoke_with<T: Transport>(
    capability: &str,
    value: Value,
    base: &Base,
    mut transport: T,
) -> Result<Value, VmError> {
    let input = input(Operation::parse(capability)?, value)?;
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
    let request = |verb, path: &str, body: Option<Value>, header: Option<(&str, &str)>| {
        let mut request = Request::new(
            verb,
            base.join(path).map_err(|_| error("invalid-settings"))?,
        )
        .map_err(|_| error("invalid-settings"))?;
        if let Some(body) = body {
            request.body = serde_json::to_vec(&body).map_err(|_| error("invalid-input"))?;
            request.headers.push(
                Header::text("content-type", "application/json")
                    .map_err(|_| error("invalid-header"))?,
            );
        }
        if let Some((name, value)) = header {
            request
                .headers
                .push(Header::text(name, value).map_err(|_| error("invalid-header"))?);
        }
        Ok::<_, VmError>(request)
    };
    let mut call = |verb, path: &str, body: Option<Value>, header: Option<(&str, &str)>| {
        transport
            .send(request(verb, path, body, header)?)
            .map_err(map_http_error)
    };
    let (profile, name) = match &input {
        Input::Job(job) => {
            let wait = job.wait_seconds.map(|s| format!("wait={s}"));
            let response = call(
                method::GET,
                &format!("/v1/jobs/{}", encode(&job.job_id)),
                None,
                wait.as_deref().map(|wait| ("prefer", wait)),
            )?;
            return json_response(response, &[200, 502]);
        }
        Input::Exec(v) => (&v.profile, &v.name),
        Input::Artifact(v) => (&v.profile, &v.name),
        Input::List => {
            let sessions = list_sessions(call(method::GET, "/v1/sessions", None, None)?)?;
            return serde_json::to_value(sessions).map_err(|_| error("invalid-response"));
        }
        Input::Close(v) => {
            let sessions = list_sessions(call(method::GET, "/v1/sessions", None, None)?)?;
            let mut matches = sessions.iter().filter(|session| session.name == v.name);
            let session = matches.next().ok_or_else(|| error("vm-unknown-session"))?;
            if matches.next().is_some() || !command::job_id(&session.session_id) {
                return Err(error("invalid-response"));
            }
            let path = format!("/v1/sessions/{}", encode(&session.session_id));
            let response = call(method::DELETE, &path, None, None)?;
            return match response.status {
                204 => Ok(json!({"name": v.name, "state": "closed"})),
                404 | 502 | 504 => Err(close_refusal(&response)),
                _ => Err(status_error(&response)),
            };
        }
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
                let artifact_path = format!("{prefix}/artifacts/{path}");
                if let Some(content_type) = attach_type(&path) {
                    let get = request(method::GET, &artifact_path, None, None)?;
                    return attach(&mut transport, get, &path, content_type);
                }
                let response = call(
                    method::GET,
                    &artifact_path,
                    None,
                    Some(("range", "bytes=0-65536")),
                )?;
                artifact(response, &path)
            }
        },
        Input::Job(_) | Input::List | Input::Close(_) => {
            unreachable!("operation returned before session creation")
        }
    }
}

fn list_sessions(response: Response) -> Result<Vec<ListedSession>, VmError> {
    if response.status != 200 {
        return Err(status_error(&response));
    }
    serde_json::from_slice(&response.body).map_err(|_| error("invalid-response"))
}

fn close_refusal(response: &Response) -> VmError {
    let Ok(refusal) = serde_json::from_slice::<CloseRefusal>(&response.body) else {
        return error("invalid-response");
    };
    error(match (response.status, refusal.error) {
        (404, CloseCode::UnknownSession) => "vm-unknown-session",
        (502, CloseCode::SessionDeleteFailed) => "vm-session-delete-failed",
        (504, CloseCode::SessionDeleteTimeout) => "vm-session-delete-timeout",
        _ => "invalid-response",
    })
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
    status_code(response.status, &response.body)
}

fn status_code(status: u16, body: &[u8]) -> VmError {
    if status == 400
        && let Ok(body) = serde_json::from_slice::<Value>(body)
        && body["reason"] == "quota"
    {
        let sessions_in_use = body["sessionsInUse"].as_u64();
        let max_sessions = body["maxSessions"].as_u64().and_then(|n| n.try_into().ok());
        if let (true, Some(sessions_in_use), Some(max_sessions)) = (
            body["outcome"] == "not_executed",
            sessions_in_use,
            max_sessions,
        ) {
            return VmError(VmFailure::Quota {
                sessions_in_use,
                max_sessions,
            });
        }
        return error("vm-quota");
    }
    error(match status {
        401 | 403 => "vm-unauthorized",
        409 => "vm-conflict",
        429 => "vm-quota",
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

fn attach_type(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    ATTACH_TYPES
        .iter()
        .find(|(extension, _)| lower.ends_with(extension))
        .map(|(_, content_type)| *content_type)
}

fn attach<T: Transport>(
    transport: &mut T,
    request: Request,
    path: &str,
    content_type: &str,
) -> Result<Value, VmError> {
    let (status, headers, body) = transport.stream(request).map_err(map_http_error)?;
    if status != 200 {
        return Err(status_code(status, &[]));
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(&h.value).ok())
    };
    let bytes: u64 = header("content-length")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| error("invalid-response"))?;
    let sha256 = header("sha256")
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| error("invalid-response"))?;
    if bytes > ASSET_LIMIT {
        return Err(error("asset-too-large"));
    }
    let writer = transport.allocate(content_type).map_err(map_asset_error)?;
    let mut buffer = vec![0; CHUNK];
    let mut copied = 0u64;
    let mut digest = Sha256::new();
    loop {
        let read = transport
            .read(&body, &mut buffer)
            .map_err(map_asset_error)?;
        if read == 0 {
            break;
        }
        copied += read as u64;
        if copied > bytes || copied > ASSET_LIMIT {
            return Err(error("artifact-length-mismatch"));
        }
        digest.update(&buffer[..read]);
        transport
            .write_all(&writer, &buffer[..read])
            .map_err(map_asset_error)?;
    }
    if copied != bytes {
        return Err(error("artifact-length-mismatch"));
    }
    if hex::decode(sha256).ok().as_deref() != Some(digest.finalize().as_slice()) {
        return Err(error("artifact-hash-mismatch"));
    }
    drop(body);
    transport.attach(writer).map_err(map_asset_error)?;
    Ok(json!({"path": path, "bytes": bytes, "sha256": sha256, "binary": true, "attached": true}))
}

fn map_asset_error(failure: AssetError) -> VmError {
    error(match failure.code {
        AssetErrorCode::TooLarge => "asset-too-large",
        AssetErrorCode::Denied => "asset-denied",
        AssetErrorCode::TooManyAssets => "asset-too-many",
        AssetErrorCode::OverBudget => "asset-over-budget",
        _ => "asset-failed",
    })
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
    base: &Base,
    transport: impl Transport,
    out: &mut Stdout,
) -> Result<(), VmError> {
    let result = invoke_with(op.id(), input, base, transport)?;
    // One bounded vm-runner response; no returned value side channel.
    serde_json::to_writer(out, &result).map_err(|_| error("output-closed"))
}

#[allow(unsafe_code)]
mod export {
    dekopon_provider_sdk::export!(super::Vm);
}

#[cfg(test)]
mod tests;
