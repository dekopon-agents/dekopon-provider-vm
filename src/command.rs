use crate::{Artifact, ArtifactInput, Exec, ExecInput, Job, JobInput, Vm};
use dekopon_provider_sdk::provider::{Proposal, Usage};
use dekopon_provider_sdk::{SecretDrn, SecretUseProposal};

use crate::Operation;

pub(crate) const MAX_ARGV: usize = 70;
pub(crate) const MAX_BYTES: usize = 24_576;
pub(crate) const USAGE: &str = "usage: ssh [--session NAME] --secret DRN [--timeout SECONDS] PROFILE -- ARGV...\n       ssh --job JOBID --secret DRN\n       ssh --artifacts [--session NAME] --secret DRN PROFILE [PATH]\ntry 'ssh --help'\n";
const HELP: &str = "ssh: broker-authorized commands in vm-runner jails (not SSH transport).\n\nssh [--session NAME] --secret DRN [--timeout SECONDS] PROFILE -- ARGV...\nssh --job JOBID --secret DRN\nssh --artifacts [--session NAME] --secret DRN PROFILE [PATH]\n\nSession defaults to default; timeout is 1-25 seconds (default 25).\nNAME and PROFILE: lowercase letters, digits and hyphens, 1-63 characters,\nstarting with a letter or digit. Stdin passes through to exec.\n--secret requires a bare drn:<authority>:secret:<realm>:<path>.\nThe broker authorizes and injects the Bearer token; this provider never sees it.\nArtifacts return UTF-8 text up to 64 KiB, otherwise metadata only.\nArtifact reads require a flat name: [A-Za-z0-9][A-Za-z0-9._-]{0,127}.\nCopy other files to a flat name under /artifacts first; listing shows all paths.\n-h, --help prints this help. No retries; poll an unknown outcome with --job.\n";
const SECRET: &str = "ssh: --secret requires one bare secret DRN\n";
pub(crate) const ARTIFACT_PATH: &str = "ssh: artifact reads require a flat name; copy the file to a flat name under /artifacts first (e.g. ssh --secret DRN PROFILE -- cp 'dir/a b.png' /artifacts/shot.png)\n";

pub(crate) fn name(s: &str) -> bool {
    (1..=63).contains(&s.len())
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub(crate) fn job_id(s: &str) -> bool {
    (1..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
pub(crate) fn path(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub(crate) fn propose(argv: &[String], stdin_piped: bool) -> Result<Proposal<Vm>, Usage> {
    parse(argv, stdin_piped).map_err(Usage::new)
}

fn parse(argv: &[String], stdin_piped: bool) -> Result<Proposal<Vm>, &'static str> {
    let argv_bytes = argv
        .iter()
        .map(String::len)
        .try_fold(0usize, usize::checked_add)
        .ok_or(USAGE)?;
    if argv.len() > MAX_ARGV || argv_bytes > MAX_BYTES {
        return Err(USAGE);
    }
    let mut index = 0;
    let mut session = None;
    let mut secret = None;
    let mut timeout = None;
    let mut operation = None;
    let mut job = None;
    let mut positional = Vec::new();
    let mut exec = None;
    while let Some(arg) = argv.get(index) {
        index += 1;
        match arg.as_str() {
            "-h" | "--help" => return Err(HELP),
            "--" => {
                exec = Some(&argv[index..]);
                break;
            }
            "--secret" => {
                if secret.is_some() {
                    return Err(SECRET);
                }
                secret = Some(
                    take(argv, &mut index)
                        .map_err(|_| SECRET)?
                        .parse::<SecretDrn>()
                        .map_err(|_| SECRET)?,
                );
            }
            "--session" => {
                if session.is_some() {
                    return Err(USAGE);
                }
                session = Some(take(argv, &mut index)?);
            }
            "--timeout" => {
                if timeout.is_some() {
                    return Err(USAGE);
                }
                let seconds = take(argv, &mut index)?;
                if !seconds.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(USAGE);
                }
                timeout = Some(
                    seconds
                        .parse::<u32>()
                        .ok()
                        .filter(|n| (1..=25).contains(n))
                        .ok_or(USAGE)?,
                );
            }
            "--job" => {
                if operation.is_some() {
                    return Err(USAGE);
                }
                operation = Some(Operation::Job);
                job = Some(take(argv, &mut index)?);
            }
            "--artifacts" => {
                if operation.is_some() {
                    return Err(USAGE);
                }
                operation = Some(Operation::Artifact);
            }
            s if s.starts_with('-') => {
                return Err(
                    if matches!(operation, Some(Operation::Artifact)) && !positional.is_empty() {
                        ARTIFACT_PATH
                    } else {
                        USAGE
                    },
                );
            }
            s => positional.push(s),
        }
    }
    let secret = secret.ok_or(SECRET)?;
    let op = operation.unwrap_or(Operation::Exec);
    let name = session.unwrap_or("default");
    if !self::name(name) {
        return Err(USAGE);
    }
    let proposal = match op {
        Operation::Job => {
            if session.is_some() || timeout.is_some() || exec.is_some() || !positional.is_empty() {
                return Err(USAGE);
            }
            let id = job.filter(|s| job_id(s)).ok_or(USAGE)?;
            Proposal::to::<Job>(JobInput { job_id: id.into() })
        }
        Operation::Exec => {
            if positional.len() != 1 || !self::name(positional[0]) {
                return Err(USAGE);
            }
            let args = exec
                .filter(|a| {
                    !a.is_empty() && !a[0].is_empty() && a.iter().all(|s| !s.contains('\0'))
                })
                .ok_or(USAGE)?;
            Proposal::to::<Exec>(ExecInput {
                profile: positional[0].into(),
                name: name.into(),
                argv: args.to_vec(),
                stdin_piped,
                stdin_budget: stdin_piped.then_some(MAX_BYTES - argv_bytes),
                deadline_ms: timeout.unwrap_or(25) * 1000,
            })
        }
        Operation::Artifact => {
            if timeout.is_some()
                || exec.is_some()
                || !(1..=2).contains(&positional.len())
                || !self::name(positional[0])
            {
                return Err(USAGE);
            }
            let path = positional
                .get(1)
                .map(|p| {
                    if !self::path(p) {
                        return Err(ARTIFACT_PATH);
                    }
                    Ok((*p).to_owned())
                })
                .transpose()?;
            Proposal::to::<Artifact>(ArtifactInput {
                profile: positional[0].into(),
                name: name.into(),
                path,
            })
        }
    };
    Ok(proposal.with_secret_use(SecretUseProposal::HttpBearer { secret }))
}

fn take<'a>(args: &'a [String], index: &mut usize) -> Result<&'a str, &'static str> {
    let value = args.get(*index).ok_or(USAGE)?;
    *index += 1;
    Ok(value)
}
