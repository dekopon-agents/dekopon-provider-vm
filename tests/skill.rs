//! The embedded `vm` Agent Skill: its bytes in the component and its text rules.
use dekopon_broker_host::skills;
use dekopon_core::ProviderId;
use dekopon_provider_sdk::CommandRunOutcome;
use dekopon_provider_sdk::provider;
use dekopon_vm_provider::Vm;
use std::path::PathBuf;

const SKILL: &str = include_str!("../skills/vm/SKILL.md");
const DRN: &str = "drn:com.example:secret:test:vm/token";

fn front_matter() -> Vec<(&'static str, &'static str)> {
    let rest = SKILL.strip_prefix("---\n").expect("front matter opens");
    let (block, _) = rest.split_once("\n---\n").expect("front matter closes");
    block
        .lines()
        .map(|line| line.split_once(": ").expect("single-line key: value"))
        .collect()
}

#[test]
fn the_built_component_carries_the_skill_file_byte_for_byte() {
    let path: PathBuf = std::env::var_os("DEKOPON_PROVIDER_COMPONENT")
        .expect("build the component with provider-workflows/build.sh first")
        .into();
    let component = std::fs::read(path).expect("component bytes");
    let provider_id: ProviderId = "vm".parse().expect("provider id");
    let files = skills::read(&provider_id, &component).expect("skill sections");
    assert_eq!(files.len(), 1, "only vm/SKILL.md is embedded");
    assert_eq!(files[0].skill.as_str(), "vm");
    assert_eq!(files[0].path, "vm/SKILL.md");
    assert_eq!(files[0].bytes, SKILL.as_bytes());
}

#[test]
fn the_front_matter_holds_only_name_and_description_and_the_name_is_vm() {
    let keys = front_matter();
    assert_eq!(
        keys.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        ["name", "description"]
    );
    assert_eq!(keys[0].1, "vm");
    assert!(!keys[1].1.is_empty() && keys[1].1.len() <= 1024);
}

#[test]
fn the_skill_names_no_drn_url_or_installation_value() {
    // examples/ names no profile; these are its caller, agent, host and
    // authority, plus the profile the repository's own tests use.
    for forbidden in [
        "drn:",
        "://",
        "www.",
        "example-caller",
        "example-agent",
        "vm-runner",
        "com.xrl",
        "travel",
        "svc.cluster",
    ] {
        assert!(!SKILL.contains(forbidden), "skill contains {forbidden:?}");
    }
}

#[test]
fn every_ssh_line_the_skill_shows_parses_into_a_proposal() {
    let mut seen = 0;
    for line in SKILL.lines().filter(|l| l.starts_with("ssh ")) {
        let words: Vec<String> = line
            .split_whitespace()
            .map(|w| match w {
                "PROFILE" => "jail",
                "DRN" => DRN,
                "ID" => "job-1",
                other => other,
            })
            .map(String::from)
            .collect();
        match provider::command::<Vm>(&words[1..], false) {
            CommandRunOutcome::Proposed { .. } => seen += 1,
            other => panic!("{line:?} did not propose: {other:?}"),
        }
    }
    assert!(seen >= 6, "expected the skill's ssh examples, saw {seen}");
}
