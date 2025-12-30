use std::path::{Path, PathBuf};

use bloody_falcon::cli::commands::run_replay_with_config;
use bloody_falcon::cli::config::{CommandName, RunConfig};
use bloody_falcon::core::hash::sha256_hex;
use bloody_falcon::core::scope::load_scope;
use bloody_falcon::core::types::OutputFormat;

#[test]
fn replay_manifest_is_deterministic() {
    std::env::set_var("BF_FIXED_TIME", "2025-01-02T00:00:00Z");
    std::env::set_var("GITHUB_SHA", "test-hash");
    std::env::set_var("GIT_HASH", "test-hash");

    let scope = load_scope(Path::new("clients/example.toml")).unwrap();
    let temp_dir = std::env::temp_dir().join("bf_replay_test");
    let _ = std::fs::remove_dir_all(&temp_dir);
    let _ = std::fs::create_dir_all(&temp_dir);

    let cfg = RunConfig {
        command: CommandName::Replay,
        scope_path: Some(PathBuf::from("clients/example.toml")),
        demo_safe: false,
        no_network: true,
        format: OutputFormat::Jsonl,
        output: temp_dir.clone(),
        manifest: Some(temp_dir.join("manifest.json")),
        policy: None,
        detectors: None,
        sources: None,
        alerts: None,
        webhook_url: None,
        trend_window: None,
    };

    let fixture = Path::new("fixtures/run-2025-01-02.jsonl");
    let manifest = run_replay_with_config(&cfg, &scope, fixture).unwrap();
    let manifest_json = serde_json::to_string(&manifest).unwrap();
    let hash = sha256_hex(manifest_json.as_bytes());

    println!("Manifest JSON: {}", manifest_json);
    println!("Hash: {}", hash);

    assert_eq!(
        hash,
        "47127489f8808b8987125f4cdedb09410c34defe2983db04c9dec2d5e680c681"
    );
}
