use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

/// The fixture the signing side (the Vault's `/sign-release-manifest`) and
/// the node agent's `canonical.mjs` both hash to 58363d39....
fn body() -> Value {
    json!({
        "v": 1, "app": "com.solar.yourowai", "channel": "stable", "sequence": 12,
        "issued_at": "2026-11-20T03:00:00Z", "version": "0.9.2",
        "notes_url": "https://github.com/WeAreFlowsta/your-own-ai/releases/tag/v0.9.2",
        "holochain": { "lines": ["holochain-0.7"], "changes_line": false },
        "rollout": { "percent": 100 }, "from_version": "0.9.1",
        "files": [
            { "platform": "darwin-aarch64", "kind": "app-tarball", "name": "Your.Own.AI_aarch64.app.tar.gz", "url": "https://example.com/a.tar.gz", "size": 123456, "sha256": "a".repeat(64) },
            { "platform": "windows-x86_64", "kind": "nsis", "name": "Your.Own.AI_0.9.2_x64-setup.exe", "url": "https://example.com/b.exe", "size": 654321, "sha256": "b".repeat(64) }
        ],
        "kit": [{ "line": "holochain-0.7", "target": "x86_64-pc-windows-msvc", "sidecar": "yourowai-holochain-07", "sha256": "c".repeat(64) }]
    })
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

/// A `did:flowsta:` identity for a key, as Holochain spells an agent key.
fn did(k: &SigningKey) -> String {
    let mut raw = vec![0x84, 0x20, 0x24];
    raw.extend_from_slice(k.verifying_key().as_bytes());
    raw.extend_from_slice(&[0, 0, 0, 0]);
    format!("did:flowsta:u{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

fn signed(mut m: Value, k: &SigningKey) -> Vec<u8> {
    let st = statement(&m).unwrap();
    let sig = base64::engine::general_purpose::STANDARD.encode(k.sign(st.as_bytes()).to_bytes());
    m["signature"] = json!({ "signer": did(k), "sig": sig, "statement": st });
    serde_json::to_vec(&m).unwrap()
}

fn signers() -> Vec<String> {
    vec![did(&key(7)), did(&key(8))]
}

fn installed(version: &str) -> Installed<'_> {
    Installed { version, last_sequence: Some(11), rollout_ticket: 5 }
}

fn checked(m: &[u8], version: &str) -> Result<Release, Refused> {
    let s = signers();
    let refs: Vec<&str> = s.iter().map(String::as_str).collect();
    check(m, &Trust { app: "com.solar.yourowai", channel: "stable", signers: &refs }, &installed(version))
}

#[test]
fn the_statement_matches_the_signing_side() {
    assert_eq!(
        statement(&body()).unwrap(),
        "flowsta-release-manifest:v1:com.solar.yourowai:stable:12:58363d398fa0463cbcb947af90a91756c1b0f59d66b476560b9a08a1c08794e8"
    );
}

#[test]
fn a_signed_newer_release_for_this_app_and_channel_is_accepted() {
    let r = checked(&signed(body(), &key(7)), "0.9.1").unwrap();
    assert_eq!((r.version.as_str(), r.sequence, r.rollout_percent), ("0.9.2", 12, 100));
    assert_eq!(r.signer, did(&key(7)));
    assert_eq!(r.file("windows-x86_64", "nsis").unwrap().size, 654321);
    assert!(r.file("windows-x86_64", "msi").is_none());
    // Any one trusted signer will do.
    assert!(checked(&signed(body(), &key(8)), "0.9.1").is_ok());
}

#[test]
fn a_manifest_from_elsewhere_or_tampered_with_is_refused() {
    let mut other = body();
    other["app"] = json!("com.example.other");
    assert_eq!(checked(&signed(other, &key(7)), "0.9.1").unwrap_err(), Refused::OtherApp("com.example.other".into()));
    let mut beta = body();
    beta["channel"] = json!("beta");
    assert_eq!(checked(&signed(beta, &key(7)), "0.9.1").unwrap_err(), Refused::OtherChannel("beta".into()));
    assert_eq!(checked(&signed(body(), &key(9)), "0.9.1").unwrap_err(), Refused::Signer(did(&key(9))));

    // A file swapped after signing: the body no longer matches the signature.
    let mut m: Value = serde_json::from_slice(&signed(body(), &key(7))).unwrap();
    m["files"][1]["sha256"] = json!("d".repeat(64));
    assert_eq!(checked(&serde_json::to_vec(&m).unwrap(), "0.9.1").unwrap_err(), Refused::Signature);
    // A statement that names something else.
    let mut m: Value = serde_json::from_slice(&signed(body(), &key(7))).unwrap();
    m["signature"]["statement"] = json!("flowsta-release-manifest:v1:com.solar.yourowai:stable:13:00");
    assert_eq!(checked(&serde_json::to_vec(&m).unwrap(), "0.9.1").unwrap_err(), Refused::Signature);
    // A signature by a trusted key over another body.
    let mut m: Value = serde_json::from_slice(&signed(body(), &key(7))).unwrap();
    let mut other = body();
    other["version"] = json!("0.9.3");
    let elsewhere: Value = serde_json::from_slice(&signed(other, &key(7))).unwrap();
    m["signature"]["sig"] = elsewhere["signature"]["sig"].clone();
    assert_eq!(checked(&serde_json::to_vec(&m).unwrap(), "0.9.1").unwrap_err(), Refused::Signature);
}

#[test]
fn replays_downgrades_skipped_releases_and_the_rollout_are_refused() {
    let m = signed(body(), &key(7));
    let s = signers();
    let refs: Vec<&str> = s.iter().map(String::as_str).collect();
    let trust = Trust { app: "com.solar.yourowai", channel: "stable", signers: &refs };
    let at = |version, last_sequence, rollout_ticket| check(&m, &trust, &Installed { version, last_sequence, rollout_ticket });
    assert_eq!(at("0.9.1", Some(12), 5).unwrap_err(), Refused::Replayed { sequence: 12, last: 12 });
    assert!(at("0.9.1", None, 5).is_ok(), "a first check has no sequence yet");
    assert_eq!(at("0.9.2", Some(11), 5).unwrap_err(), Refused::NotNewer { version: "0.9.2".into(), installed: "0.9.2".into() });
    assert_eq!(at("0.9.0", Some(11), 5).unwrap_err(), Refused::InstallFirst("0.9.1".into()));
    let mut slow = body();
    slow["rollout"] = json!({ "percent": 10 });
    let slow = signed(slow, &key(7));
    let ticket = |t| check(&slow, &trust, &Installed { version: "0.9.1", last_sequence: Some(11), rollout_ticket: t });
    assert!(ticket(9).is_ok());
    assert_eq!(ticket(10).unwrap_err(), Refused::NotYet { percent: 10 });
}

#[test]
fn a_manifest_that_could_hash_differently_or_mislead_is_refused_for_its_shape() {
    let refused = |edit: &dyn Fn(&mut Value)| {
        let mut m = body();
        edit(&mut m);
        match checked(&signed(m, &key(7)), "0.9.1") {
            Err(Refused::Shape(why)) => why,
            other => panic!("{other:?}"),
        }
    };
    assert!(refused(&|m| m["rollout"]["percent"] = json!(12.5)).contains("rollout.percent is not a whole number"));
    assert!(refused(&|m| m["v"] = json!(2)).contains("v must be 1"));
    assert!(refused(&|m| m["files"][0]["url"] = json!("http://example.com/a")).contains("url"));
    assert!(refused(&|m| m["files"][0]["platform"] = json!("linux-arm")).contains("platform"));
    assert!(refused(&|m| m["files"][0]["name"] = json!("../a.tar.gz")).contains("name"));
    assert!(refused(&|m| m["files"][0]["sha256"] = json!("A".repeat(64))).contains("sha256"));
    assert!(refused(&|m| m["kit"][0]["sha256"] = json!("short")).contains("kit[0]"));
    assert!(matches!(checked(b"{not json", "0.9.1"), Err(Refused::Shape(_))));
}

#[test]
fn the_downloaded_file_must_be_the_one_named() {
    let bytes = b"the installer";
    let file = File {
        platform: "linux-x86_64".into(),
        kind: "deb".into(),
        name: "x.deb".into(),
        url: "https://example.com/x.deb".into(),
        size: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    };
    assert!(check_file(&file, bytes).is_ok());
    assert_eq!(check_file(&file, b"the installer!").unwrap_err(), Refused::FileSize { expected: 13, got: 14 });
    assert_eq!(check_file(&file, b"the_installer").unwrap_err(), Refused::FileHash);
}

#[test]
fn versions_compare_naturally() {
    use std::cmp::Ordering::*;
    assert_eq!(compare_versions("1.8.0-beta10", "1.8.0-beta9"), Greater, "beta10 after beta9");
    assert_eq!(compare_versions("1.8.0", "1.8.0-beta10"), Greater, "a release after its betas");
    assert_eq!(compare_versions("1.10.0", "1.9.9"), Greater);
    assert_eq!(compare_versions("0.9.2", "0.9.1"), Greater);
    assert_eq!(compare_versions("1.8.0-beta.2", "1.8.0-beta.10"), Less);
    assert_eq!(compare_versions("1.8.0+build5", "1.8.0"), Equal);
    assert_eq!(compare_versions("1.8", "1.8.0"), Equal);
}
