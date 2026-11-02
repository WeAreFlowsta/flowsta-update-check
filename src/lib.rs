//! Check a signed release manifest before an app installs an update.
//!
//! A release manifest names one release of one app on one channel: the
//! version, the files with their size and SHA-256, and a signature by one of
//! the app's trusted signers. Everything here is local: the signers are
//! compiled into the app as `did:flowsta:` identities, and nothing is fetched
//! to check a signature, so an app updates with no server and no other app
//! running.
//!
//! The signed statement is
//! `flowsta-release-manifest:v1:<app>:<channel>:<sequence>:<sha256 hex>`, the
//! hash taken over the manifest's canonical JSON without its `signature`
//! member (object keys sorted, no whitespace, integers only).
//!
//! [`check`] applies the rules in order: the shape, the app, the channel, the
//! signer and signature, the sequence (no replay), the version (no
//! downgrade), the version to update from, and the rollout share. After the
//! download, [`check_file`] compares the file's size and SHA-256 with its
//! entry.

use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

/// The statement's prefix, naming the format and its version.
pub const STATEMENT_PREFIX: &str = "flowsta-release-manifest:v1";

/// Platforms, as the Tauri updater names them.
pub const PLATFORMS: [&str; 4] = ["darwin-aarch64", "darwin-x86_64", "windows-x86_64", "linux-x86_64"];

/// File kinds. An app installs only the kind it was installed as.
pub const KINDS: [&str; 6] = ["app-tarball", "nsis", "msi", "deb", "rpm", "dmg"];

/// What the app trusts, compiled in.
#[derive(Clone, Copy, Debug)]
pub struct Trust<'a> {
    /// This app's id, for example `com.example.app`.
    pub app: &'a str,
    /// The channel this install follows (`stable`, `beta`, ...).
    pub channel: &'a str,
    /// The identities allowed to sign, as `did:flowsta:uhCAk...`; any one
    /// signature is enough.
    pub signers: &'a [&'a str],
}

/// What this install is and has seen.
#[derive(Clone, Copy, Debug)]
pub struct Installed<'a> {
    pub version: &'a str,
    /// The highest sequence this install accepted for its app and channel,
    /// kept on disk by the app.
    pub last_sequence: Option<u64>,
    /// A number from 0 to 99 the app made once at random and keeps on the
    /// device (never sent): inside the rollout when it is below the share.
    pub rollout_ticket: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct File {
    pub platform: String,
    pub kind: String,
    pub name: String,
    pub url: String,
    pub size: u64,
    pub sha256: String,
}

/// A Holochain program the release carries, by its hash after signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kit {
    pub line: String,
    pub target: String,
    pub sidecar: String,
    pub sha256: String,
}

/// A release that passed [`check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub app: String,
    pub channel: String,
    pub sequence: u64,
    pub version: String,
    pub issued_at: String,
    pub notes_url: String,
    pub lines: Vec<String>,
    /// The release moves people's data to another Holochain line.
    pub changes_line: bool,
    pub rollout_percent: u8,
    pub from_version: Option<String>,
    pub files: Vec<File>,
    pub kit: Vec<Kit>,
    /// The identity whose signature verified.
    pub signer: String,
}

impl Release {
    /// The file for this platform and kind, if the release has one.
    pub fn file(&self, platform: &str, kind: &str) -> Option<&File> {
        self.files.iter().find(|f| f.platform == platform && f.kind == kind)
    }
}

/// Why a manifest or a file was refused. Nothing is installed after any of these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Not a manifest this version understands.
    Shape(String),
    /// A manifest for another app.
    OtherApp(String),
    /// A manifest for another channel (a beta never reaches a stable install).
    OtherChannel(String),
    /// Signed by an identity this app does not trust.
    Signer(String),
    /// The signature does not verify, or the statement does not match the body.
    Signature,
    /// Not newer than a manifest already accepted: a replay.
    Replayed { sequence: u64, last: u64 },
    /// Not newer than the installed version: the updater never downgrades.
    NotNewer { version: String, installed: String },
    /// This release updates only from `from_version` or later: install that one first.
    InstallFirst(String),
    /// This install is outside the rollout share for now.
    NotYet { percent: u8 },
    /// The downloaded file is not the one the manifest names.
    FileSize { expected: u64, got: u64 },
    FileHash,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Shape(why) => write!(f, "not a release manifest this app understands: {why}"),
            Refused::OtherApp(app) => write!(f, "a manifest for another app ({app})"),
            Refused::OtherChannel(channel) => write!(f, "a manifest for the {channel} channel"),
            Refused::Signer(signer) => write!(f, "signed by an identity this app does not trust ({signer})"),
            Refused::Signature => write!(f, "the signature does not verify"),
            Refused::Replayed { sequence, last } => write!(f, "sequence {sequence} is not newer than {last}"),
            Refused::NotNewer { version, installed } => write!(f, "{version} is not newer than the installed {installed}"),
            Refused::InstallFirst(from) => write!(f, "this release updates from {from} or later: install {from} first"),
            Refused::NotYet { percent } => write!(f, "outside the rollout ({percent} %) for now"),
            Refused::FileSize { expected, got } => write!(f, "the file is {got} bytes, the manifest says {expected}"),
            Refused::FileHash => write!(f, "the file's SHA-256 is not the one the manifest names"),
        }
    }
}

impl std::error::Error for Refused {}

/// Canonical JSON: object keys sorted, no whitespace. The same bytes as the
/// signing side's (the Vault's `/sign-release-manifest` and the node agent's
/// `canonical.mjs`).
pub fn canonical_json(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                canonical_json(&map[*k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
    }
}

/// The statement a manifest's signature covers. `manifest` may carry its
/// `signature` member; it is left out of the hash.
pub fn statement(manifest: &Value) -> Result<String, Refused> {
    let mut body = manifest.as_object().ok_or_else(|| Refused::Shape("not an object".into()))?.clone();
    body.remove("signature");
    let field = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let app = field("app").ok_or_else(|| Refused::Shape("app missing".into()))?;
    let channel = field("channel").ok_or_else(|| Refused::Shape("channel missing".into()))?;
    let sequence = body.get("sequence").and_then(|s| s.as_u64()).ok_or_else(|| Refused::Shape("sequence missing".into()))?;
    let mut canon = String::new();
    canonical_json(&Value::Object(body), &mut canon);
    Ok(format!("{STATEMENT_PREFIX}:{app}:{channel}:{sequence}:{}", hex::encode(Sha256::digest(canon.as_bytes()))))
}

/// Compare two versions: `major.minor.patch` numerically, a release above
/// its pre-releases, and pre-release labels in natural order (digit runs as
/// numbers, so `beta10` comes after `beta9`, which plain semver orders the
/// other way). A `+build` suffix is ignored.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    fn split(v: &str) -> (Vec<u64>, Option<&str>) {
        let v = v.split('+').next().unwrap_or(v);
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (v, None),
        };
        (core.split('.').map(|n| n.parse().unwrap_or(0)).collect(), pre)
    }
    fn natural(a: &str, b: &str) -> Ordering {
        fn runs(s: &str) -> Vec<(bool, &str)> {
            let mut out = Vec::new();
            let mut start = 0;
            let bytes = s.as_bytes();
            for i in 1..=bytes.len() {
                if i == bytes.len() || bytes[i].is_ascii_digit() != bytes[start].is_ascii_digit() {
                    out.push((bytes[start].is_ascii_digit(), &s[start..i]));
                    start = i;
                }
            }
            out
        }
        let (ra, rb) = (runs(a), runs(b));
        for (x, y) in ra.iter().zip(rb.iter()) {
            let o = match (x.0, y.0) {
                (true, true) => x.1.parse::<u64>().unwrap_or(0).cmp(&y.1.parse::<u64>().unwrap_or(0)),
                _ => x.1.cmp(y.1),
            };
            if o != Ordering::Equal {
                return o;
            }
        }
        ra.len().cmp(&rb.len())
    }
    let ((ca, pa), (cb, pb)) = (split(a), split(b));
    for i in 0..ca.len().max(cb.len()) {
        let o = ca.get(i).unwrap_or(&0).cmp(cb.get(i).unwrap_or(&0));
        if o != Ordering::Equal {
            return o;
        }
    }
    match (pa, pb) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => natural(x, y),
    }
}

/// The Ed25519 key inside a `did:flowsta:uhCAk...` identity (a Holochain
/// agent key: base64url of a 3-byte prefix, the 32-byte key and a 4-byte
/// location).
fn did_key(did: &str) -> Option<[u8; 32]> {
    let encoded = did.strip_prefix("did:flowsta:")?.strip_prefix('u')?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded).ok()?;
    if raw.len() != 39 || raw[..3] != [0x84, 0x20, 0x24] {
        return None;
    }
    raw[3..35].try_into().ok()
}

fn first_non_integer(v: &Value, path: &str) -> Option<String> {
    match v {
        Value::Number(n) if !(n.is_i64() || n.is_u64()) => Some(path.to_string()),
        Value::Object(map) => map.iter().find_map(|(k, x)| first_non_integer(x, &format!("{path}.{k}"))),
        Value::Array(items) => items.iter().enumerate().find_map(|(i, x)| first_non_integer(x, &format!("{path}[{i}]"))),
        _ => None,
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn is_version(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.starts_with(|c: char| c.is_ascii_digit()) && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

/// Read and check a manifest's shape (rule 1).
fn parse(manifest: &Value) -> Result<(Release, String, String), Refused> {
    let shape = |why: String| Refused::Shape(why);
    let obj = manifest.as_object().ok_or_else(|| shape("not an object".into()))?;
    let mut body = obj.clone();
    body.remove("signature");
    if body.get("v").and_then(|v| v.as_u64()) != Some(1) {
        return Err(shape("v must be 1".into()));
    }
    if let Some(path) = first_non_integer(&Value::Object(body.clone()), "manifest") {
        return Err(shape(format!("{path} is not a whole number")));
    }
    let text = |k: &str| body.get(k).and_then(|v| v.as_str());
    let app = text("app").filter(|a| a.len() <= 128 && a.contains('.') && !a.starts_with('.') && !a.ends_with('.') && a.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'));
    let app = app.ok_or_else(|| shape("app is not an app id".into()))?;
    let channel = text("channel").filter(|c| c.len() <= 32 && c.starts_with(|x: char| x.is_ascii_lowercase()) && c.chars().all(|x| x.is_ascii_lowercase() || x.is_ascii_digit() || x == '-'));
    let channel = channel.ok_or_else(|| shape("channel is not a channel name".into()))?;
    let sequence = body.get("sequence").and_then(|s| s.as_u64()).filter(|s| *s >= 1).ok_or_else(|| shape("sequence must be a positive integer".into()))?;
    let version = text("version").filter(|v| is_version(v)).ok_or_else(|| shape("version missing".into()))?;
    let from_version = match body.get("from_version") {
        None => None,
        Some(v) => Some(v.as_str().filter(|v| is_version(v)).ok_or_else(|| shape("from_version is not a version".into()))?.to_string()),
    };
    let holochain = body.get("holochain").and_then(|h| h.as_object()).ok_or_else(|| shape("holochain missing".into()))?;
    let lines: Vec<String> = holochain.get("lines").and_then(|l| l.as_array()).map(|l| l.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    if lines.is_empty() {
        return Err(shape("holochain.lines missing".into()));
    }
    let changes_line = match holochain.get("changes_line") {
        None => false,
        Some(v) => v.as_bool().ok_or_else(|| shape("holochain.changes_line must be true or false".into()))?,
    };
    let rollout_percent = match body.get("rollout") {
        None => 100,
        Some(r) => r.get("percent").and_then(|p| p.as_u64()).filter(|p| *p <= 100).ok_or_else(|| shape("rollout.percent must be 0 to 100".into()))? as u8,
    };
    let mut files = Vec::new();
    for (i, f) in body.get("files").and_then(|f| f.as_array()).filter(|f| !f.is_empty()).ok_or_else(|| shape("files missing".into()))?.iter().enumerate() {
        let field = |k: &str| f.get(k).and_then(|v| v.as_str());
        let bad = |what: &str| shape(format!("files[{i}].{what}"));
        files.push(File {
            platform: field("platform").filter(|p| PLATFORMS.contains(p)).ok_or_else(|| bad("platform"))?.to_string(),
            kind: field("kind").filter(|k| KINDS.contains(k)).ok_or_else(|| bad("kind"))?.to_string(),
            name: field("name").filter(|n| !n.is_empty() && !n.contains('/') && !n.contains('\\')).ok_or_else(|| bad("name"))?.to_string(),
            url: field("url").filter(|u| u.starts_with("https://")).ok_or_else(|| bad("url (https only)"))?.to_string(),
            size: f.get("size").and_then(|v| v.as_u64()).filter(|n| *n > 0).ok_or_else(|| bad("size"))?,
            sha256: field("sha256").filter(|h| is_sha256_hex(h)).ok_or_else(|| bad("sha256"))?.to_string(),
        });
    }
    let mut kit = Vec::new();
    for (i, k) in body.get("kit").and_then(|k| k.as_array()).map(|k| k.as_slice()).unwrap_or(&[]).iter().enumerate() {
        let field = |key: &str| k.get(key).and_then(|v| v.as_str()).filter(|v| !v.is_empty());
        let (Some(line), Some(target), Some(sidecar), Some(sha256)) = (field("line"), field("target"), field("sidecar"), field("sha256").filter(|h| is_sha256_hex(h))) else {
            return Err(shape(format!("kit[{i}]")));
        };
        kit.push(Kit { line: line.into(), target: target.into(), sidecar: sidecar.into(), sha256: sha256.into() });
    }
    let sig = obj.get("signature").and_then(|s| s.as_object()).ok_or_else(|| shape("signature missing".into()))?;
    let signer = sig.get("signer").and_then(|v| v.as_str()).ok_or_else(|| shape("signature.signer missing".into()))?.to_string();
    let sig_b64 = sig.get("sig").and_then(|v| v.as_str()).ok_or_else(|| shape("signature.sig missing".into()))?.to_string();
    let claimed = sig.get("statement").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let release = Release {
        app: app.into(),
        channel: channel.into(),
        sequence,
        version: version.into(),
        issued_at: text("issued_at").unwrap_or_default().into(),
        notes_url: text("notes_url").unwrap_or_default().into(),
        lines,
        changes_line,
        rollout_percent,
        from_version,
        files,
        kit,
        signer,
    };
    Ok((release, sig_b64, claimed))
}

/// Check a manifest (its JSON bytes) against what the app trusts and what
/// this install is. `Ok` means the release may be downloaded; the file
/// still goes through [`check_file`] before it is installed.
pub fn check(manifest: &[u8], trust: &Trust, installed: &Installed) -> Result<Release, Refused> {
    let value: Value = serde_json::from_slice(manifest).map_err(|e| Refused::Shape(format!("not JSON: {e}")))?;
    let (release, sig_b64, claimed) = parse(&value)?;
    if release.app != trust.app {
        return Err(Refused::OtherApp(release.app));
    }
    if release.channel != trust.channel {
        return Err(Refused::OtherChannel(release.channel));
    }
    if !trust.signers.contains(&release.signer.as_str()) {
        return Err(Refused::Signer(release.signer));
    }
    let key = did_key(&release.signer).ok_or(Refused::Signature)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| Refused::Signature)?;
    let sig = base64::engine::general_purpose::STANDARD.decode(sig_b64).map_err(|_| Refused::Signature)?;
    let sig = ed25519_dalek::Signature::from_slice(&sig).map_err(|_| Refused::Signature)?;
    let expected = statement(&value)?;
    if claimed != expected || key.verify_strict(expected.as_bytes(), &sig).is_err() {
        return Err(Refused::Signature);
    }
    if let Some(last) = installed.last_sequence {
        if release.sequence <= last {
            return Err(Refused::Replayed { sequence: release.sequence, last });
        }
    }
    if compare_versions(&release.version, installed.version) != Ordering::Greater {
        return Err(Refused::NotNewer { version: release.version, installed: installed.version.into() });
    }
    if let Some(from) = &release.from_version {
        if compare_versions(installed.version, from) == Ordering::Less {
            return Err(Refused::InstallFirst(from.clone()));
        }
    }
    if installed.rollout_ticket >= release.rollout_percent {
        return Err(Refused::NotYet { percent: release.rollout_percent });
    }
    Ok(release)
}

/// After the download: the file's size and SHA-256 against its entry.
pub fn check_file(file: &File, bytes: &[u8]) -> Result<(), Refused> {
    if bytes.len() as u64 != file.size {
        return Err(Refused::FileSize { expected: file.size, got: bytes.len() as u64 });
    }
    if hex::encode(Sha256::digest(bytes)) != file.sha256 {
        return Err(Refused::FileHash);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
