# flowsta-update-check

Check a signed release manifest before an app installs an update.

A release manifest names one release of one app on one channel: its version, every file with its size and SHA-256, and a signature by one of the app's trusted signers. The app compiles in its signers. Checking a manifest is local math, so an app can update with no server and no other app running, and a manifest signed by anyone else, for another app, for another channel, or for an older release is refused.

Flowsta's apps use it beside Tauri's updater: the updater's own signature proves the file came from the release build, and the manifest proves a person the app trusts approved this release for this channel. Other developers can use the same format with their own app id and signers.

## The manifest

```json
{
  "v": 1,
  "app": "com.example.app",
  "channel": "stable",
  "sequence": 12,
  "issued_at": "2026-11-20T03:00:00Z",
  "version": "1.2.0",
  "notes_url": "https://example.com/releases/1.2.0",
  "holochain": { "lines": ["holochain-0.7"], "changes_line": false },
  "rollout": { "percent": 100 },
  "from_version": "1.1.0",
  "files": [
    { "platform": "windows-x86_64", "kind": "nsis", "name": "App_1.2.0_x64-setup.exe", "url": "https://...", "size": 123, "sha256": "<64 hex>" }
  ],
  "kit": [
    { "line": "holochain-0.7", "target": "x86_64-pc-windows-msvc", "sidecar": "app-holochain", "sha256": "<64 hex>" }
  ],
  "signature": { "signer": "did:flowsta:uhCAk...", "sig": "<base64>", "statement": "flowsta-release-manifest:v1:com.example.app:stable:12:<sha256 hex>" }
}
```

- **The signature** is Ed25519 over the UTF-8 statement `flowsta-release-manifest:v1:<app>:<channel>:<sequence>:<sha256>`, where the hash is of the manifest's canonical JSON without `signature`: object keys sorted, no whitespace.
- **Integers only.** Floats print differently across languages and would change the hash, so a manifest with one is refused.
- **`platform`** uses the Tauri updater's names: `darwin-aarch64`, `darwin-x86_64`, `windows-x86_64`, `linux-x86_64`.
- **`kind`** is one of `app-tarball`, `nsis`, `msi`, `deb`, `rpm` or `dmg`. An app installs only the kind it was installed as.
- **`kit`** (optional) lists programs the release carries, by their hash after code signing.
- **The signer** is a `did:flowsta:` identity: a Holochain agent key, whose 32-byte Ed25519 key is checked here.

## What `check` accepts, in order

1. The shape is valid and `v` is 1.
2. `app` is this app.
3. `channel` is the channel this install follows. A beta manifest never reaches a stable install, even when the same key signed it.
4. The signer is in the app's list, the statement matches the body, and the signature verifies.
5. `sequence` is greater than the last one this install accepted (the app keeps it on disk): no replay of an older manifest.
6. `version` is greater than the installed version: no downgrade. Pre-release labels compare naturally, so `beta10` comes after `beta9`.
7. If `from_version` is set, the installed version is at least that; otherwise the app should install that release first.
8. This install is inside `rollout.percent`, by a number from 0 to 99 it made once and keeps on the device. It is never sent anywhere.

After the download, `check_file` compares the file's size and SHA-256 with its entry.

## Use

```rust
use flowsta_update_check::{check, check_file, Installed, Trust};

const SIGNERS: &[&str] = &["did:flowsta:uhCAk..."];

let release = check(
    &manifest_bytes,
    &Trust { app: "com.example.app", channel: "stable", signers: SIGNERS },
    &Installed { version: env!("CARGO_PKG_VERSION"), last_sequence, rollout_ticket },
)?;
if let Some(file) = release.file("windows-x86_64", "nsis") {
    // download it (Tauri's updater checks its own signature), then:
    check_file(file, &bytes)?;
    // install
}
```

Every refusal is a `Refused` value with a plain-language `Display`. Nothing should be installed after one, and the app keeps running.

## License

MIT
