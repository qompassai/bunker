//! `qompass-approve` — the human signer for Signed Authority
//! Approvals (DESIGN section 3, pilot Stage B).
//!
//! Parses the canonical manifest itself, renders every field,
//! and signs only when the human types `sign`. The key lives in
//! a local 0600 file named by `QOMPASS_APPROVE_KEY`; nothing here
//! talks to a network or a web page (F-18).

use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use signed_approval::canonical::JsonValue;
use signed_approval::manifest::{Manifest, hex_decode, hex_encode};
use signed_approval::record::AuthorityRecord;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Days since epoch → (year, month, day), Howard Hinnant's
/// civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn today_stamp() -> String {
    let days = now_unix().div_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}{m:02}{d:02}")
}

fn fingerprint_of(key: &SigningKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.verifying_key().to_bytes());
    hex_encode(&hasher.finalize())
}

fn load_key(path: &str) -> Result<SigningKey, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| format!("key file: {e}"))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(format!(
                "key file permissions are {mode:o}, must be 600 — refusing"
            ));
        }
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("key file: {e}"))?;
    let seed = hex_decode(text.trim()).ok_or("key file is not hex")?;
    let seed_bytes: [u8; 32] = seed
        .try_into()
        .map_err(|_| "key file must hold a 32-byte seed".to_string())?;
    Ok(SigningKey::from_bytes(&seed_bytes))
}

/// The per-day ask counter (fatigue visibility, DESIGN section
/// 3): incremented at every presentation, shown before signing.
fn next_ask_number(key_path: &str) -> u32 {
    let counter_path = format!("{key_path}.asks-{}", today_stamp());
    let current: u32 = std::fs::read_to_string(&counter_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let next = current + 1;
    let _ = std::fs::write(&counter_path, format!("{next}\n"));
    next
}

fn render_payload(value: &JsonValue, indent: usize, out: &mut String) {
    let pad = " ".repeat(indent);
    match value {
        JsonValue::Object(entries) => {
            let mut sorted: Vec<&(String, JsonValue)> = entries.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            for (key, val) in sorted {
                match val {
                    JsonValue::Object(_) | JsonValue::Array(_) => {
                        out.push_str(&format!("{pad}{key}:\n"));
                        render_payload(val, indent + 2, out);
                    }
                    _ => {
                        out.push_str(&format!("{pad}{key}: {}\n", render_scalar(val)));
                    }
                }
            }
        }
        JsonValue::Array(items) => {
            for item in items {
                out.push_str(&format!("{pad}- {}\n", render_scalar(item)));
            }
        }
        _ => out.push_str(&format!("{pad}{}\n", render_scalar(value))),
    }
}

fn render_scalar(value: &JsonValue) -> String {
    match value {
        JsonValue::String(s) => s.clone(),
        JsonValue::Number(n) => n.clone(),
        JsonValue::Bool(b) => b.to_string(),
        JsonValue::Null => "null".to_string(),
        other => signed_approval::canonical::serialize(other),
    }
}

fn render(manifest: &Manifest, ask: u32) {
    let now = now_unix();
    let remaining = manifest.expires_at - now;
    println!("=== APPROVAL REQUEST (ask #{ask} today) ===");
    println!("tool:        {}", manifest.tool);
    println!("audience:    {}", manifest.audience);
    println!("trajectory:  {}", manifest.trajectory);
    println!("effects:     {}", manifest.effects.join(", "));
    println!(
        "labels:      data={} destination={}",
        manifest.labels.data, manifest.labels.destination
    );
    println!("expires in:  {remaining}s");
    println!(
        "digest:      {} (check: {})",
        manifest.digest(),
        manifest.digest_check()
    );
    println!("payload:");
    let mut body = String::new();
    render_payload(&manifest.payload, 2, &mut body);
    print!("{body}");
    println!("================================================");
}

fn generate_test_key(key_path: &str, record_path: &str) -> Result<(), String> {
    if std::path::Path::new(key_path).exists() {
        return Err(format!(
            "refusing to overwrite existing key file {key_path}"
        ));
    }
    let key = SigningKey::generate(&mut OsRng);
    let seed_hex = hex_encode(&key.to_bytes());
    std::fs::write(key_path, format!("{seed_hex}\n")).map_err(|e| format!("write key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod key: {e}"))?;
    }
    let record = AuthorityRecord {
        fetched_at: now_unix(),
        fingerprint: fingerprint_of(&key),
        public_key: BASE64.encode(key.verifying_key().to_bytes()),
        revoked: false,
    };
    let record_json = signed_approval::canonical::serialize(&record.to_value());
    std::fs::write(record_path, format!("{record_json}\n"))
        .map_err(|e| format!("write record: {e}"))?;
    println!("test key written: {key_path}");
    println!("authority record: {record_path}");
    println!("fingerprint: {}", record.fingerprint);
    Ok(())
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 3 && args[0] == "--generate-test-key" {
        generate_test_key(&args[1], &args[2])?;
        return Ok(0);
    }
    let manifest_path = args
        .first()
        .ok_or("usage: qompass-approve <manifest-file|-> [--out <token-file>] | --generate-test-key <key> <record>")?;
    let out_path = if args.len() == 3 && args[1] == "--out" {
        Some(args[2].clone())
    } else if args.len() == 1 {
        None
    } else {
        return Err("usage: qompass-approve <manifest-file|-> [--out <token-file>]".to_string());
    };
    let key_path = std::env::var("QOMPASS_APPROVE_KEY")
        .map_err(|_| "QOMPASS_APPROVE_KEY is not set".to_string())?;
    let key = load_key(&key_path)?;

    let mut bytes = Vec::new();
    if manifest_path == "-" {
        std::io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|e| format!("read stdin: {e}"))?;
    } else {
        bytes = std::fs::read(manifest_path).map_err(|e| format!("read manifest: {e}"))?;
    }
    let manifest =
        Manifest::from_canonical_bytes(&bytes).map_err(|e| format!("manifest refused: {e}"))?;
    if manifest.expires_at <= now_unix() {
        return Err("manifest refused: already expired".to_string());
    }
    let ask = next_ask_number(&key_path);
    render(&manifest, ask);
    print!("Type \"sign\" to approve: ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("read answer: {e}"))?;
    if line.trim() != "sign" {
        eprintln!("not signed");
        return Ok(1);
    }
    let token = signed_approval::ApprovalToken::sign(manifest, &key, &fingerprint_of(&key));
    let json = token.to_json();
    match out_path {
        Some(path) => {
            std::fs::write(&path, &json).map_err(|e| format!("write token: {e}"))?;
            println!("token written: {path}");
        }
        None => {
            println!("{}", String::from_utf8_lossy(&json));
        }
    }
    Ok(0)
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(message) => {
            eprintln!("qompass-approve: {message}");
            std::process::exit(2);
        }
    }
}
