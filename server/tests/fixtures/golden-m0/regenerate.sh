#!/usr/bin/env bash
# regenerate.sh - rebuild the golden-m0 narinfo/NAR corpus from scratch.
#
# Usage:
#   regenerate.sh [verify]   Seed a throwaway bunkerd and diff the bytes
#                            it serves against expected/. (default)
#   regenerate.sh write      Seed a throwaway bunkerd and replace
#                            expected/ with the bytes it serves.
#
# Environment:
#   BUNKERD    bunkerd binary to test   (default: <repo>/target/debug/bunkerd)
#   BUNKERADM  bunkeradm binary         (default: <repo>/target/debug/bunkeradm)
#
# Everything is deterministic: the cache is created with a fixed,
# test-only keypair (below), the JWT signing key is the in-tree
# config-test key, the store paths are content-addressed by
# `nix-store --add`, and path B's payload is generated from a fixed
# PRNG seed. See README.md for the full provenance notes.
set -euo pipefail

MODE="${1:-verify}"
if [[ "$MODE" != "verify" && "$MODE" != "write" ]]; then
    echo "usage: $0 [verify|write]" >&2
    exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../../.." && pwd)"
BUNKERD="${BUNKERD:-$REPO_ROOT/target/debug/bunkerd}"
BUNKERADM="${BUNKERADM:-$REPO_ROOT/target/debug/bunkeradm}"
PORT=8931
BASE="http://127.0.0.1:$PORT"
CACHE="golden-m0"

# Test-only fixture keypair. The seed is SHA-256 of the string
# "bunker golden-m0 fixture keypair (test only)"; the name matches
# the cache name. Never use this key anywhere else.
FIXTURE_KEYPAIR="golden-m0:Z3g49mGX69DrLt5Ewh9SQU+/Sgaydbu763FYKnUcw4MX7VQsHVQDpwbx7Hi92OT32NRagHwYMDYKHVVyhhsU2Q=="

# The JWT signing key already published in server/src/config.rs
# tests (TEST_TOKEN_ED25519_SECRET_BASE64): base64 of a PKCS#8 PEM
# Ed25519 private key. Test-only.
TOKEN_SECRET="LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSUxpdlM2bDZvYzZTeWZYcnk1YUpsZmtYZEVnblZCQnVjOFg1K3VTWEFiMmUKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo="

for bin in "$BUNKERD" "$BUNKERADM"; do
    if [[ ! -x "$bin" ]]; then
        echo "missing binary: $bin (build with: cargo build -p bunker-server)" >&2
        exit 1
    fi
done

RUNTIME="$(mktemp -d)"
SERVER_PID=""
cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$RUNTIME"
}
trap cleanup EXIT

# --- Fixture content ---------------------------------------------------
mkdir -p "$RUNTIME/content"
cp -r "$HERE/seed/content-a" "$RUNTIME/content/golden-a"
python3 - "$RUNTIME/content/golden-b" <<'PY'
import pathlib, random, sys
root = pathlib.Path(sys.argv[1])
root.mkdir(parents=True)
# 600_000 deterministic pseudo-random bytes: incompressible, so the
# compressed stream stays well above the 256 KiB maximum chunk size
# and FastCDC must cut the NAR into multiple chunks.
(root / "data.bin").write_bytes(random.Random(20261013).randbytes(600_000))
(root / "note.txt").write_text(
    "Golden M0 fixture path B: payload sized to force multi-chunk storage.\n"
)
PY

# --- Store paths and NARs ----------------------------------------------
PATH_A="$(nix-store --add "$RUNTIME/content/golden-a")"
PATH_B="$(nix-store --add "$RUNTIME/content/golden-b")"
BASE_A="$(basename "$PATH_A")"
BASE_B="$(basename "$PATH_B")"
HASH_A="${BASE_A%%-*}"
HASH_B="${BASE_B%%-*}"
nix-store --dump "$PATH_A" > "$RUNTIME/a.nar"
nix-store --dump "$PATH_B" > "$RUNTIME/b.nar"

nar_hash() { echo "sha256:$(nix hash file --type sha256 --base32 "$1")"; }
NAR_HASH_A="$(nar_hash "$RUNTIME/a.nar")"
NAR_HASH_B="$(nar_hash "$RUNTIME/b.nar")"
NAR_SIZE_A="$(stat -c%s "$RUNTIME/a.nar")"
NAR_SIZE_B="$(stat -c%s "$RUNTIME/b.nar")"

# --- Server -------------------------------------------------------------
sed -e "s|@RUNTIME@|$RUNTIME|g" -e "s|@TOKEN_SECRET@|$TOKEN_SECRET|g" \
    "$HERE/config.toml.template" > "$RUNTIME/config.toml"

"$BUNKERD" -f "$RUNTIME/config.toml" > "$RUNTIME/server.log" 2>&1 &
SERVER_PID=$!

ready=0
for _ in $(seq 1 60); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "bunkerd exited during startup:" >&2
        cat "$RUNTIME/server.log" >&2
        exit 1
    fi
    if curl -s -o /dev/null "$BASE/"; then
        ready=1
        break
    fi
    sleep 1
done
if [[ "$ready" != "1" ]]; then
    echo "bunkerd did not start listening on $BASE within 60s:" >&2
    cat "$RUNTIME/server.log" >&2
    exit 1
fi

# --- Token and cache -----------------------------------------------------
TOKEN="$("$BUNKERADM" -f "$RUNTIME/config.toml" make-token \
    --sub golden-m0 --validity 1h \
    --pull "$CACHE" --push "$CACHE" \
    --create-cache "$CACHE" --configure-cache "$CACHE" | tr -d '[:space:]')"

curl -sf -X POST "$BASE/_api/v1/cache-config/$CACHE" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"keypair\":{\"Keypair\":\"$FIXTURE_KEYPAIR\"},\"is_public\":true,\"store_dir\":\"/nix/store\",\"priority\":40,\"upstream_cache_key_names\":[]}" \
    > /dev/null

# --- Uploads --------------------------------------------------------------
upload() {
    # $1 = nar file, $2 = store path, $3 = store path hash,
    # $4 = references (JSON array), $5 = deriver (JSON string or null)
    python3 - "$RUNTIME/preamble.json" "$1" "$2" "$3" "$4" "$5" <<'PY'
import json, pathlib, subprocess, sys
out, nar_file, store_path, store_path_hash, references, deriver = sys.argv[1:7]
nar_hash = "sha256:" + subprocess.run(
    ["nix", "hash", "file", "--type", "sha256", "--base32", nar_file],
    capture_output=True, text=True, check=True).stdout.strip()
info = {
    "cache": "golden-m0",
    "store_path_hash": store_path_hash,
    "store_path": store_path,
    "references": json.loads(references),
    "system": "x86_64-linux",
    "deriver": json.loads(deriver),
    "sigs": [],
    "ca": None,
    "nar_hash": nar_hash,
    "nar_size": pathlib.Path(nar_file).stat().st_size,
}
pathlib.Path(out).write_text(json.dumps(info))
PY
    local preamble_size
    preamble_size="$(stat -c%s "$RUNTIME/preamble.json")"
    cat "$RUNTIME/preamble.json" "$1" > "$RUNTIME/body.bin"
    curl -sf -X PUT "$BASE/_api/v1/upload-path" \
        -H "Authorization: Bearer $TOKEN" \
        -H "X-Bunker-Nar-Info-Preamble-Size: $preamble_size" \
        --data-binary @"$RUNTIME/body.bin" > /dev/null
}

upload "$RUNTIME/a.nar" "$PATH_A" "$HASH_A" '[]' 'null'
upload "$RUNTIME/b.nar" "$PATH_B" "$HASH_B" "[\"$BASE_A\"]" '"golden-b.drv"'

# --- Captures ---------------------------------------------------------------
OUT="$RUNTIME/capture"
mkdir -p "$OUT"
curl -sf "$BASE/$CACHE/nix-cache-info" -o "$OUT/nix-cache-info.txt"
curl -sf "$BASE/$CACHE/$HASH_A.narinfo" -o "$OUT/$HASH_A.narinfo"
curl -sf "$BASE/$CACHE/nar/$HASH_A.nar" -o "$OUT/$HASH_A.nar"
curl -sf "$BASE/$CACHE/$HASH_B.narinfo" -o "$OUT/$HASH_B.narinfo"
curl -sf "$BASE/$CACHE/nar/$HASH_B.nar" -o "$OUT/$HASH_B.nar"
python3 - "$RUNTIME/bunker.db" "$OUT/chunk-counts.txt" <<'PY'
import sqlite3, sys
db, out = sys.argv[1:3]
rows = sqlite3.connect(db).execute(
    "SELECT o.store_path, n.num_chunks FROM object o "
    "JOIN nar n ON n.id = o.nar_id ORDER BY o.store_path"
).fetchall()
with open(out, "w") as f:
    for store_path, num_chunks in rows:
        f.write(f"{store_path}: num_chunks={num_chunks}\n")
PY
(cd "$OUT" && sha256sum nix-cache-info.txt "$HASH_A.narinfo" "$HASH_A.nar" \
    "$HASH_B.narinfo" "$HASH_B.nar" chunk-counts.txt > SHA256SUMS)

if [[ "$MODE" == "write" ]]; then
    rm -rf "$HERE/expected"
    cp -r "$OUT" "$HERE/expected"
    echo "corpus written to $HERE/expected"
else
    if diff -r "$HERE/expected" "$OUT"; then
        echo "golden-m0 corpus: byte-identical"
    else
        echo "golden-m0 corpus: DIFFERS from expected/ (see diff above)" >&2
        exit 1
    fi
fi
