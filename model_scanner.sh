#!/usr/bin/env bash
set -euo pipefail

print_help() {
  cat <<'EOF'
model_scanner.sh — quarantine, verify, and scan a Hugging Face model before
approving it for use.

Usage:
  ./model_scanner.sh [OPTIONS] <hf_repo_id> [expected_sha256]

Arguments:
  <hf_repo_id>       Required. e.g. sshleifer/tiny-gpt2, microsoft/phi-2
  [expected_sha256]  Optional. Reject if no downloaded file matches this hash.

Options:
  -y, --yes    Skip the manual download-size confirmation prompt (for CI).
               Default is manual confirmation — recommended while this is MVP.
  -h, --help   Show this help message and exit.

Examples:
  ./model_scanner.sh sshleifer/tiny-gpt2
  ./model_scanner.sh microsoft/phi-2 3b1e6c2a...
  ./model_scanner.sh --yes sshleifer/tiny-gpt2

Pipeline stages:
  1. Quarantine   — isolated staging dir + throwaway venv, wiped on exit
  2. Source check — publisher/repo legitimacy signals from the HF API
  3. Integrity    — SHA-256 checksum verification (if provided)
  4. Security scan— ModelScan + Fickling static analysis
  5. Verdict      — APPROVE or REJECT with matching exit code

Run this only on a disposable VM/container with no outbound network access
beyond huggingface.co, and no credentials to anything else on the box.
EOF
}

AUTO_APPROVE=0
POSITIONAL=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      print_help
      exit 0
      ;;
    -y|--yes)
      AUTO_APPROVE=1
      shift
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "Unknown option: $1"
      echo
      print_help
      exit 1
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

REPO_ID="${POSITIONAL[0]:-}"
EXPECTED_SHA256="${POSITIONAL[1]:-}"

if [[ -z "$REPO_ID" ]]; then
  print_help
  exit 1
fi

# --- Stage 1: Quarantine setup ---
# Isolated, disposable dirs for the downloaded model and the Python env.
# Both are wiped on exit (success, failure, or Ctrl-C) via the trap below —
# nothing from an untrusted model persists on this VM between runs.
STAGING_DIR="$(mktemp -d -t model-quarantine-XXXXXX)"
VENV_DIR="$(mktemp -d -t model-scan-venv-XXXXXX)"
echo "== Staging in: $STAGING_DIR =="
echo "== Venv in: $VENV_DIR =="

cleanup() {
  echo "== Cleaning up staging dir and venv =="
  deactivate 2>/dev/null || true
  rm -rf "$STAGING_DIR" "$VENV_DIR"
}
trap cleanup EXIT

# --- Stage 1b: Isolated Python environment ---
# Scan tooling gets its own throwaway venv per run, so this VM can be reused
# across scans without deps leaking or conflicting between runs.
# modelscan doesn't yet support the newest Python releases, so prefer a
# known-compatible interpreter (3.10-3.12) if one is installed, falling
# back to whatever python3 resolves to otherwise.
PYTHON_BIN=""
for candidate in python3.12 python3.11 python3.10 python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    PYTHON_BIN="$candidate"
    break
  fi
done

PY_VERSION="$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
echo "== Using $PYTHON_BIN (Python $PY_VERSION) =="
case "$PY_VERSION" in
  3.10|3.11|3.12) ;;
  *)
    echo "WARNING: Python $PY_VERSION may be too new for modelscan."
    echo "If the pip install below fails, run: brew install python@3.11"
    ;;
esac

echo "== Creating isolated venv =="
"$PYTHON_BIN" -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

echo "== Installing scan tools (modelscan, fickling, huggingface_hub) =="
pip install --quiet --upgrade pip "modelscan[h5py]" fickling huggingface_hub

# --- Stage 2: Source verification ---
# Pull publisher/repo metadata from the HF API before spending bandwidth/disk
# on the actual weights. This automates what the API reliably exposes
# (downloads, likes, age, license, gated/private status) and flags anything
# thin for manual review — it does NOT hard-fail, since "is this a legitimate
# publisher" needs a human to also check the verified-org badge and community
# history on the model page itself (link printed below).
echo "== Checking source legitimacy for $REPO_ID =="
python3 - "$REPO_ID" <<'PYEOF'
import sys
from datetime import datetime, timezone
from huggingface_hub import HfApi

repo_id = sys.argv[1]
api = HfApi()

try:
    info = api.model_info(repo_id)
except Exception as e:
    print(f"FAIL: could not fetch model info for {repo_id}: {e}")
    sys.exit(1)

age_days = None
if info.created_at:
    age_days = (datetime.now(timezone.utc) - info.created_at).days

license_ = (info.card_data or {}).get("license") if info.card_data else None

print(f"Author:        {info.author}")
print(f"Downloads:      {info.downloads}")
print(f"Likes:          {info.likes}")
print(f"Created:        {info.created_at} ({age_days} days ago)" if age_days is not None else "Created:        unknown")
print(f"Last modified:  {info.last_modified}")
print(f"Gated:          {info.gated}")
print(f"Private:        {info.private}")
print(f"License:        {license_ or 'not specified'}")
print(f"Model page:     https://huggingface.co/{repo_id}  <- manually check for verified-org badge")

warnings = []
if (info.downloads or 0) < 100:
    warnings.append(f"low download count ({info.downloads})")
if age_days is not None and age_days < 7:
    warnings.append(f"repo created only {age_days} day(s) ago")
if not license_:
    warnings.append("no license specified in model card")
if info.gated:
    warnings.append("repo is gated — confirm you trust the publisher before requesting access")

if warnings:
    print("WARNING: review before proceeding — " + "; ".join(warnings))
else:
    print("Source signals OK — no automated red flags (verified-org badge still needs a manual check)")
PYEOF

# --- Stage 1c-i: Human-in-the-loop size confirmation ---
# Total download size isn't exposed by model_info() without fetching
# per-file metadata, so compute it explicitly and make the human confirm
# before any bytes move — cheap insurance against a surprise multi-hundred-
# GB pull (see DeepSeek-R1 earlier).
echo "== Checking total download size for $REPO_ID =="
TOTAL_BYTES="$(python3 - "$REPO_ID" <<'PYEOF'
import sys
from huggingface_hub import HfApi

repo_id = sys.argv[1]
api = HfApi()
info = api.model_info(repo_id, files_metadata=True)
total = sum((s.size or 0) for s in info.siblings)
print(total)
PYEOF
)"

TOTAL_HUMAN="$(python3 -c "
size = $TOTAL_BYTES
for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
    if size < 1024:
        print(f'{size:.1f} {unit}')
        break
    size /= 1024
else:
    print(f'{size:.1f} PB')
")"

echo "Total download size for $REPO_ID: $TOTAL_HUMAN"
if [[ "$AUTO_APPROVE" -eq 1 ]]; then
  echo "Auto-approved via --yes: proceeding with $TOTAL_HUMAN download."
else
  read -r -p "Proceed with downloading $TOTAL_HUMAN into quarantine? [y/N] " CONFIRM
  if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Aborted by user before download."
    exit 3
  fi
fi

# --- Stage 1c: Download into quarantine ---
# Pulls the raw files only via the huggingface_hub Python API directly
# (version-proof vs. the CLI entrypoint, which was renamed huggingface-cli
# -> hf in huggingface_hub 2.x). Never deserializes/loads anything, so
# nothing executes yet even if the model is malicious.
echo "== Downloading $REPO_ID into quarantine (no load, no execution) =="
python3 - "$REPO_ID" "$STAGING_DIR" <<'PYEOF'
import sys
from huggingface_hub import snapshot_download

repo_id, local_dir = sys.argv[1], sys.argv[2]
snapshot_download(repo_id=repo_id, local_dir=local_dir)
PYEOF

# --- Stage 3: Integrity check ---
# Hash every downloaded file; if the caller passed an expected checksum,
# treat a mismatch as an automatic reject before any scanning is attempted.
echo "== Computing SHA-256 checksums =="
CHECKSUM_FILE="$STAGING_DIR.checksums.txt"
find "$STAGING_DIR" -type f -not -path "*/.cache/huggingface/*" -exec sha256sum {} \; | tee "$CHECKSUM_FILE"

if [[ -n "$EXPECTED_SHA256" ]]; then
  if grep -q "$EXPECTED_SHA256" "$CHECKSUM_FILE"; then
    echo "== Checksum match found: OK =="
  else
    echo "== FAIL: expected checksum $EXPECTED_SHA256 not found among downloaded files =="
    exit 2
  fi
fi

# --- Stage 4a: Security scan — ModelScan ---
# Static analysis across all formats in the directory (pickle, PyTorch,
# Keras H5, TF SavedModel, HF) for load-time code-execution risks.
# Deliberately avoids fragile CLI flags (e.g. --output-format), which have
# changed across modelscan versions — plain invocation + captured output is
# more version-resilient, and the raw output is always shown so a future
# CLI change is visible garbled text, not a silent false FAIL.
echo "== Running ModelScan =="
MODELSCAN_REPORT="$STAGING_DIR.modelscan.txt"
if modelscan -p "$STAGING_DIR" >"$MODELSCAN_REPORT" 2>&1; then
  MODELSCAN_STATUS="PASS"
else
  MODELSCAN_STATUS="FAIL"
fi
cat "$MODELSCAN_REPORT"
echo "ModelScan result: $MODELSCAN_STATUS (full output: $MODELSCAN_REPORT)"

# --- Stage 4b: Security scan — Fickling ---
# Deeper opcode-level check specifically on pickle-based files, without
# unpickling/executing them. Same version-resilience approach as ModelScan
# above: no flags beyond the file path, output always shown, and failure
# is exit code OR a keyword hit in the output (fickling's text verdict is
# the more stable signal across versions than exit code alone).
echo "== Running Fickling on any pickle-based files (.bin, .pt, .pth) =="
FICKLING_FAIL=0
while IFS= read -r -d '' f; do
  echo "-- fickling check: $f --"
  if FICKLING_OUTPUT="$(fickling "$f" 2>&1)"; then
    FICKLING_EXIT=0
  else
    FICKLING_EXIT=$?
  fi
  echo "$FICKLING_OUTPUT"
  if [[ "$FICKLING_EXIT" -ne 0 ]] || grep -qiE "unsafe|dangerous|overtly malicious" <<< "$FICKLING_OUTPUT"; then
    FICKLING_FAIL=1
  fi
done < <(find "$STAGING_DIR" -type f \( -name "*.bin" -o -name "*.pt" -o -name "*.pth" \) -print0)

# --- Stage 4c: Security scan — ClamAV ---
# Generic signature-based malware scan across every file in the staging
# dir, not just model formats — catches a known-malware binary or dropper
# hidden anywhere in the repo, which ModelScan/Fickling (pickle-opcode-aware
# only) wouldn't look for. Complementary, not redundant, coverage.
#
# ClamAV is a system package, not pip-installable, so it may not be present
# everywhere this script runs. Missing ClamAV warns and skips this stage
# rather than hard-failing the whole pipeline.
#
# freshclam needs the same network access this run already requires for the
# HF download — the isolation guarantee here is ephemeral, credential-free
# compute with everything wiped on exit, not a total absence of egress.
CLAMAV_STATUS="SKIPPED"
if command -v clamscan >/dev/null 2>&1; then
  echo "== Updating ClamAV virus definitions =="
  if command -v freshclam >/dev/null 2>&1; then
    freshclam --quiet || echo "WARNING: freshclam update failed — scanning with existing definitions."
  fi

  echo "== Running ClamAV across quarantine directory =="
  CLAMAV_REPORT="$STAGING_DIR.clamav.txt"
  set +e
  clamscan -r "$STAGING_DIR" >"$CLAMAV_REPORT" 2>&1
  CLAMAV_EXIT=$?
  set -e
  cat "$CLAMAV_REPORT"
  case "$CLAMAV_EXIT" in
    0) CLAMAV_STATUS="PASS" ;;
    1) CLAMAV_STATUS="FAIL" ;;
    *) CLAMAV_STATUS="FAIL"; echo "WARNING: clamscan exited $CLAMAV_EXIT (scan error, treating as FAIL)" ;;
  esac
  echo "ClamAV result: $CLAMAV_STATUS (full output: $CLAMAV_REPORT)"
else
  echo "== ClamAV not installed — skipping this stage =="
  echo "Install it for generic malware coverage: brew install clamav (macOS) / apt install clamav (Linux)"
fi

# --- Stage 5: Approve or reject ---
# Summarize all scan results and give a single pass/fail verdict with a
# matching exit code, so this can be wired into CI later.
echo
echo "===================================="
echo "Model:       $REPO_ID"
echo "ModelScan:   $MODELSCAN_STATUS"
if [[ "$FICKLING_FAIL" -eq 0 ]]; then
  echo "Fickling:    PASS"
else
  echo "Fickling:    FAIL"
fi
echo "ClamAV:      $CLAMAV_STATUS"
echo "===================================="

if [[ "$MODELSCAN_STATUS" == "FAIL" || "$FICKLING_FAIL" -ne 0 || "$CLAMAV_STATUS" == "FAIL" ]]; then
  echo "RESULT: REJECT — do not promote this model."
  exit 1
else
  echo "RESULT: APPROVE — safe to promote to the approved-models store."
  exit 0
fi
