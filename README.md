# AIMS
AI Integrity &amp; Model Scanning 

# model_scanner.sh

Quarantine, verify, and scan a Hugging Face model before approving it for use.
Built to compensate for the gap where native model-aware scanning (JFrog Xray)
isn't available on the artifact path you're using.

## Table of Contents

- [What it does](#what-it-does)
- [Usage](#usage)
  - [Examples](#examples)
- [Prerequisites](#prerequisites)
- [Where to run this](#where-to-run-this)
- [What this does NOT cover](#what-this-does-not-cover)
- [To-do](#to-do)

## What it does

1. **Quarantine** — downloads into an isolated staging dir with its own
   throwaway Python venv, both wiped on exit (success, failure, or Ctrl-C).
2. **Source verification** — pulls publisher/repo metadata from the Hugging
   Face API (author, downloads, likes, repo age, license, gated/private
   status) and warns on thin signals. Does not hard-fail — verifying the
   publisher's legitimacy (e.g. the verified-org badge) still needs a human
   look at the model page, which the script links directly.
3. **Size confirmation (human-in-the-loop)** — computes the total download
   size from file metadata and asks for explicit `[y/N]` confirmation before
   pulling any bytes. Prevents an accidental multi-hundred-GB download.
4. **Integrity check** — SHA-256 checksums every downloaded model file; if
   you passed an expected hash, a mismatch is an automatic reject.
   `huggingface_hub`'s own bookkeeping files (`.cache/huggingface/...` — lock
   files and metadata, not model content) are excluded from checksumming to
   keep the report to actual artifact files only.
5. **Security scan — ModelScan + Fickling** — runs
   [ModelScan](https://github.com/protectai/modelscan) across all files and
   [Fickling](https://github.com/trailofbits/fickling) specifically on
   pickle-based files (`.bin`, `.pt`, `.pth`), without ever
   unpickling/executing them. If a repo ships the same model in multiple
   framework formats (PyTorch, TF, Flax, etc.), all of them get scanned —
   deliberate, since a malicious repo could hide a payload in whichever
   format is least likely to be the one you deploy.
6. **Security scan — ClamAV** — runs `clamscan` across the entire staging
   directory (not just model files). Generic, signature-based malware
   detection that isn't pickle/format-aware, so it catches a different
   threat than stage 5: a known-malware binary or dropper hidden anywhere
   in the repo, not just in the model weight files. `freshclam` updates
   definitions first, using the same network access this run already needs
   for the HF download. Skips with a warning (doesn't hard-fail the
   pipeline) if ClamAV isn't installed.
7. **Verdict** — prints APPROVE or REJECT and exits with a matching code
   (`0` = approve, `1` = reject, `2` = checksum mismatch, `3` = aborted by
   user at the size prompt).

## Usage

```bash
./model_scanner.sh [OPTIONS] <hf_repo_id> [expected_sha256]
```

| Argument | Required | Description |
|---|---|---|
| `<hf_repo_id>` | Yes | e.g. `sshleifer/tiny-gpt2`, `microsoft/phi-2` |
| `[expected_sha256]` | No | Reject if no downloaded file matches this hash |

| Option | Description |
|---|---|
| `-y`, `--yes` | Skip the manual size-confirmation prompt (for CI). Default is manual — recommended while this is MVP. |
| `-h`, `--help` | Show usage and exit |

### Examples

```bash
./model_scanner.sh sshleifer/tiny-gpt2
./model_scanner.sh microsoft/phi-2 3b1e6c2a...
./model_scanner.sh --yes sshleifer/tiny-gpt2
```

## Prerequisites

- Bash, `find`, `grep`, `mktemp` (standard on macOS/Linux).
- Python 3.10, 3.11, or 3.12 available on `PATH` (as `python3.10`/`.11`/`.12`,
  or as the default `python3`). **ModelScan does not yet support Python
  3.13+** — the script auto-selects a compatible interpreter if one exists,
  and warns if it has to fall back to an incompatible `python3`.
  - macOS: `brew install python@3.11`
- Network access to `huggingface.co`.
- `sha256sum` — on macOS this is BSD-based and lacks `sha256sum` by default;
  install GNU coreutils (`brew install coreutils`) if the checksum step fails
  with "command not found."
- A Hugging Face token (`huggingface-cli login` or `HF_TOKEN` env var) only
  if scanning a gated/private repo.
- **ClamAV** (optional, but recommended) — `brew install clamav` on macOS,
  `apt install clamav` on Linux. If not installed, that stage is skipped
  with a warning rather than blocking the rest of the pipeline.

## Where to run this

Run on a **disposable** VM or container with:
- Egress limited to what this script actually needs — `huggingface.co` (for
  the model download) and ClamAV's definition-update servers (`freshclam`).
  The isolation guarantee here is **ephemeral, credential-free compute
  wiped after every run**, not a total absence of network access — the
  download step already requires egress, so "no internet at all" was never
  quite accurate.
- No credentials to anything else (AWS, Vault, internal services).
- Nothing else of value on the box — treat it as burnable.

Never run this on a primary workstation with real credentials on it. See the
Docker-based two-step pattern (download with network, scan with
`--network none`) if you don't have a dedicated VM available.

## What this does NOT cover

- **Fine-tune / weight poisoning** (backdoored behavior triggered by specific
  inputs). ModelScan and Fickling catch load-time code execution, not
  behavioral backdoors — that needs a separate eval-based test, not a static
  file scan.
- **LoRA adapters, model merging, and conversion services** — out of scope
  for this script; conversion/merge steps execute code via the source
  framework's load path and need their own isolated handling.
- **The "verified organization" badge** — not exposed cleanly via the HF API;
  the script prints the model page URL for a manual check.

  ## To-do

- **Pin `modelscan`/`fickling` versions.** Currently installed unpinned
  (`pip install --upgrade modelscan fickling`), so CLI flags can silently
  change between runs — already happened once (`modelscan --output-format`
  and `fickling --check-safety` both broke after a version bump, initially
  producing a false FAIL because the flag itself was invalid, not because
  scanning found anything). Left on latest deliberately for now while still
  exploring; pin exact versions once this moves past MVP.
- ~~ModelScan errors (not fails) on `.h5` files without the `h5py` extra.~~
  **Fixed** — install line now uses `modelscan[h5py]`. Previously this made
  the H5 scanner error out (not find an issue), but the script's exit-code
  check couldn't tell "scanner errored" apart from "scanner found something,"
  so it reported a false REJECT even when the only real scan (PyTorch) came
  back clean. Worth revisiting if other optional scanner extras
  (e.g. TensorFlow SavedModel, ONNX) turn out to be needed too.
- Add `-y`/`--yes` to CI once this leaves manual-confirmation MVP stage.
- Consider a hard gate on source-verification warnings (see above) instead
  of print-only.
- Add automated self-test (crafted malicious pickle) so a broken scanner
  integration is caught immediately rather than discovered on a real run.
