#!/usr/bin/env bash
# Run pip-audit against the *production* deps of each workspace member.
#
# Why this script exists:
#   `pip-audit --strict` on the active venv fails because the workspace
#   members (secure-llm-{protocol,server,client}) aren't on PyPI and so
#   have no CVE feed — `--strict` treats those as errors.
#   Workaround: ask uv for the resolved, non-editable, no-dev requirements
#   of each workspace member, and audit that requirements file directly.
#
# Accepted ignores (re-evaluate each release):
#
#   CVE-2025-69872  diskcache 5.6.3
#     Pulled in transitively by llama-cpp-python. No fix version is
#     available upstream as of the lockfile pin. The vuln is in
#     diskcache's pickle-based on-disk cache; we do not use diskcache
#     directly and llama-cpp-python's cache is a local-only file inside
#     the server's data dir (already on the trusted side of the threat
#     boundary — see docs/threat-model.md). Tracking upstream:
#     bump the diskcache pin or drop the ignore as soon as a fixed
#     version is available.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"
bash scripts/ensure_venv.sh

IGNORES=(
  "--ignore-vuln" "CVE-2025-69872"
)

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

audit_pkg() {
  local pkg="$1"
  echo "[sec] auditing production deps of ${pkg}"
  uv export --package "${pkg}" --no-dev --no-emit-workspace --no-hashes \
    --format requirements.txt > "${TMP}/${pkg}.txt"
  uv run pip-audit --strict -r "${TMP}/${pkg}.txt" "${IGNORES[@]}"
}

audit_pkg secure-llm-server
audit_pkg secure-llm-client
audit_pkg secure-llm-protocol

echo "[sec] all production trees clean (accepted: ${IGNORES[*]})"
