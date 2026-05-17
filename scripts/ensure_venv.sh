#!/usr/bin/env bash
# Refuses to proceed unless we're inside ./.venv (or explicitly opted out).
# Sourced or invoked by Makefile targets and bootstrap.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED_VENV="${REPO_ROOT}/.venv"

if [[ "${SECURE_LLM_ALLOW_GLOBAL:-0}" == "1" ]]; then
  echo "[ensure_venv] WARNING: SECURE_LLM_ALLOW_GLOBAL=1; running outside project venv is unsupported" >&2
  exit 0
fi

if [[ ! -d "${EXPECTED_VENV}" ]]; then
  echo "[ensure_venv] no ${EXPECTED_VENV} yet — run 'make bootstrap' first" >&2
  exit 1
fi

# When called via `uv run`, VIRTUAL_ENV is set by uv to the project venv.
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
  # Allow direct invocations as long as the venv exists; downstream targets
  # use `uv run` which will activate it.
  exit 0
fi

if [[ "${VIRTUAL_ENV}" != "${EXPECTED_VENV}" ]]; then
  echo "[ensure_venv] refusing: VIRTUAL_ENV=${VIRTUAL_ENV} != ${EXPECTED_VENV}" >&2
  echo "[ensure_venv] deactivate or set SECURE_LLM_ALLOW_GLOBAL=1 to override (not recommended)" >&2
  exit 1
fi
