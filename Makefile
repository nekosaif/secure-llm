# secure-llm — one-click developer Makefile
#
# All targets run inside ./.venv via `uv run`. Bootstrap is auto-applied where
# state is missing. Override the venv guard only with SECURE_LLM_ALLOW_GLOBAL=1.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

REPO_ROOT := $(shell pwd)
VENV     := $(REPO_ROOT)/.venv
UV       := uv
URUN     := $(UV) run
PYTHON   := $(URUN) python
PORT     ?= 8443
PID_FILE := $(REPO_ROOT)/data/server.pid
LOG_FILE := $(REPO_ROOT)/data/logs/server.log

# Every real target depends on this guard.
define guard
	@bash $(REPO_ROOT)/scripts/ensure_venv.sh
endef

##@ Setup
.PHONY: bootstrap
bootstrap: ## install uv, build .venv, sync deps, gen keys/certs, run doctor
	@bash $(REPO_ROOT)/scripts/bootstrap.sh

.PHONY: bootstrap-full
bootstrap-full: bootstrap ## bootstrap + pull tiny smoke-test model
	$(URUN) sllm models pull TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF:tinyllama-1.1b-chat-v1.0.Q2_K.gguf || true

.PHONY: doctor
doctor: ## run diagnostic self-check (same output as /v1/debug/doctor)
	$(call guard)
	$(URUN) python -m secure_llm_server.scripts_doctor

##@ Run
.PHONY: run
run: bootstrap ## start server in foreground
	$(call guard)
	$(URUN) secure-llm-server --config $(REPO_ROOT)/data/config.toml

.PHONY: run-bg
run-bg: bootstrap ## start server in background; writes data/server.pid
	$(call guard)
	@mkdir -p $(REPO_ROOT)/data/logs
	@if [[ -f $(PID_FILE) ]] && kill -0 "$$(cat $(PID_FILE))" 2>/dev/null; then \
	  echo "already running pid=$$(cat $(PID_FILE))"; exit 0; fi
	@$(URUN) secure-llm-server --config $(REPO_ROOT)/data/config.toml \
	  >>$(LOG_FILE) 2>&1 & echo $$! > $(PID_FILE)
	@sleep 1; echo "started pid=$$(cat $(PID_FILE)) (logs: $(LOG_FILE))"

.PHONY: stop
stop: ## stop background server
	@if [[ -f $(PID_FILE) ]]; then \
	  pid="$$(cat $(PID_FILE))"; \
	  if kill -0 "$$pid" 2>/dev/null; then kill -TERM "$$pid"; echo "stopped pid=$$pid"; fi; \
	  rm -f $(PID_FILE); \
	else echo "no pid file"; fi

.PHONY: logs
logs: ## tail JSON logs (pretty)
	@tail -F $(LOG_FILE) | $(URUN) python -m secure_llm_server.scripts_pretty_log

##@ Tests + quality
.PHONY: test
test: bootstrap ## run unit + property + integration tests
	$(call guard)
	$(URUN) pytest -q --cov

.PHONY: test-one
test-one: ## run a single test: make test-one T=path::node
	$(call guard)
	$(URUN) pytest -q "$(T)"

.PHONY: lint
lint: bootstrap ## ruff
	$(call guard)
	$(URUN) ruff check .
	$(URUN) ruff format --check .

.PHONY: type
type: bootstrap ## mypy --strict
	$(call guard)
	$(URUN) mypy

.PHONY: sec
sec: bootstrap ## pip-audit + bandit
	$(call guard)
	@bash scripts/sec_audit.sh
	$(URUN) bandit -c pyproject.toml -r protocol server client -q

.PHONY: fuzz
fuzz: bootstrap ## short atheris run (CI runs long)
	$(call guard)
	$(URUN) python -m server.tests.fuzz.run_short || true

##@ End-to-end
.PHONY: smoke
smoke: bootstrap-full ## full e2e: handshake -> chat -> idle-offload -> admin/debug
	$(call guard)
	$(URUN) python -m secure_llm_server.scripts_smoke

.PHONY: smoke-v11
smoke-v11: bootstrap ## v1.1: smoke + streaming + embeddings integration tests
	$(call guard)
	$(URUN) python -m secure_llm_server.scripts_smoke_v11
	$(URUN) pytest -q server/tests/integration/test_chat_stream.py \
	                  server/tests/integration/test_embeddings.py \
	                  server/tests/unit/test_streaming.py

.PHONY: smoke-v12
smoke-v12: bootstrap ## v1.2: smoke + LoRA + multi-tenant isolation
	$(call guard)
	$(URUN) python -m secure_llm_server.scripts_smoke_v12
	$(URUN) pytest -q server/tests/integration/test_chat_stream.py \
	                  server/tests/integration/test_embeddings.py \
	                  server/tests/integration/test_multi_tenant.py \
	                  server/tests/unit/test_streaming.py

.PHONY: smoke-v13
smoke-v13: bootstrap ## v1.3: federation (SessionStore + Redis-backed failover)
	$(call guard)
	$(URUN) pytest -q server/tests/unit/test_federation.py \
	                  server/tests/unit/test_keystore_backend.py

.PHONY: crypto-soak
crypto-soak: bootstrap ## 1M envelope roundtrips
	$(call guard)
	$(URUN) python -m server.tests.crypto_property.soak

.PHONY: venv-isolation-check
venv-isolation-check: ## verify uv run python resolves under ./.venv
	$(call guard)
	@out=$$($(URUN) python -c 'import sys; print(sys.executable)'); \
	case "$$out" in $(VENV)/*) echo "ok: $$out";; *) echo "FAIL: $$out outside $(VENV)"; exit 1;; esac

##@ Docs
.PHONY: agent-docs
agent-docs: ## regenerate CLAUDE.md and AGENTS.md from docs/_agent-context.md
	$(call guard)
	$(URUN) python scripts/render_agent_docs.py

.PHONY: diagrams
diagrams: ## render architecture diagrams to docs/diagrams/*.html
	$(call guard)
	$(URUN) python scripts/render_diagrams.py

##@ Container / release
.PHONY: container
container: ## build server container image
	docker build -t secure-llm-server:dev -f server/Dockerfile .

.PHONY: sbom
sbom: ## syft SBOM
	@command -v syft >/dev/null || { echo "install syft: https://github.com/anchore/syft"; exit 1; }
	syft . -o spdx-json > $(REPO_ROOT)/data/sbom.spdx.json

##@ Housekeeping
.PHONY: clean
clean: ## remove .venv and caches
	rm -rf .venv .pytest_cache .mypy_cache .ruff_cache .hypothesis

.PHONY: nuke
nuke: ## remove .venv + all local data (irreversible)
	@read -p "delete .venv AND data/ (keys, models, logs)? [y/N] " a; [[ "$$a" == "y" ]] || exit 1
	rm -rf .venv data

.PHONY: help
help: ## show this help
	@awk 'BEGIN {FS=":.*##"; printf "\nUsage: make <target>\n"} \
	  /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 } \
	  /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
