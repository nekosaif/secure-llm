# Changelog

All notable changes to this project will be documented here.
Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-05-17

### Added
- End-to-end-encrypted LLM inference server (`llama.cpp` backend) and
  OpenAI-shaped Python client SDK + `sllm` CLI.
- Static+ephemeral X25519 handshake with Ed25519 transcript signatures
  (`PROTOCOL_VERSION = 1.0`).
- Application-layer ChaCha20-Poly1305 envelope with AAD bound to
  method+path+session+counter; sliding-window replay protection.
- At-rest age (pyrage) encryption of model files; tmpfs-with-unlink
  decryption path.
- ModelManager with LRU + idle-timeout offload and per-model inference
  workers.
- `/v1/debug/*` and `/v1/admin/*` APIs for status, doctor, logs,
  errors, sessions, models, log-level, gc, shutdown.
- Structured payload-redacted logging (structlog), Prometheus metrics,
  ring log, error tracker, health probes, audit log.
- `make bootstrap`, `make doctor`, `make run`, `make smoke`,
  `make test`, `make lint type sec` — self-healing one-click flows.
- Threat model, protocol spec, operator guide, runbook, agent
  collaboration docs (`CLAUDE.md`, `AGENTS.md`, `SECURITY.md`,
  `DESIGN.md`, `MEMORY.md`, `HANDOFF.md`).
