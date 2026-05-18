# Runbook

Common production incidents and how to handle them. Newest patterns at
the bottom.

## "handshake_failures spiking"

Signal: `secure_llm_handshake_total{result!="ok"}` rate > baseline.

1. `sllm debug logs --level INFO --component secure_llm_server.audit` to
   see the `handshake.reject` events and their `code` field.
2. If `unknown_client` dominates: someone is hitting the endpoint who
   isn't on the allowlist. Decide whether to widen, leave alone, or
   block at the network layer.
3. If `client_revoked` dominates: a client is misconfigured; help them
   rotate keys.
4. If `bad_signature` dominates: someone is tampering or there's a clock
   skew. Check NTP.

## "queue_depth saturated"

Signal: `secure_llm_inference_queue_depth{model="..."}` ≥
`inference.queue_depth_per_model`.

1. `sllm admin models list` — note how many models are loaded vs
   `max_loaded`.
2. If only one model is loaded and the queue is full, you're inference-
   bound — scale out or use a smaller/faster model.
3. If multiple models are thrashing the LRU, increase `max_loaded` (if
   you have RAM/VRAM) or raise `idle_timeout_seconds`.

## "model stuck loading"

Signal: a model stays in `state="loading"` for minutes.

1. `sllm debug errors` — look for recent `LOAD_FAILED` entries with the
   model id.
2. `data/logs/server.log` will have a `manager.loading` line and an
   error if the load raised.
3. Common causes: corrupt encrypted blob (sha doesn't match the meta
   file), age identity missing, tmpfs out of space.
4. To force-fix: `sllm admin models unload <id>` (drops any half-loaded
   state), then retry.

## "tmpfs full"

Signal: model loads start failing with `ENOSPC` or `manager.loading`
errors mentioning `/dev/shm`.

1. Check `df -h /dev/shm`.
2. If full, increase the tmpfs size in the systemd unit (`tmpfs_size=...`)
   and reload.
3. If the same model is decryption-thrashing, raise `max_loaded` or
   lower the cadence of preloads.

## "envelope_failures spiking"

Signal: `secure_llm_envelope_failures_total` non-zero with `reason="aead"`
or `"malformed"`.

1. If it's coming from one client: the client is corrupting envelopes
   (wrong keys, clock issue, byte truncation). Tell them to recreate the
   session (`sllm` clients do this automatically on session-expired
   errors).
2. If it's coming from many clients: a server change broke the wire
   format — `git diff` on `crypto/envelope.py` and `protocol/wire.py`.

## "Redis unreachable" (federated deployments)

Signal: server logs `boot.federation` then later `unknown_session` /
`hydrate` errors after a network partition; `INFO`-level Redis client
warnings from `redis.asyncio`.

1. `redis-cli -u $SESSION_STORE_URL ping` to confirm.
2. If Redis is down: existing sessions cached on the *current* instance
   still work; failover to a peer will not. Restart Redis; sessions in
   Redis survive only if `appendonly yes` is configured or the dataset
   fits a save snapshot.
3. If Redis is up but unreachable from one instance: it's a network
   issue (VPC peering, firewall). Restore connectivity, no
   server-side restart needed — the client reconnects on next op.
4. Worst case (Redis data lost): every client sees one
   `unknown_session` and transparently rehandshakes.

## "instance identity mismatch" (federated deployments)

Signal: clients pinned via `sllm trust` start failing with
`server_key_mismatch` against one instance but not others.

1. On each instance: `sha256sum data/keys/server.x25519.key.pub`. Every
   sum must be identical across the fleet.
2. If one differs: that instance was bootstrapped from scratch instead
   of having the shared identity copied in. Stop it, follow "Adding a
   node" in `operator-guide.md`, restart.
3. Until fixed, drain the offending instance from the LB.

## "key rotation needed"

If you suspect a server key compromise:

1. Stop the server.
2. Rename `data/keys/server.x25519.key{,.pub}` and
   `data/keys/server.ed25519.key{,.pub}` to `.compromised`.
3. `make bootstrap` regenerates fresh keys.
4. Distribute the new `server.x25519.key.pub` to all clients out-of-band
   so they can re-run `sllm trust`.
5. All sessions die at restart (server key changes mean the
   server-static DH share changes, so existing sessions can't decrypt new
   handshakes — but live sessions are still ephemeral-keyed and remain
   valid until TTL).
