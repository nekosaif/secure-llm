"""HTTP transport for the secure-llm SDK.

Performs the handshake on first request, wraps every subsequent body in the
application-layer envelope, retries idempotent calls with backoff. TLS
verification is on by default; callers pass ``insecure_skip_tls_verify=True``
for self-signed dev certs.
"""

from __future__ import annotations

import time
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass
from threading import Lock
from typing import Any

import httpx
from nacl.public import PrivateKey

from secure_llm_client.crypto.attestation import AttestationVerifier
from secure_llm_client.crypto.envelope import (
    EnvelopeAuthError,
    open_envelope,
    seal,
)
from secure_llm_client.crypto.handshake import (
    ClientIdentity,
    HandshakeOutcome,
    build_handshake_request,
    derive_session,
)
from secure_llm_client.errors import (
    HandshakeFailed,
    SecureLLMError,
    SessionExpired,
    from_error_envelope,
)
from secure_llm_protocol.errors import ErrorCode
from secure_llm_protocol.schemas import HandshakeRequest, HandshakeResponse


@dataclass(slots=True)
class _SessionState:
    outcome: HandshakeOutcome
    c2s_counter: int
    last_replay_high: int  # high watermark of last-seen s2c counter


class _ReplayClient:
    """Client-side replay protection on responses."""

    __slots__ = ("high", "seen")

    def __init__(self) -> None:
        self.high = 0
        self.seen: set[int] = set()

    def check(self, counter: int) -> None:
        if counter in self.seen:
            raise SecureLLMError("server replay detected", code=ErrorCode.REPLAY_DETECTED)
        # Allow forward-jump; record a small recent set
        self.high = max(self.high, counter)
        self.seen.add(counter)
        if len(self.seen) > 4096:
            # bound memory; drop the oldest by keeping last 2048
            self.seen = set(sorted(self.seen)[-2048:])


class Transport:
    def __init__(
        self,
        *,
        base_url: str,
        identity: ClientIdentity,
        pinned_server_pk: bytes,
        timeout: httpx.Timeout | None = None,
        verify: bool | str = True,
        attestation_verifier: AttestationVerifier | None = None,
        pinned_measurement: str | None = None,
        attestation_required: bool = False,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._identity = identity
        self._pinned = pinned_server_pk
        self._attestation_verifier = attestation_verifier
        self._pinned_measurement = pinned_measurement
        self._attestation_required = attestation_required
        self._client = httpx.Client(
            base_url=self._base,
            timeout=timeout or httpx.Timeout(connect=5, read=300, write=30, pool=5),
            verify=verify,
            headers={"user-agent": "secure-llm-client/0.1"},
        )
        self._lock = Lock()
        self._session: _SessionState | None = None
        self._replay = _ReplayClient()

    @property
    def server_host(self) -> str:
        return urllib.parse.urlparse(self._base).netloc

    # --------------------------------------------------------- handshake

    def _do_handshake(self) -> _SessionState:
        eph_sk = PrivateKey.generate()
        eph_pk = bytes(eph_sk.public_key)
        ts = int(time.time())
        req: HandshakeRequest = build_handshake_request(
            identity=self._identity,
            server_host=self.server_host,
            client_eph_pk=eph_pk,
            now=ts,
        )
        r = self._client.post("/v1/session", json=req.model_dump())
        if r.status_code != 200:
            try:
                detail = r.json()
                code_str = detail.get("detail", {}).get("code") or detail.get("code")
                code = ErrorCode(code_str) if code_str else ErrorCode.BAD_SIGNATURE
            except Exception:
                code = ErrorCode.BAD_SIGNATURE
            raise HandshakeFailed(f"handshake failed: {r.status_code}", code=code)
        outcome = derive_session(
            identity=self._identity,
            client_eph_sk=eph_sk,
            server_host=self.server_host,
            handshake_request_ts=ts,
            response=HandshakeResponse.model_validate_json(r.content),
            pinned_server_static_pk=self._pinned,
            attestation_verifier=self._attestation_verifier,
            pinned_measurement=self._pinned_measurement,
            attestation_required=self._attestation_required,
        )
        # Each handshake yields fresh keys + a fresh s2c counter starting at
        # 0 — so the *server* replay window resets implicitly. The client's
        # own watch on s2c counters must reset too, otherwise the next
        # response's counter=1 collides with the previous session's
        # counter=1 and gets rejected as a (false) replay.
        self._replay = _ReplayClient()
        return _SessionState(outcome=outcome, c2s_counter=0, last_replay_high=0)

    def _session_state(self) -> _SessionState:
        with self._lock:
            if self._session is None:
                self._session = self._do_handshake()
            return self._session

    def reset_session(self) -> None:
        with self._lock:
            if self._session is None:
                return
            sid = self._session.outcome.session_id
            self._session = None
            try:
                import base64

                # URL-safe base64 keeps the session_id inside a single path
                # segment (standard b64 can contain '/').
                self._client.delete(f"/v1/session/{base64.urlsafe_b64encode(sid).decode('ascii')}")
            except Exception:
                pass

    # --------------------------------------------------------- request

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        retry_on_session_expired: bool = True,
    ) -> dict[str, Any]:
        state = self._session_state()
        sid = state.outcome.session_id
        body = b"" if payload is None else _dump_json(payload).encode("utf-8")
        with self._lock:
            state.c2s_counter += 1
            counter = state.c2s_counter
        envelope = seal(
            direction=state.outcome.c2s,
            counter=counter,
            session_id=sid,
            method=method.upper(),
            path=path,
            plaintext=body,
        )
        r = self._client.request(
            method, path, content=envelope, headers={"content-type": "application/octet-stream"}
        )
        # If session expired, do one auto-rehandshake.
        if r.status_code in (401, 400):
            err_code = _try_extract_error_code(r)
            if (
                err_code in {ErrorCode.UNKNOWN_SESSION, ErrorCode.SESSION_EXPIRED}
                and retry_on_session_expired
            ):
                with self._lock:
                    self._session = None
                return self.request(method, path, payload=payload, retry_on_session_expired=False)
        return _decode_response(r, state, method=method, path=path, replay=self._replay)

    def stream_request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """SSE-streaming sibling of :meth:`request`.

        Yields one decrypted JSON payload per ``data:`` line. Each envelope
        carries a monotonic s2c counter, so the replay check is identical to
        the non-streaming path. A trailing ``data: [DONE]`` ends iteration.
        """
        import base64

        state = self._session_state()
        sid = state.outcome.session_id
        body = b"" if payload is None else _dump_json(payload).encode("utf-8")
        with self._lock:
            state.c2s_counter += 1
            counter = state.c2s_counter
        envelope = seal(
            direction=state.outcome.c2s,
            counter=counter,
            session_id=sid,
            method=method.upper(),
            path=path,
            plaintext=body,
        )
        with self._client.stream(
            method,
            path,
            content=envelope,
            headers={
                "content-type": "application/octet-stream",
                "accept": "text/event-stream",
            },
        ) as response:
            if response.status_code != 200:
                response.read()
                _decode_response(response, state, method=method, path=path, replay=self._replay)
                return  # _decode_response raises on errors

            import json as _json

            for line in response.iter_lines():
                if not line:
                    continue
                if line.startswith(":"):  # SSE comment / keepalive
                    continue
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    return
                try:
                    raw_envelope = base64.b64decode(data, validate=True)
                except Exception as e:
                    raise SecureLLMError(f"bad SSE base64: {e}", code=ErrorCode.BAD_ENVELOPE) from e
                env, plaintext = open_envelope(
                    direction=state.outcome.s2c,
                    expected_session_id=sid,
                    method=method.upper(),
                    path=path,
                    body=raw_envelope,
                )
                self._replay.check(env.counter)
                yield _json.loads(plaintext) if plaintext else {}

    def close(self) -> None:
        try:
            self.reset_session()
        finally:
            self._client.close()


def _dump_json(obj: dict[str, Any]) -> str:
    import json

    return json.dumps(obj, separators=(",", ":"))


def _try_extract_error_code(r: httpx.Response) -> ErrorCode | None:
    try:
        data = r.json()
        code_str = data.get("code") or (data.get("detail") or {}).get("code")
        return ErrorCode(code_str) if code_str else None
    except Exception:
        return None


def _decode_response(
    r: httpx.Response,
    state: _SessionState,
    *,
    method: str,
    path: str,
    replay: _ReplayClient,
) -> dict[str, Any]:
    if r.status_code == 204:
        return {}
    content_type = r.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        # plain-JSON error
        data = r.json()
        err = data.get("detail", data)
        code = ErrorCode(err.get("code", ErrorCode.INTERNAL_ERROR.value))
        raise from_error_envelope(
            code,
            err.get("message", ""),
            err.get("error_id"),
            err.get("retry_after_seconds"),
        )

    if not content_type.startswith("application/octet-stream"):
        raise SecureLLMError(f"unexpected content-type: {content_type}")

    try:
        env, plaintext = open_envelope(
            direction=state.outcome.s2c,
            expected_session_id=state.outcome.session_id,
            method=method.upper(),
            path=path,
            body=r.content,
        )
    except EnvelopeAuthError as e:
        raise SecureLLMError(
            f"response decrypt failed: {e}", code=ErrorCode.DECRYPT_FAILED
        ) from None
    replay.check(env.counter)

    import json

    data = json.loads(plaintext) if plaintext else {}

    # Application-layer error envelopes ride inside successful HTTP 4xx bodies too.
    looks_like_error = (
        isinstance(data, dict) and "code" in data and "message" in data and len(data) <= 4
    )
    if r.status_code >= 400 or looks_like_error:
        code_str = data.get("code")
        if code_str:
            code = ErrorCode(code_str)
            if code == ErrorCode.SESSION_EXPIRED:
                raise SessionExpired(data.get("message", ""))
            raise from_error_envelope(
                code,
                data.get("message", ""),
                data.get("error_id"),
                data.get("retry_after_seconds"),
            )
    return data
