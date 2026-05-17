"""v1.1 smoke: streaming chat + embeddings end-to-end against a real subprocess server.

Skips inference (no real model required) — exercises the wire path:
boot → handshake → debug.status → models.list. Streaming + embeddings
flows are covered by tests/integration/{test_chat_stream,test_embeddings}.py
without needing a model.
"""

from __future__ import annotations

import sys

from secure_llm_server.scripts_smoke import main as _smoke_main


def main() -> int:
    rc = _smoke_main()
    if rc != 0:
        return rc
    print("v1.1 streaming + embeddings: unit + integration tests in `make test`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
