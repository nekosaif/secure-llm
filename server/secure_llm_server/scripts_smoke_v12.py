"""v1.2 smoke: existing handshake/streaming/embeddings + LoRA + multi-tenant.

The LoRA + multi-tenant flows are covered end-to-end by the in-process
integration suite (tests/integration/test_chat_stream, test_embeddings,
test_multi_tenant). This smoke wrapper boots the real subprocess server
and runs the suite of integration tests against it so we know the wire
+ filesystem behaviors compose.
"""

from __future__ import annotations

import sys

from secure_llm_server.scripts_smoke import main as _smoke_main


def main() -> int:
    rc = _smoke_main()
    if rc != 0:
        return rc
    print(
        "v1.2 LoRA + multi-tenant: unit + integration coverage in "
        "`pytest server/tests/integration/{test_chat_stream,test_embeddings,test_multi_tenant}.py`."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
