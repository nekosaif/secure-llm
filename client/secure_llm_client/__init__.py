"""secure-llm client SDK (OpenAI-compatible surface) and ``sllm`` CLI."""

from secure_llm_client.client import SecureLLMClient
from secure_llm_client.errors import (
    AdminRequiredError,
    AuthError,
    HandshakeFailed,
    SecureLLMError,
    ServerKeyMismatch,
)

__version__ = "0.1.0"

__all__ = [
    "AdminRequiredError",
    "AuthError",
    "HandshakeFailed",
    "SecureLLMClient",
    "SecureLLMError",
    "ServerKeyMismatch",
]
