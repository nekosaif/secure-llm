"""v2.0b: multimodal content parts on ChatMessage.

The schema-level tests live here; the inference-side integration with
Llava is gated on a CLIP companion GGUF being present and runs only
in ``make smoke`` against a real model.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from secure_llm_protocol.schemas import (
    ChatCompletionRequest,
    ChatMessage,
    ImageContentPart,
    ImageUrlPayload,
    TextContentPart,
)


def test_chat_message_accepts_plain_string():
    msg = ChatMessage(role="user", content="hello")
    assert msg.content == "hello"


def test_chat_message_accepts_text_part_list():
    msg = ChatMessage(role="user", content=[TextContentPart(text="hello")])
    assert isinstance(msg.content, list)
    assert msg.content[0].text == "hello"


def test_chat_message_accepts_mixed_text_and_image_parts():
    msg = ChatMessage(
        role="user",
        content=[
            TextContentPart(text="describe this:"),
            ImageContentPart(
                image_url=ImageUrlPayload(url="data:image/png;base64,iVBORw0KGgo="),
            ),
        ],
    )
    assert len(msg.content) == 2  # type: ignore[arg-type]
    image_part = msg.content[1]  # type: ignore[index]
    assert isinstance(image_part, ImageContentPart)
    assert image_part.image_url.url.startswith("data:image/png")


def test_chat_message_rejects_unknown_part_type():
    with pytest.raises(ValidationError):
        ChatMessage.model_validate(
            {"role": "user", "content": [{"type": "audio", "audio": "x"}]}
        )


def test_chat_message_rejects_part_without_type():
    with pytest.raises(ValidationError):
        ChatMessage.model_validate(
            {"role": "user", "content": [{"text": "hi"}]}
        )


def test_image_url_payload_detail_defaults_to_auto():
    payload = ImageUrlPayload(url="data:image/png;base64,xx")
    assert payload.detail == "auto"


def test_chat_completion_request_round_trips_image_parts():
    req = ChatCompletionRequest(
        model="llava-q4",
        messages=[
            ChatMessage(role="system", content="be terse"),
            ChatMessage(
                role="user",
                content=[
                    TextContentPart(text="what's in this image?"),
                    ImageContentPart(
                        image_url=ImageUrlPayload(url="data:image/png;base64,iVBORw0=")
                    ),
                ],
            ),
        ],
    )
    serialized = req.model_dump_json()
    rebuilt = ChatCompletionRequest.model_validate_json(serialized)
    assert rebuilt.messages[1].content[1].image_url.url.startswith("data:")  # type: ignore[index, union-attr]


def test_chat_message_rejects_empty_part_list_is_valid_pydantic():
    """An empty list is technically valid at the schema level — the
    router rejects empty content separately with a 400."""
    msg = ChatMessage(role="user", content=[])
    assert msg.content == []
