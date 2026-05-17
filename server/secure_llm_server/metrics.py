"""Prometheus metrics registry. Importing this module is side-effect-free
(the registry isn't started until the lifespan does so explicitly)."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

registry = CollectorRegistry()

requests_total = Counter(
    "secure_llm_requests_total",
    "Total requests by endpoint and status.",
    ["endpoint", "status"],
    registry=registry,
)
request_latency = Histogram(
    "secure_llm_request_latency_seconds",
    "Request latency by endpoint.",
    ["endpoint"],
    registry=registry,
)
inference_tokens_total = Counter(
    "secure_llm_inference_tokens_total",
    "Tokens produced/consumed by inference.",
    ["model", "type"],
    registry=registry,
)
inference_queue_depth = Gauge(
    "secure_llm_inference_queue_depth",
    "Per-model inference queue depth.",
    ["model"],
    registry=registry,
)
model_loaded = Gauge(
    "secure_llm_model_loaded",
    "1 if model is currently loaded, else 0.",
    ["model"],
    registry=registry,
)
model_load_seconds = Histogram(
    "secure_llm_model_load_seconds",
    "Time taken to load a model.",
    ["model"],
    registry=registry,
)
handshake_total = Counter(
    "secure_llm_handshake_total",
    "Handshake attempts by result.",
    ["result"],
    registry=registry,
)
envelope_failures_total = Counter(
    "secure_llm_envelope_failures_total",
    "Envelope decryption failures by reason.",
    ["reason"],
    registry=registry,
)
gpu_memory_bytes = Gauge(
    "secure_llm_gpu_memory_bytes", "GPU memory bytes used.", ["gpu"], registry=registry
)
disk_free_bytes = Gauge(
    "secure_llm_disk_free_bytes",
    "Free bytes in the models storage dir.",
    registry=registry,
)
