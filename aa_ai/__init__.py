"""Undertow: detect and slow autonomous AI attack agents (ARTEX-class)."""
# Anthropic Claude Opus 5.5 on Amazon Bedrock: the model every LLM feature uses unless overridden.
DEFAULT_MODEL = "anthropic.claude-opus-5-5"

from .events import Event, parse_alb, parse_jsonl
from .scoring import analyze, distributed_spray

__all__ = ["Event", "parse_alb", "parse_jsonl", "analyze", "distributed_spray"]
