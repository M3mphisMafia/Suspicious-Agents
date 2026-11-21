"""LLM-in-the-loop red-team harness: a real model drives HTTP requests against the
operator's OWN target, to test whether Undertow's deception actually works — does the
model get stuck in the padded cell, chase fake data, stop on the scope notice — and to
MEASURE the tokens it burns rather than estimate them.

Guardrails by construction: it only makes HTTP requests, only to the one configured
target, under hard request/time/token budgets, and it logs every action and the model's
reasoning. It is a defensive validation tool for your own app, not a general attack agent.
"""
