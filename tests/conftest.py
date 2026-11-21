import pytest

from aa_ai import scorer


@pytest.fixture(autouse=True)
def edge_block_mode(monkeypatch, request):
    """Most tests exercise the WAF block path; tests marked cell_edge get the default (cell)."""
    if "cell_edge" not in request.keywords:
        monkeypatch.setitem(scorer.DEFAULT_POLICY, "edge", "block")
