"""Regression tests for the tolerant LLM-JSON extractor.

Each case mirrors a real failure mode observed on phi3:medium / llama3.1
local runs (see slm_analyst error logs).
"""

import json

import pytest

from utils import extract_json


def test_direct_parse():
    assert extract_json('{"a": 1}') == {"a": 1}


def test_strips_markdown_fences():
    raw = "Here is the result:\n```json\n{\"verdict\": \"normal\"}\n```\nThanks!"
    assert extract_json(raw) == {"verdict": "normal"}


def test_recovers_from_prose_around_json():
    raw = "Sure! {\"score\": 7, \"verdict\": \"suspicious\"} — hope this helps."
    assert extract_json(raw) == {"score": 7, "verdict": "suspicious"}


def test_repairs_unterminated_string_via_brace_balancing():
    """Truncated by num_predict — the closing '}' and quote are missing."""
    raw = '{"summary": "powershell launched a remote'
    out = extract_json(raw)
    assert "summary" in out


def test_repairs_invalid_unicode_escape():
    """LLM emits `\\user` (no 4 hex digits) instead of escaping the backslash."""
    raw = r'{"path": "C:\users\admin\malware.exe"}'
    out = extract_json(raw)
    assert "path" in out


def test_repairs_trailing_comma():
    raw = '{"a": 1, "b": 2,}'
    assert extract_json(raw) == {"a": 1, "b": 2}


def test_smart_quotes_normalised():
    raw = "{\u201cverdict\u201d: \u201cmalicious\u201d}"
    assert extract_json(raw) == {"verdict": "malicious"}


def test_empty_raises():
    with pytest.raises(json.JSONDecodeError):
        extract_json("")


def test_total_garbage_raises():
    with pytest.raises(json.JSONDecodeError):
        extract_json("absolutely no json here at all")
