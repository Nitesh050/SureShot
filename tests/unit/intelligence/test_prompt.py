import pytest

from sureshot.engine.intelligence.prompts.registry import (
    PromptNotFound,
    list_prompts,
    load_prompt,
)


def test_triage_prompt_loads():
    prompt = load_prompt("triage", "v3")
    assert prompt.version == "triage.v3"
    assert prompt.hash and len(prompt.hash) == 16


def test_hash_is_stable_across_loads():
    assert load_prompt("triage", "v3").hash == load_prompt("triage", "v3").hash


def test_missing_prompt_raises():
    with pytest.raises(PromptNotFound):
        load_prompt("triage", "v99")


def test_render_substitutes_placeholders():
    rendered = load_prompt("triage", "v3").render(
        rule_id="python.sqli",
        message="SQL injection",
        cwe="CWE-89",
        file_path="app.py",
        line_start=7,
        line_end=9,
        context_start=1,
        code="def get_user(u): ...",
    )
    assert "python.sqli" in rendered
    assert "{rule_id}" not in rendered


def test_render_rejects_missing_placeholder():
    with pytest.raises(KeyError):
        load_prompt("triage", "v3").render(rule_id="x")


def test_prompts_are_discoverable():
    assert ("triage", "v3") in list_prompts()