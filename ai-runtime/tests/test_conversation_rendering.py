"""Conversation rendering: budget, turn alignment and authorization safety.

The point of these tests is that a long conversation degrades predictably:
the newest turns survive whole, the authorization context is never cut, and the rendered
conversation never starts with a reply to a question that was dropped.
"""

from __future__ import annotations

from app.model import _format_conversation_for_model


def _user(text: str) -> dict:
    return {"role": "user", "content": text}


def _assistant(text: str) -> dict:
    return {"role": "assistant", "content": text}


def test_recent_turns_are_kept_whole_and_old_ones_dropped_from_the_front():
    messages: list[dict] = []
    for i in range(1, 21):
        messages.append(_user(f"question-{i}"))
        messages.append(_assistant(f"answer-{i}" + "detail" * 200))

    rendered = _format_conversation_for_model(messages, "current request")

    # The oldest turns are gone, the newest survive.
    assert "用户：question-1\n" not in rendered
    assert "用户：question-20" in rendered
    # A kept assistant message is never sliced mid-content.
    assert "detail" * 200 in rendered


def test_conversation_never_starts_with_a_reply_to_a_dropped_question():
    # Pad so early turns fall outside the budget, making the first kept message an assistant one.
    messages: list[dict] = []
    for i in range(30):
        messages.append(_user(f"turn-{i}-question" + "pad" * 400))
        messages.append(_assistant(f"turn-{i}-answer" + "fill" * 400))

    rendered = _format_conversation_for_model(messages, "current request")

    assert rendered.lstrip().startswith("用户："), "conversation must not open with an orphan reply"


def test_authorization_context_is_not_truncated_by_the_turn_budget():
    from app.model import _MAX_AUTHORIZATION_CONTEXT_CHARS

    # Sized to sit inside the authorization cap but far larger than a normal scope statement,
    # so the assertion really tests "not squeezed out by the turn budget".
    repeat = _MAX_AUTHORIZATION_CONTEXT_CHARS // len("authorized target and port scope") - 2
    long_auth = "server authorization context: " + "authorized target and port scope" * repeat
    messages = [
        {"role": "system", "content": long_auth},
        _user("scan the ports"),
        _assistant("ok"),
    ]

    rendered = _format_conversation_for_model(messages, "scan the ports")

    assert long_auth in rendered
    assert rendered.index("[系统/授权上下文]") < rendered.index("用户：scan the ports")


def test_authorization_context_alone_survives_even_when_every_turn_is_dropped():
    # A conversation so long that every turn is dropped still carries the scope context.
    long_auth = "scope: " + "project and target binding" * 5000
    messages = [{"role": "system", "content": long_auth}]
    for i in range(200):
        messages.append(_user(f"turn-{i}" + "long" * 800))

    rendered = _format_conversation_for_model(messages, "current request")

    assert "scope: " in rendered
    assert "[系统/授权上下文]" in rendered


def test_current_request_is_appended_once():
    messages = [_user("previous question"), _assistant("previous answer")]

    rendered = _format_conversation_for_model(messages, "this turn request")

    assert rendered.count("当前请求：this turn request") == 1
    assert rendered.rstrip().endswith("当前请求：this turn request")


def test_empty_conversation_returns_only_the_current_request():
    assert _format_conversation_for_model([], "only this request") == "当前请求：only this request"
