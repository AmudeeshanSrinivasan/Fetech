"""Content-state detection and acceptance scoring."""

from __future__ import annotations

import re

from fetech.models import PageState, QualityAssessment

_LOGIN = re.compile(r"\b(sign[ -]?in|log[ -]?in|enter your password|authentication required)\b", re.I)
_CAPTCHA = re.compile(r"\b(captcha|verify you are human|human verification)\b", re.I)
_BOT = re.compile(r"\b(access denied|bot detection|unusual traffic|checking your browser)\b", re.I)
_PAYWALL = re.compile(r"\b(subscribe to continue|subscription required|unlock this article)\b", re.I)
_ERROR = re.compile(r"\b(404 not found|500 internal server error|service unavailable)\b", re.I)


def assess_text(
    text: str, *, media_type: str = "text/plain", expected_language: str | None = None
) -> QualityAssessment:
    normalized = " ".join(text.split())
    reasons: list[str] = []
    state = PageState.OK
    if not normalized:
        state = PageState.EMPTY
        reasons.append("no usable text")
    elif _CAPTCHA.search(normalized):
        state = PageState.CAPTCHA
        reasons.append("CAPTCHA marker detected")
    elif _BOT.search(normalized):
        state = PageState.BOT_BLOCK
        reasons.append("bot-block marker detected")
    elif _PAYWALL.search(normalized):
        state = PageState.PAYWALL
        reasons.append("paywall marker detected")
    elif _LOGIN.search(normalized) and len(normalized) < 5_000:
        state = PageState.LOGIN
        reasons.append("login page marker detected")
    elif _ERROR.search(normalized) and len(normalized) < 5_000:
        state = PageState.ERROR
        reasons.append("error page marker detected")
    length_score = min(1.0, len(normalized) / 1_000)
    accepted = state == PageState.OK and length_score >= 0.05
    if state == PageState.OK and not accepted:
        reasons.append("content is below the minimum useful-text threshold")
    if expected_language:
        reasons.append("language verification requires an optional detector")
    score = length_score if state == PageState.OK else min(0.2, length_score)
    return QualityAssessment(
        page_state=state,
        score=round(score, 4),
        accepted=accepted,
        completeness=length_score,
        reasons=tuple(reasons),
    )


def assess_binary(size: int, *, media_type: str) -> QualityAssessment:
    accepted = size > 0
    return QualityAssessment(
        page_state=PageState.OK if accepted else PageState.EMPTY,
        score=1.0 if accepted else 0.0,
        accepted=accepted,
        completeness=1.0 if accepted else 0.0,
        reasons=() if accepted else (f"empty {media_type} body",),
    )
