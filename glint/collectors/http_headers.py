from dataclasses import dataclass, field
from flask import Request


@dataclass
class HeaderAnalysis:
    accept_language: str | None
    user_agent: str | None
    lang_mismatch: bool
    lang_header: str | None
    lang_navigator: str | None


def analyze(request: Request, browser: dict) -> HeaderAnalysis:
    accept_language = request.headers.get("Accept-Language")
    user_agent      = request.headers.get("User-Agent")

    lang_header    = _parse_primary_lang(accept_language)
    lang_navigator = _parse_primary_lang(
        browser.get("navigator", {}).get("language")
    )

    lang_mismatch = False
    if lang_header and lang_navigator:
        lang_mismatch = lang_header.lower() != lang_navigator.lower()

    return HeaderAnalysis(
        accept_language=accept_language,
        user_agent=user_agent,
        lang_mismatch=lang_mismatch,
        lang_header=lang_header,
        lang_navigator=lang_navigator,
    )


def _parse_primary_lang(value: str | None) -> str | None:
    if not value:
        return None
    primary = value.split(",")[0].split(";")[0].strip()
    return primary if primary else None
