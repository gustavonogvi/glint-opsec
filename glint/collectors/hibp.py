import hashlib
import httpx
from dataclasses import dataclass, field


@dataclass
class HIBPResult:
    checked: bool
    breach_count: int
    breaches: list[dict]
    available: bool
    error: str | None = None


def check_email(email: str, api_key: str) -> HIBPResult:
    if not api_key:
        return HIBPResult(
            checked=False,
            breach_count=0,
            breaches=[],
            available=False,
            error="no_api_key",
        )

    try:
        response = httpx.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={
                "hibp-api-key": api_key,
                "User-Agent":   "Glint-OPSEC/1.0",
            },
            params={"truncateResponse": "false"},
            timeout=5.0,
        )

        if response.status_code == 404:
            return HIBPResult(checked=True, breach_count=0, breaches=[], available=True)

        if response.status_code == 401:
            return HIBPResult(
                checked=False, breach_count=0, breaches=[],
                available=False, error="invalid_api_key",
            )

        if response.status_code == 429:
            return HIBPResult(
                checked=False, breach_count=0, breaches=[],
                available=False, error="rate_limited",
            )

        breaches = response.json()
        return HIBPResult(
            checked=True,
            breach_count=len(breaches),
            breaches=breaches,
            available=True,
        )

    except Exception:
        return HIBPResult(
            checked=False, breach_count=0, breaches=[],
            available=False, error="request_failed",
        )


def check_password(password: str) -> int:
    sha1    = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix  = sha1[:5]
    suffix  = sha1[5:]

    try:
        response = httpx.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5.0,
        )
        for line in response.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0] == suffix:
                return int(parts[1])
        return 0

    except Exception:
        return -1
