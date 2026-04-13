from dataclasses import dataclass
import httpx


@dataclass
class IPReputation:
    ip: str
    country: str | None
    country_code: str | None
    isp: str | None
    org: str | None
    asn: str | None
    is_proxy: bool
    is_hosting: bool
    timezone: str | None
    available: bool


def collect(ip: str) -> IPReputation:
    if ip in ("127.0.0.1", "::1", "unknown"):
        return IPReputation(
            ip=ip,
            country=None,
            country_code=None,
            isp=None,
            org=None,
            asn=None,
            is_proxy=False,
            is_hosting=False,
            timezone=None,
            available=False,
        )

    try:
        response = httpx.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,isp,org,as,proxy,hosting,timezone"},
            timeout=5.0,
        )
        data = response.json()

        if data.get("status") != "success":
            raise ValueError("ip-api returned non-success status")

        return IPReputation(
            ip=ip,
            country=data.get("country"),
            country_code=data.get("countryCode"),
            isp=data.get("isp"),
            org=data.get("org"),
            asn=data.get("as"),
            is_proxy=bool(data.get("proxy", False)),
            is_hosting=bool(data.get("hosting", False)),
            timezone=data.get("timezone"),
            available=True,
        )

    except Exception:
        return IPReputation(
            ip=ip,
            country=None,
            country_code=None,
            isp=None,
            org=None,
            asn=None,
            is_proxy=False,
            is_hosting=False,
            timezone=None,
            available=False,
        )
