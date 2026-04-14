import uuid
import ipaddress
from datetime import datetime
from zoneinfo import ZoneInfo
from dataclasses import dataclass, field
from glint.collectors.http_headers import HeaderAnalysis
from glint.collectors.ip_reputation import IPReputation
from glint.collectors.dns_leak import DNSLeakResult
from glint.collectors.hibp import HIBPResult


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _tz_offset(name: str) -> int | None:
    try:
        return int(datetime.now(ZoneInfo(name)).utcoffset().total_seconds())
    except Exception:
        return None


@dataclass
class Finding:
    id: str
    finding_key: str
    severity: str
    title: str
    description: str
    dimension: str
    evidence: dict = field(default_factory=dict)


@dataclass
class DimensionScore:
    name: str
    score: float
    findings: list[Finding] = field(default_factory=list)


def _finding(key: str, severity: str, title: str, description: str,
             dimension: str, evidence: dict | None = None) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        finding_key=key,
        severity=severity,
        title=title,
        description=description,
        dimension=dimension,
        evidence=evidence or {},
    )


def score_anonymity(browser: dict) -> DimensionScore:
    score = 0.0
    findings = []

    font_count = browser.get("font_count", 0)
    if font_count > 80:
        score += 20.0
        findings.append(_finding(
            "FONT_COUNT_HIGH", "MEDIUM",
            "High font count",
            f"Browser detected {font_count} fonts. High font counts are rare and increase uniqueness.",
            "anonymity",
            {"font_count": font_count},
        ))

    webgl = browser.get("webgl", {})
    if webgl and not webgl.get("webgl_blocked"):
        if webgl.get("unmasked") and webgl.get("renderer"):
            score += 15.0
            findings.append(_finding(
                "WEBGL_SPECIFIC", "MEDIUM",
                "Identifiable GPU renderer",
                "Browser exposed exact GPU model via WEBGL_debug_renderer_info.",
                "anonymity",
                {"renderer": webgl.get("renderer"), "vendor": webgl.get("vendor")},
            ))

    nav = browser.get("navigator", {})
    if nav:
        concurrency = nav.get("hardware_concurrency", 0)
        memory      = nav.get("device_memory", 0)
        if concurrency and memory:
            score += 10.0

    if not browser.get("canvas_blocked"):
        score += 15.0
        findings.append(_finding(
            "CANVAS_EXPOSED", "HIGH",
            "Canvas fingerprint collected",
            "Browser did not block canvas fingerprinting. This hash can identify you across sites without cookies.",
            "anonymity",
            {"canvas_hash": browser.get("canvas_hash", "")[:16] + "..."},
        ))

    if not browser.get("audio_blocked"):
        score += 10.0
        findings.append(_finding(
            "AUDIO_EXPOSED", "MEDIUM",
            "Audio fingerprint collected",
            "AudioContext was not blocked. Hardware audio signature varies by GPU, OS, and driver version.",
            "anonymity",
            {"audio_hash": browser.get("audio_hash", "")[:16] + "..."},
        ))

    score = min(score, 100.0)
    return DimensionScore(name="anonymity", score=round(score, 2), findings=findings)


def score_network(browser: dict, headers: HeaderAnalysis,
                  remote_ip: str, ip_rep: IPReputation,
                  dns_leak: DNSLeakResult,
                  stun_ip_rep: IPReputation | None = None) -> DimensionScore:
    score = 0.0
    findings = []

    webrtc = browser.get("webrtc", {})
    if webrtc and not webrtc.get("webrtc_blocked"):
        local_ips = webrtc.get("local_ips", [])
        if local_ips:
            score += 40.0
            findings.append(_finding(
                "WEBRTC_LEAK", "CRITICAL",
                "WebRTC IP leak",
                "Your local network IP was exposed via WebRTC ICE candidates.",
                "network",
                {"local_ips": local_ips},
            ))

        stun_ip = webrtc.get("public_ip_via_stun")
        _server_is_local = remote_ip and _is_private_ip(remote_ip)
        _same_asn = (
            stun_ip_rep and stun_ip_rep.asn
            and ip_rep.asn
            and stun_ip_rep.asn == ip_rep.asn
        )
        if stun_ip and remote_ip and stun_ip != remote_ip and not _server_is_local and not _same_asn:
            score += 20.0
            findings.append(_finding(
                "WEBRTC_VPN_BYPASS", "HIGH",
                "WebRTC bypasses VPN",
                "Public IP via STUN differs from the IP observed by the server.",
                "network",
                {"stun_ip": stun_ip, "server_ip": remote_ip},
            ))

    if headers.lang_mismatch:
        score += 20.0
        findings.append(_finding(
            "HEADER_LANG_MISMATCH", "MEDIUM",
            "Language header mismatch",
            "Accept-Language header differs from navigator.language.",
            "network",
            {"accept_language": headers.lang_header,
             "navigator_language": headers.lang_navigator},
        ))

    nav = browser.get("navigator", {})
    nav_tz = nav.get("timezone")
    ip_tz  = ip_rep.timezone if ip_rep.available else None
    if nav_tz and ip_tz and nav_tz != ip_tz:
        nav_offset = _tz_offset(nav_tz)
        ip_offset  = _tz_offset(ip_tz)
        offsets_differ = (nav_offset is None or ip_offset is None or nav_offset != ip_offset)
    if nav_tz and ip_tz and nav_tz != ip_tz and offsets_differ:
        score += 20.0
        findings.append(_finding(
            "TIMEZONE_MISMATCH", "MEDIUM",
            "Timezone inconsistency",
            "JavaScript timezone does not match IP geolocation timezone.",
            "network",
            {"js_timezone": nav_tz, "ip_timezone": ip_tz},
        ))

    if dns_leak.available and dns_leak.leaked:
        leaked_isps = [r.isp for r in dns_leak.resolvers if not r.is_clean and r.isp]
        score += 30.0
        findings.append(_finding(
            "DNS_LEAK", "HIGH",
            "DNS resolver belongs to ISP",
            "Your DNS queries are handled by your ISP, not a private resolver.",
            "network",
            {
                "resolvers": [{"ip": r.ip, "isp": r.isp} for r in dns_leak.resolvers if not r.is_clean],
                "isps": leaked_isps,
            },
        ))

    score = min(score, 100.0)
    return DimensionScore(name="network", score=round(score, 2), findings=findings)


def score_data_exposure(browser: dict, hibp: HIBPResult | None = None) -> DimensionScore:
    score    = 0.0
    findings = []

    if not hibp:
        findings.append(_finding(
            "NO_EMAIL_CHECKED", "INFO",
            "No email checked",
            "No email was provided for breach check.",
            "data_exposure",
        ))
        return DimensionScore(name="data_exposure", score=0.0, findings=findings)

    if not hibp.available:
        findings.append(_finding(
            "NO_EMAIL_CHECKED", "INFO",
            "Breach check unavailable",
            "HIBP API key not configured. Set HIBP_API_KEY in .env (paid subscription at haveibeenpwned.com/API/Key).",
            "data_exposure",
        ))
        return DimensionScore(name="data_exposure", score=0.0, findings=findings)

    if hibp.breach_count == 0:
        findings.append(_finding(
            "EMAIL_CLEAN", "INFO",
            "No breaches found",
            "This email was not found in any known breach.",
            "data_exposure",
        ))
        return DimensionScore(name="data_exposure", score=0.0, findings=findings)

    score = min(hibp.breach_count * 12.0, 60.0)
    findings.append(_finding(
        "BREACH_FOUND", "HIGH",
        "Email found in breaches",
        f"This email appeared in {hibp.breach_count} known breach(es).",
        "data_exposure",
        {"breach_count": hibp.breach_count,
         "breaches": [b.get("Name") for b in hibp.breaches[:5]]},
    ))

    return DimensionScore(name="data_exposure", score=round(score, 2), findings=findings)


def score_ip_reputation(ip_rep: IPReputation) -> DimensionScore:
    score = 0.0
    findings = []

    if not ip_rep.available:
        findings.append(_finding(
            "API_UNAVAILABLE", "INFO",
            "IP reputation unavailable",
            "ip-api.com did not return a result for this IP.",
            "ip_reputation",
            {"ip": ip_rep.ip},
        ))
        return DimensionScore(name="ip_reputation", score=0.0, findings=findings)

#testing this logic n2
    if ip_rep.is_proxy:
        score += 10.0
        findings.append(_finding(
            "IP_PROXY", "LOW",
            "IP flagged as proxy/VPN",
            "ip-api.com flagged this IP as a proxy or VPN exit node.",
            "ip_reputation",
            {"ip": ip_rep.ip, "isp": ip_rep.isp},
        ))

    if ip_rep.is_hosting:
        score += 15.0
        findings.append(_finding(
            "IP_HOSTING", "LOW",
            "Datacenter or hosting IP",
            "This IP belongs to a datacenter or hosting provider.",
            "ip_reputation",
            {"ip": ip_rep.ip, "org": ip_rep.org},
        ))

    score = min(score, 100.0)
    return DimensionScore(name="ip_reputation", score=round(score, 2), findings=findings)
