from dataclasses import dataclass, field


@dataclass
class Recommendation:
    finding_key: str
    priority: str
    title: str
    steps: list[str]
    references: list[str] = field(default_factory=list)


RULES: dict[str, Recommendation] = {
    "WEBRTC_LEAK": Recommendation(
        finding_key="WEBRTC_LEAK",
        priority="CRITICAL",
        title="Disable WebRTC IP leak",
        steps=[
            "Firefox: set media.peerconnection.enabled = false in about:config",
            "Chrome/Opera: install 'WebRTC Leak Prevent' extension",
            "Brave: Settings -> Privacy -> WebRTC IP handling -> Disable non-proxied UDP",
            "Verify fix at browserleaks.com/webrtc",
        ],
        references=["https://browserleaks.com/webrtc"],
    ),
    "WEBRTC_VPN_BYPASS": Recommendation(
        finding_key="WEBRTC_VPN_BYPASS",
        priority="HIGH",
        title="Fix WebRTC VPN bypass",
        steps=[
            "Enable WebRTC leak protection in your VPN client settings",
            "Or disable WebRTC entirely (see WEBRTC_LEAK recommendation)",
            "Confirm your VPN routes all traffic including UDP",
        ],
    ),
    "DNS_LEAK": Recommendation(
        finding_key="DNS_LEAK",
        priority="HIGH",
        title="Switch to a private DNS resolver",
        steps=[
            "Set DNS to 1.1.1.1 (Cloudflare) or 9.9.9.9 (Quad9) in network settings",
            "Enable DNS over HTTPS in your browser: Settings -> Privacy -> DNS over HTTPS",
            "Firefox: about:config -> network.trr.mode = 2 (DoH enabled)",
            "Verify at 1.1.1.1/help or dnsleaktest.com",
        ],
        references=["https://1.1.1.1/dns/"],
    ),
    "HEADER_LANG_MISMATCH": Recommendation(
        finding_key="HEADER_LANG_MISMATCH",
        priority="MEDIUM",
        title="Align browser language with Accept-Language header",
        steps=[
            "Set browser language to match your intended locale",
            "Or use a browser profile with consistent language settings",
            "Firefox: about:config -> intl.accept_languages",
        ],
    ),
    "TIMEZONE_MISMATCH": Recommendation(
        finding_key="TIMEZONE_MISMATCH",
        priority="MEDIUM",
        title="Align system timezone with VPN location",
        steps=[
            "Change system timezone to match your VPN exit node country",
            "Or use Tor Browser which normalizes timezone to UTC",
            "Firefox with resistFingerprinting also normalizes timezone",
        ],
    ),
    "WEBGL_SPECIFIC": Recommendation(
        finding_key="WEBGL_SPECIFIC",
        priority="MEDIUM",
        title="Reduce WebGL fingerprint exposure",
        steps=[
            "Firefox: set privacy.resistFingerprinting = true in about:config",
            "This blocks WEBGL_debug_renderer_info extension",
            "Brave: fingerprint protection is enabled by default in Shields",
        ],
    ),
    "CANVAS_EXPOSED": Recommendation(
        finding_key="CANVAS_EXPOSED",
        priority="HIGH",
        title="Block canvas fingerprinting",
        steps=[
            "Firefox: set privacy.resistFingerprinting = true in about:config",
            "Brave: Shields -> Fingerprinting -> Block all fingerprinting",
            "Chrome: install 'Canvas Fingerprint Defender' extension",
            "Tor Browser blocks canvas reads by default",
        ],
        references=["https://browserleaks.com/canvas"],
    ),
    "AUDIO_EXPOSED": Recommendation(
        finding_key="AUDIO_EXPOSED",
        priority="MEDIUM",
        title="Block AudioContext fingerprinting",
        steps=[
            "Firefox: privacy.resistFingerprinting also covers AudioContext",
            "Brave Shields blocks audio fingerprinting by default",
            "Safari 17+ injects noise into AudioContext in Private mode",
        ],
    ),
    "FONT_COUNT_HIGH": Recommendation(
        finding_key="FONT_COUNT_HIGH",
        priority="MEDIUM",
        title="Reduce font fingerprint surface",
        steps=[
            "Enable privacy.resistFingerprinting in Firefox to normalize font metrics",
            "Brave Shields blocks font enumeration by default",
            "Avoid installing unnecessary fonts from professional software suites",
        ],
    ),
    "BREACH_FOUND": Recommendation(
        finding_key="BREACH_FOUND",
        priority="HIGH",
        title="Act on exposed email breach",
        steps=[
            "Change passwords on all services where you use this email",
            "Enable two-factor authentication everywhere possible",
            "Use a unique password per service (password manager recommended)",
            "Consider creating a new email alias for sensitive accounts",
        ],
    ),
    "IP_ABUSE_HIGH": Recommendation(
        finding_key="IP_ABUSE_HIGH",
        priority="HIGH",
        title="Your IP has a high abuse score",
        steps=[
            "Contact your ISP or VPN provider about the flagged IP",
            "Switch to a different VPN server or exit node",
            "If using a shared hosting/VPN IP, consider a dedicated IP",
        ],
    ),
}


PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def generate(findings: list[dict]) -> list[dict]:
    seen = set()
    recommendations = []

    for finding in findings:
        key = finding.get("finding_key")
        if key in seen or key not in RULES:
            continue
        seen.add(key)
        rec = RULES[key]
        recommendations.append({
            "finding_key": rec.finding_key,
            "priority":    rec.priority,
            "title":       rec.title,
            "steps":       rec.steps,
            "references":  rec.references,
        })

    recommendations.sort(key=lambda r: PRIORITY_ORDER.get(r["priority"], 99))
    return recommendations
