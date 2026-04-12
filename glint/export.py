"""
Generates a plain-text assessment report from a scan result.
"""

import json
from datetime import datetime, timezone

BAR_WIDTH = 28
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
WEIGHTS   = {"network": 35, "anonymity": 30, "data_exposure": 25, "ip_reputation": 10}
LINE      = "-" * 80


def _bar(score: float) -> str:
    filled = round((score / 100) * BAR_WIDTH)
    return "#" * filled + "." * (BAR_WIDTH - filled)


def _fmt_ts(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S") + " UTC"
    except Exception:
        return ts


def generate(scan_id: str, created_at: str, ip_address: str,
             user_agent: str, raw_payload: dict, result: dict) -> str:
    lines: list[str] = []
    out = lines.append

    obs  = result.get("server_observed") or {}
    ip   = obs.get("ip_reputation") or {}
    hdr  = obs.get("header_analysis") or {}
    b    = (raw_payload.get("browser") or {})
    nav  = b.get("navigator") or {}
    scr  = b.get("screen") or {}
    wgl  = b.get("webgl") or {}
    wrt  = b.get("webrtc") or {}

    # ── header ────────────────────────────────────────────────────────────────
    out("=" * 80)
    out("GLINT - DIGITAL FOOTPRINT ASSESSMENT REPORT")
    out("=" * 80)
    out("")
    out(f"SCAN ID        : {scan_id}")
    out(f"ASSESSED       : {_fmt_ts(created_at)}")
    out(f"SUBJECT IP     : {ip_address}")
    out(f"USER AGENT     : {user_agent}")
    if ip.get("country"):
        out(f"COUNTRY        : {ip['country']}")
    if ip.get("isp"):
        out(f"ISP            : {ip['isp']}")
    out("")
    out(LINE)
    out("")

    # ── threat index ──────────────────────────────────────────────────────────
    score = result.get("composite_score", 0)
    level = result.get("risk_level", "UNKNOWN")
    out(f"THREAT INDEX   : {score:.2f} / 100")
    out(f"CLASSIFICATION : {level}")
    entropy = result.get("identity_entropy_score")
    if entropy is not None:
        out(f"ENTROPY        : {entropy:.1f} bits")
    out("")
    out(LINE)
    out("")

    # ── dimensional analysis ──────────────────────────────────────────────────
    out("SECTION 01 - DIMENSIONAL ANALYSIS")
    out("")
    dim_map = {d["name"]: d["score"] for d in result.get("dimensions", [])}
    for name in ["network", "anonymity", "data_exposure", "ip_reputation"]:
        s   = dim_map.get(name, 0)
        wt  = WEIGHTS.get(name, 0)
        bar = _bar(s)
        out(f"  {name:<16}  {bar}  {s:>3}  wt {wt}%")
    out("")
    out(LINE)
    out("")

    # ── findings ──────────────────────────────────────────────────────────────
    findings = sorted(
        result.get("findings", []),
        key=lambda f: SEV_ORDER.get(f.get("severity", "INFO"), 99),
    )
    out(f"SECTION 02 - FINDINGS [{len(findings)}]")
    out("")
    if not findings:
        out("  no findings recorded")
    for i, f in enumerate(findings, 1):
        out(f"  [{i:02d}] {f.get('severity','?'):<10}  {f.get('finding_key','?')}")
        out(f"        {f.get('title','')}")
        out(f"        {f.get('description','')}")
        ev = f.get("evidence") or {}
        if ev:
            out(f"        evidence: {json.dumps(ev)}")
        out("")
    out(LINE)
    out("")

    # ── hardening ─────────────────────────────────────────────────────────────
    recs = result.get("recommendations", [])
    out(f"SECTION 03 - HARDENING DIRECTIVES [{len(recs)}]")
    out("")
    if not recs:
        out("  no directives")
    for i, r in enumerate(recs, 1):
        out(f"  [{i:02d}] {r.get('priority','?'):<10}  {r.get('title','')}")
        for step in r.get("steps", []):
            out(f"        - {step}")
        for ref in r.get("references", []):
            out(f"        ref: {ref}")
        out("")
    out(LINE)
    out("")

    # ── server intelligence ───────────────────────────────────────────────────
    out("SECTION 04 - SERVER INTELLIGENCE")
    out("")
    fields = [
        ("remote_ip",   obs.get("remote_ip")),
        ("user_agent",  obs.get("user_agent")),
        ("country",     ip.get("country")),
        ("isp",         ip.get("isp")),
        ("org",         ip.get("org")),
        ("timezone",    ip.get("timezone")),
        ("is_proxy",    ip.get("is_proxy")),
        ("is_hosting",  ip.get("is_hosting")),
        ("accept_lang", hdr.get("accept_language")),
        ("lang_match",  "mismatch" if hdr.get("lang_mismatch") else "ok"),
    ]
    for k, v in fields:
        if v not in (None, "", "unknown"):
            out(f"  {k:<16}  {v}")
    out("")
    out(LINE)
    out("")

    # ── raw collector data ────────────────────────────────────────────────────
    out("SECTION 05 - RAW COLLECTOR DATA")
    out("")

    # navigator
    out("  navigator:")
    for k in ["user_agent","language","platform","hardware_concurrency",
              "device_memory","timezone","max_touch_points","plugin_count"]:
        v = nav.get(k)
        if v not in (None, ""):
            out(f"    {k:<24}  {v}")
    out("")

    # screen
    out("  screen:")
    for k in ["screen_width","screen_height","window_inner_width",
              "window_inner_height","device_pixel_ratio","color_depth","orientation"]:
        v = scr.get(k)
        if v not in (None, ""):
            out(f"    {k:<24}  {v}")
    out("")

    # canvas / audio
    out(f"  canvas_hash     : {b.get('canvas_hash') or 'blocked'}")
    out(f"  audio_hash      : {b.get('audio_hash')  or 'blocked'}")
    out("")

    # webgl
    out("  webgl:")
    for k in ["vendor","renderer","version","unmasked","precision_hash"]:
        v = wgl.get(k)
        if v not in (None, ""):
            out(f"    {k:<24}  {v}")
    out("")

    # webrtc
    out("  webrtc:")
    local_ips = wrt.get("local_ips") or []
    if local_ips:
        for entry in local_ips:
            if isinstance(entry, dict):
                out(f"    local_ip  {entry.get('ip','')}  ({entry.get('type','')})")
            else:
                out(f"    local_ip  {entry}")
    else:
        out("    local_ips  none")
    stun = wrt.get("public_ip_via_stun")
    if stun:
        out(f"    stun_ip   {stun}")
    out("")

    # fonts
    fonts = b.get("fonts") or []
    out(f"  fonts [{b.get('font_count', len(fonts))} detected]:")
    if fonts:
        out("    " + ", ".join(fonts))
    out("")

    out(LINE)
    out("")
    out("END OF REPORT")
    out("=" * 80)

    report = "\n".join(lines)
    # normalize any non-ASCII that may be stored in older scan records
    report = report.replace("\u2192", "->").replace("\u2014", "--").replace("\u2013", "-")
    report = report.encode("ascii", errors="replace").decode("ascii")
    return report
