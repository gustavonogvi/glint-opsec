# Per-signal entropy estimates (bits) — conservative, research-backed
_SIGNALS = {
    "canvas":          13.0,
    "audio":            7.0,
    "webgl_unmasked":   5.0,
    "webgl_masked":     2.0,
    "webgl_precision":  3.0,
    "fonts_high":       8.0,   # > 60 fonts
    "fonts_mid":        5.0,   # 30-60
    "fonts_low":        2.0,   # < 30
    "font_groups":      2.0,
    "timezone":         4.0,
    "platform":         1.0,
    "hw_concurrency":   1.5,
    "device_memory":    1.0,
    "screen":           3.0,
    "mdns":             8.0,
    "local_ip":         2.0,
}

# Each signal after the first contributes at this fraction (correlation discount)
_DISCOUNT = 0.65


def calculate(browser: dict) -> float:
    active: list[float] = []

    def add(key: str) -> None:
        active.append(_SIGNALS[key])

    canvas = browser.get("canvas_hash")
    if canvas and not browser.get("canvas_blocked"):
        add("canvas")

    audio = browser.get("audio_hash")
    if audio and not browser.get("audio_blocked"):
        add("audio")

    font_count = browser.get("font_count", 0)
    if font_count > 0 and not browser.get("fonts_blocked"):
        if font_count > 60:
            add("fonts_high")
        elif font_count > 30:
            add("fonts_mid")
        else:
            add("fonts_low")
        if len(browser.get("font_groups", [])) > 5:
            add("font_groups")

    webgl = browser.get("webgl", {})
    if webgl and not webgl.get("webgl_blocked"):
        if webgl.get("unmasked"):
            add("webgl_unmasked")
        elif webgl.get("renderer"):
            add("webgl_masked")
        if webgl.get("precision_hash"):
            add("webgl_precision")

    nav = browser.get("navigator", {})
    if nav:
        if nav.get("timezone"):
            add("timezone")
        if nav.get("platform"):
            add("platform")
        if nav.get("hardware_concurrency"):
            add("hw_concurrency")
        if nav.get("device_memory"):
            add("device_memory")

    screen = browser.get("screen", {})
    if screen and screen.get("screen_width"):
        add("screen")

    webrtc = browser.get("webrtc", {})
    if webrtc and not webrtc.get("webrtc_blocked"):
        if webrtc.get("mdns_hostnames"):
            add("mdns")
        elif webrtc.get("local_ips"):
            add("local_ip")

    if not active:
        return 0.0

    # sort descending so the highest-entropy signal comes first
    active.sort(reverse=True)

    total = active[0]
    for bits in active[1:]:
        total += bits * _DISCOUNT

    return round(total, 1)
