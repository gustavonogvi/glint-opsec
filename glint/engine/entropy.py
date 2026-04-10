import math


def _bits(probability: float) -> float:
    if probability <= 0 or probability >= 1:
        return 0.0
    return -math.log2(probability)


def calculate(browser: dict) -> float:
    total = 0.0

    canvas = browser.get("canvas_hash")
    if canvas and not browser.get("canvas_blocked"):
        total += _bits(1 / 1_000_000)

    audio = browser.get("audio_hash")
    if audio and not browser.get("audio_blocked"):
        total += _bits(1 / 500_000)

    font_count = browser.get("font_count", 0)
    if font_count > 0:
        font_groups = browser.get("font_groups", [])
        if font_count > 60:
            total += _bits(1 / 10_000)
        elif font_count > 30:
            total += _bits(1 / 1_000)
        else:
            total += _bits(1 / 100)

        if len(font_groups) > 5:
            total += _bits(1 / 100)

    webgl = browser.get("webgl", {})
    if webgl and not webgl.get("webgl_blocked"):
        if webgl.get("unmasked"):
            total += _bits(1 / 500_000)
        elif webgl.get("renderer"):
            total += _bits(1 / 10_000)

        if webgl.get("precision_hash"):
            total += _bits(1 / 100_000)

    nav = browser.get("navigator", {})
    if nav:
        if nav.get("hardware_concurrency"):
            total += _bits(1 / 8)
        if nav.get("device_memory"):
            total += _bits(1 / 6)
        if nav.get("platform"):
            total += _bits(1 / 4)
        if nav.get("timezone"):
            total += _bits(1 / 400)

    screen = browser.get("screen", {})
    if screen:
        if screen.get("screen_width") and screen.get("screen_height"):
            total += _bits(1 / 50)
        if screen.get("pixel_ratio") and screen.get("pixel_ratio") != 1.0:
            total += _bits(1 / 5)

    webrtc = browser.get("webrtc", {})
    if webrtc and not webrtc.get("webrtc_blocked"):
        local_ips = webrtc.get("local_ips", [])
        if local_ips:
            total += _bits(1 / 1_000)
        mdns = webrtc.get("mdns_hostnames", [])
        if mdns:
            total += _bits(1 / 1_000_000)

    return round(total, 2)
