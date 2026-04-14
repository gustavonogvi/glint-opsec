import { collectFingerprint } from "./fingerprint.js";

function log(message, color) {
    const logs = document.getElementById("logs");
    if (!logs) return;
    const line = document.createElement("p");
    line.style.margin = "0.1rem 0";
    if (color) line.style.color = color;
    line.textContent = "> " + message;
    logs.appendChild(line);
    logs.parentElement.scrollTop = logs.scrollHeight;
}

function setStatus(message, color) {
    const el = document.getElementById("scan-status");
    if (!el) return;
    el.textContent = message;
    if (color) el.style.color = color;
}

function trunc(str, len) {
    if (!str) return "—";
    return String(str).length > len ? String(str).slice(0, len) + "…" : String(str);
}

function onProgress(name, result) {
    switch (name) {
        case "canvas":
            if (result.canvas_blocked) {
                log("canvas        [BLOCKED]", "#004d18");
            } else {
                log("canvas        " + trunc(result.canvas_hash, 16) + "  [fingerprinted]");
            }
            break;

        case "audio":
            if (result.audio_blocked) {
                log("audio         [BLOCKED]", "#004d18");
            } else {
                log("audio         " + trunc(result.audio_hash, 16) + "  [fingerprinted]");
            }
            break;

        case "fonts": {
            const count  = result.font_count || 0;
            const sample = (result.fonts || []).slice(0, 3).join(", ");
            const more   = count > 3 ? " +" + (count - 3) + " more" : "";
            if (result.fonts_blocked) {
                log("fonts         [BLOCKED]", "#004d18");
            } else {
                log("fonts         " + count + " detected — " + sample + more);
            }
            break;
        }

        case "navigator": {
            const lang = result.language || "?";
            const plat = result.platform || "?";
            const cpu  = result.hardware_concurrency || "?";
            const mem  = result.device_memory ? result.device_memory + "GB" : "?";
            const tz   = result.timezone || "?";
            log("navigator     " + lang + " · " + plat + " · " + cpu + " cores · " + mem);
            log("              tz: " + tz, "#007a22");
            break;
        }

        case "screen": {
            const sw  = result.screen_width || "?";
            const sh  = result.screen_height || "?";
            const ww  = result.window_inner_width || "?";
            const wh  = result.window_inner_height || "?";
            const dpr = result.device_pixel_ratio || "?";
            log("screen        " + sw + "×" + sh + " · window " + ww + "×" + wh + " · dpr " + dpr);
            break;
        }

        case "webrtc": {
            if (result.webrtc_blocked) {
                log("webrtc        [BLOCKED]", "#004d18");
                break;
            }
            const local  = (result.local_ips || []);
            const pub    = result.public_ip_via_stun;
            if (local.length > 0) {
                log("webrtc        local: " + local.join(", "), "#ff8800");
            } else {
                log("webrtc        no local ip leak", "#007a22");
            }
            if (pub) {
                log("              public: " + pub, "#007a22");
            }
            break;
        }

        case "webgl": {
            if (result.webgl_blocked) {
                log("webgl         [BLOCKED]", "#004d18");
                break;
            }
            const renderer = result.renderer || result.vendor || "unknown";
            const masked   = result.unmasked ? "[unmasked]" : "[masked]";
            log("webgl         " + trunc(renderer, 40) + "  " + masked,
                result.unmasked ? "#00cc33" : "#007a22");
            if (result.precision_hash) {
                log("              precision: " + trunc(result.precision_hash, 16), "#007a22");
            }
            break;
        }
    }
}

async function run(email) {
    log("initializing collectors...", "#007a22");
    setStatus("[ SCANNING ]");

    try {
        const browser = await collectFingerprint(onProgress);

        log("─────────────────────────────────", "#004d18");
        log("payload assembled — transmitting...", "#00ff41");
        setStatus("[ TRANSMITTING ]", "#00ff41");

        const payload = { browser };
        if (email) payload.email = email;

        const response = await fetch("/api/fingerprint", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify(payload),
        });

        if (!response.ok) {
            log("server error: " + response.status, "#ff3333");
            setStatus("[ ERROR ]", "#ff3333");
            return;
        }

        const result = await response.json();
        log("analysis complete · score: " + result.composite_score + " [" + result.risk_level + "]",
            result.risk_level === "CRITICAL" ? "#ff3333" :
            result.risk_level === "HIGH"     ? "#ff8800" :
            result.risk_level === "MEDIUM"   ? "#ffff00" : "#00ff41");
        setStatus("[ COMPLETE ]", "#00ff41");
        window.location.href = "/results/" + result.scan_id;

    } catch (err) {
        log("fatal: " + err.message, "#ff3333");
        setStatus("[ ERROR ]", "#ff3333");
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const btn   = document.getElementById("scan-btn");
    const input = document.getElementById("email-input");
    const form  = document.getElementById("email-form");
    const logArea = document.getElementById("log-area");

    if (btn) {
        btn.addEventListener("click", () => {
            const email = input ? input.value.trim() : "";
            if (form)    form.style.display    = "none";
            if (logArea) logArea.style.display = "block";
            run(email);
        });
    }
});
