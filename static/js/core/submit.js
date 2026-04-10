import { collectFingerprint } from "./fingerprint.js";

function log(message, color) {
    const logs = document.getElementById("logs");
    if (!logs) {
        return;
    }
    const line = document.createElement("p");
    line.style.margin = "0.15rem 0";
    if (color) {
        line.style.color = color;
    }
    line.textContent = "> " + message;
    logs.appendChild(line);
    logs.parentElement.scrollTop = logs.scrollHeight;
}

function setStatus(message, color) {
    const el = document.getElementById("scan-status");
    if (!el) {
        return;
    }
    el.textContent = message;
    if (color) {
        el.style.color = color;
    }
}

async function run() {
    log("initializing collectors...");
    setStatus("[ SCANNING ]");

    try {
        log("canvas fingerprint...");
        log("audio fingerprint...");
        log("font enumeration...");
        log("navigator metadata...");
        log("screen geometry...");
        log("webrtc ip probe...");
        log("webgl precision hash...");

        const browser = await collectFingerprint();

        log("payload assembled — transmitting...", "#fa5");
        setStatus("[ TRANSMITTING ]", "#fa5");

        const response = await fetch("/api/fingerprint", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ browser: browser }),
        });

        if (!response.ok) {
            log("server error: " + response.status, "#f55");
            setStatus("[ ERROR ]", "#f55");
            return;
        }

        const result = await response.json();
        log("scan complete — redirecting...", "#5f5");
        setStatus("[ COMPLETE ]", "#5f5");
        window.location.href = "/results/" + result.scan_id;

    } catch (err) {
        log("fatal: " + err.message, "#f55");
        setStatus("[ ERROR ]", "#f55");
    }
}

document.addEventListener("DOMContentLoaded", run);
