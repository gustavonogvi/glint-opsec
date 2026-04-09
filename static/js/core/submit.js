import { collectFingerprint } from "./fingerprint.js";

function setStatus(message) {
    const el = document.getElementById("scan-status");
    if (el) {
        el.textContent = message;
    }
}

async function run() {
    try {
        setStatus("collecting...");
        const browser = await collectFingerprint();

        setStatus("analyzing...");
        const response = await fetch("/api/fingerprint", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ browser: browser }),
        });

        if (!response.ok) {
            setStatus("server error — check console");
            console.error("POST /api/fingerprint failed:", response.status);
            return;
        }

        const result = await response.json();
        window.location.href = "/results/" + result.scan_id;

    } catch (err) {
        setStatus("collection failed — check console");
        console.error(err);
    }
}

document.addEventListener("DOMContentLoaded", run);
