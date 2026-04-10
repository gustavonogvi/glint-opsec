const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

export function renderFindings(data) {
    _renderFindingCards(data.findings);
    _renderRecommendations(data.recommendations);
    _renderServerObserved(data.server_observed);
}

function _renderFindingCards(findings) {
    const container = document.getElementById("findings-list");
    if (!container) return;

    const sorted = [...findings].sort(
        (a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
    );

    if (sorted.length === 0) {
        container.innerHTML = '<p style="color:#2a2a2a;font-size:0.75rem;">no findings</p>';
        return;
    }

    container.innerHTML = sorted.map((f, i) => {
        const evidenceText = Object.keys(f.evidence || {}).length > 0
            ? JSON.stringify(f.evidence, null, 2)
            : "";
        const delay = (i * 60) + "ms";

        return `
<div class="finding-card border-${f.severity}" style="animation-delay:${delay}">
    <div class="finding-card-header">
        <span class="badge badge-${f.severity}">${f.severity}</span>
        <span class="finding-title">${_esc(f.title)}</span>
    </div>
    <div class="finding-desc">${_esc(f.description)}</div>
    ${evidenceText ? `<pre class="finding-evidence">${_esc(evidenceText)}</pre>` : ""}
</div>`;
    }).join("");
}

function _renderRecommendations(recommendations) {
    const container = document.getElementById("recommendations-list");
    if (!container) return;

    if (!recommendations || recommendations.length === 0) {
        container.innerHTML = '<p style="color:#2a2a2a;font-size:0.75rem;">no recommendations</p>';
        return;
    }

    container.innerHTML = recommendations.map(rec => {
        const steps = (rec.steps || []).map(
            s => `<li>${_esc(s)}</li>`
        ).join("");

        const refs = (rec.references || []).map(
            r => `<a href="${_esc(r)}" target="_blank" rel="noopener noreferrer" style="font-size:0.68rem;color:#333;">${_esc(r)}</a>`
        ).join("  ");

        return `
<div class="rec-card">
    <div class="rec-title">
        <span class="badge badge-${rec.priority}">${rec.priority}</span>
        <span>${_esc(rec.title)}</span>
    </div>
    <ul class="rec-steps">${steps}</ul>
    ${refs ? `<div style="margin-top:0.5rem;">${refs}</div>` : ""}
</div>`;
    }).join("");
}

function _renderServerObserved(observed) {
    const container = document.getElementById("server-observed");
    if (!container || !observed) return;

    const rows = [
        ["remote_ip",   observed.remote_ip],
        ["user_agent",  observed.user_agent],
        ["country",     observed.ip_reputation?.country],
        ["isp",         observed.ip_reputation?.isp],
        ["is_proxy",    observed.ip_reputation?.is_proxy],
        ["is_hosting",  observed.ip_reputation?.is_hosting],
        ["timezone",    observed.ip_reputation?.timezone],
        ["accept_lang", observed.header_analysis?.accept_language],
        ["lang_match",  observed.header_analysis?.lang_mismatch === true ? "mismatch ⚠" : "ok"],
    ];

    container.innerHTML = `<div class="observed-grid">${
        rows.filter(([, v]) => v !== undefined && v !== null && v !== "")
            .map(([k, v]) => `<span class="obs-key">${_esc(k)}</span><span class="obs-val">${_esc(String(v))}</span>`)
            .join("")
    }</div>`;
}

function _esc(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}
