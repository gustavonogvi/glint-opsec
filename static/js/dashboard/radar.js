const DIM_ORDER  = ["network", "anonymity", "data_exposure", "ip_reputation"];
const DIM_LABELS = ["Network", "Anonymity", "Data Exposure", "IP Reputation"];

const WEIGHTS = {
    network:       0.35,
    anonymity:     0.30,
    data_exposure: 0.25,
    ip_reputation: 0.10,
};

function scoreColor(score) {
    if (score >= 76) return "#ff3333";
    if (score >= 51) return "#ff8800";
    if (score >= 26) return "#ffff00";
    return "#00ff41";
}

export function renderRadar(data) {
    const dimMap = {};
    for (const d of data.dimensions) {
        dimMap[d.name] = d.score;
    }

    const scores = DIM_ORDER.map(name => dimMap[name] ?? 0);
    const color  = scoreColor(data.composite_score);

    const ctx = document.getElementById("radar-canvas");
    if (!ctx) return;

    new Chart(ctx, {
        type: "radar",
        data: {
            labels:   DIM_LABELS,
            datasets: [{
                data:            scores,
                backgroundColor: color + "22",
                borderColor:     color,
                borderWidth:     1.5,
                pointBackgroundColor: color,
                pointRadius:     3,
            }],
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                r: {
                    min: 0,
                    max: 100,
                    ticks: {
                        stepSize: 25,
                        display:  false,
                    },
                    grid: {
                        color: "#0d2b14",
                    },
                    angleLines: {
                        color: "#0d2b14",
                    },
                    pointLabels: {
                        color:    "#1a6630",
                        font:     { size: 10, family: "'Cascadia Code','Fira Code','Courier New',monospace" },
                    },
                },
            },
        },
    });

    _renderBars(data, dimMap);
}

function _renderBars(data, dimMap) {
    const container = document.getElementById("dim-bars");
    if (!container) return;

    const rows = DIM_ORDER.map((name, i) => {
        const score  = dimMap[name] ?? 0;
        const color  = scoreColor(score);
        const label  = DIM_LABELS[i];
        const weight = Math.round(WEIGHTS[name] * 100);
        return { score, color, label, weight };
    });

    container.innerHTML = rows.map(({ color, label, weight }) => `
<div class="dim-row">
    <span class="dim-name">${label} <span style="color:#2a7a3e;font-size:0.65rem;">${weight}%</span></span>
    <div class="dim-bar-bg">
        <div class="dim-bar-fill" style="width:0%;background:${color};"></div>
    </div>
    <span class="dim-score" style="color:${color}">0</span>
</div>`).join("");

    requestAnimationFrame(() => {
        const fills  = container.querySelectorAll(".dim-bar-fill");
        const scores = container.querySelectorAll(".dim-score");
        rows.forEach(({ score }, i) => {
            fills[i].style.width      = score + "%";
            scores[i].textContent     = score;
        });
    });
}
