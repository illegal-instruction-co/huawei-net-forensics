const API_BASE = '';

const $ = (s) => document.querySelector(s);

let mainChart = null;

function formatUptime(seconds) {
    if (!seconds) return "00:00:00";
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return [h, m, s].map(v => v.toString().padStart(2, '0')).join(':');
}

async function updateState() {
    try {
        const res = await fetch(`${API_BASE}/state`);
        const data = await res.json();

        $('#val-score').innerText = (data.score === undefined || data.score === null) ? "N/A" : data.score.toFixed(1);
        $('#val-speed').innerText = (data.down_mbps || 0).toFixed(1) + " Mbps";
        $('#val-lat').innerText = (data.latency_avg || 0).toFixed(0) + " ms";
        $('#val-jitter').innerText = (data.jitter || 0).toFixed(1) + " ms";
        $('#sys-uptime').innerText = formatUptime(data.uptime);

        const ramp = data.ramp_up_ratio || 1;
        const rampEl = $('#val-ramp');
        rampEl.innerText = ramp.toFixed(2) + "x";
        rampEl.style.color = ramp > 1.2 ? "var(--color-red)" : "var(--text-muted)";

        $('#meta-band').innerText = data.band || "N/A";
        $('#meta-pci').innerText = data.pci || "--";
        $('#meta-enodeb').innerText = data.enodeb || "--";

        const rProb = (data.radio_prob || 0) * 100;
        const cProb = (data.congestion_prob || 0) * 100;
        const pProb = (data.policy_prob || 0) * 100;

        $('#prob-radio-val').innerText = rProb.toFixed(0) + "%";
        $('#prob-radio-bar').style.width = rProb + "%";
        $('#prob-cong-val').innerText = cProb.toFixed(0) + "%";
        $('#prob-cong-bar').style.width = cProb + "%";
        $('#prob-policy-val').innerText = pProb.toFixed(0) + "%";
        $('#prob-policy-bar').style.width = pProb + "%";

        const vBox = $('#verdict-display');
        let verdict = "INCONCLUSIVE / GATHERING DATA";
        let subVerdict = "No dominant explanation detected in current window.";
        let color = "var(--text-muted)";
        let borderColor = "var(--color-border)";

        if (pProb > 50) {
            verdict = "POLICY-LIKE PATTERN DETECTED";
            subVerdict = "Sustained throughput ceiling or shaping observed.";
            color = "var(--color-orange)";
            borderColor = "var(--color-orange)";
        } else if (cProb > 50) {
            verdict = "CONGESTION INDICATORS PRESENT";
            subVerdict = "High jitter/latency under load.";
            color = "var(--color-orange)";
            borderColor = "var(--color-orange)";
        } else if (rProb > 50) {
            verdict = "RADIO IMPAIRMENT LIKELY";
            subVerdict = "Signal quality issues dominating performance.";
            color = "var(--color-cyan)";
            borderColor = "var(--color-cyan)";
        }

        vBox.innerHTML = `<div style="font-size:14px; font-weight:bold;">${verdict}</div><div style="font-size:10px; opacity:0.7; margin-top:5px;">${subVerdict}</div>`;
        vBox.style.color = color;
        vBox.style.borderColor = borderColor;

    } catch (e) {
        console.error("State fetch failed", e);
    }
}

async function updateDashboard() {
    try {
        const res = await fetch(`${API_BASE}/history?limit=1000`);
        const json = await res.json();
        const fullData = (json.data || []).reverse();


        const recentData = fullData.slice(-100);
        updateMainChart(recentData);

        drawHeatmap(fullData);

        updateAccountabilityLog(fullData);

    } catch (e) {
        console.error("Dashboard update failed", e);
    }
}

function updateMainChart(data) {
    const ctx = document.getElementById('mainChart').getContext('2d');
    const labels = data.map(d => new Date(d.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));

    const rfData = data.map(d => Number.parseFloat(d.avg_score || d.score || 0));
    const speedData = data.map(d => Number.parseFloat(d.down_mbps || 0));
    const psiData = data.map(d => Number.parseFloat(d.psi || 0));

    if (mainChart) {
        mainChart.data.labels = labels;
        mainChart.data.datasets[0].data = rfData;
        mainChart.data.datasets[1].data = speedData;
        mainChart.data.datasets[2].data = psiData;
        mainChart.update();
    } else {
        mainChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'RF Signal (0-100)',
                        data: rfData,
                        borderColor: '#00f0ff',
                        backgroundColor: 'rgba(0, 240, 255, 0.1)',
                        borderWidth: 2,
                        tension: 0.4,
                        pointRadius: 0
                    },
                    {
                        label: 'Throughput (Mbps)',
                        data: speedData,
                        borderColor: '#00ff9d',
                        backgroundColor: 'rgba(0, 255, 157, 0.1)',
                        borderWidth: 2,
                        tension: 0.4,
                        pointRadius: 0
                    },
                    {
                        label: 'PSI (Abuse Index)',
                        data: psiData,
                        borderColor: '#ff9500',
                        backgroundColor: 'rgba(255, 149, 0, 0.2)',
                        borderWidth: 2,
                        tension: 0.4,
                        fill: true,
                        pointRadius: 0
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                scales: {
                    x: { display: false },
                    y: {
                        max: 100,
                        min: 0,
                        grid: { color: '#30363d' },
                        ticks: { color: '#8b949e' }
                    }
                },
                plugins: {
                    legend: { labels: { color: '#c9d1d9', font: { family: 'JetBrains Mono' } } },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        backgroundColor: 'rgba(0,0,0,0.8)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        borderColor: '#333',
                        borderWidth: 1
                    }
                },
                animation: false
            }
        });
    }
}

function drawHeatmap(data) {
    const canvas = document.getElementById('heatmapChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const map = {};
    const days = new Set();

    data.forEach(d => {
        const dt = new Date(d.timestamp);
        const dayKey = dt.toLocaleDateString([], { month: 'numeric', day: 'numeric' });
        const hour = dt.getHours();
        const key = `${dayKey}-${hour}`;

        days.add(dayKey);
        if (!map[key]) map[key] = [];
        map[key].push(Number.parseFloat(d.psi || 0));
    });

    const sortedDays = Array.from(days).slice(-5);

    const w = canvas.width = canvas.parentElement.offsetWidth;
    const h = canvas.height = canvas.parentElement.offsetHeight;

    ctx.clearRect(0, 0, w, h);

    const marginL = 40;
    const marginB = 20;
    const cellW = (w - marginL) / 24;
    const cellH = (h - marginB) / (sortedDays.length || 1);

    ctx.font = "10px JetBrains Mono";
    ctx.fillStyle = "#8b949e";

    for (let i = 0; i < 24; i += 2) {
        ctx.fillText(i, marginL + (i * cellW) + 5, h - 5);
    }

    sortedDays.forEach((day, rowIdx) => {
        ctx.fillStyle = "#8b949e";
        ctx.fillText(day, 5, (rowIdx * cellH) + (cellH / 1.5));

        for (let hr = 0; hr < 24; hr++) {
            const key = `${day}-${hr}`;
            const vals = map[key];
            let color = "#161b22";

            if (vals && vals.length > 0) {
                const avg = vals.reduce((a, b) => a + b, 0) / vals.length;
                if (avg < 20) color = "#0d1117";
                else if (avg < 40) color = "#1f6feb";
                else if (avg < 60) color = "#238636";
                else if (avg < 80) color = "#d29922";
                else color = "#da3633";
            }

            ctx.fillStyle = color;
            ctx.fillRect(marginL + (hr * cellW), rowIdx * cellH, cellW - 2, cellH - 2);
        }
    });
}

function updateAccountabilityLog(data) {
    const tbody = $('#accountability-log');
    tbody.innerHTML = '';

    const anomalies = data.filter(d => (d.psi > 50) || (d.policy_prob > 0.5)).reverse().slice(0, 20);

    if (anomalies.length === 0) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="3" style="text-align:center; color:#555; padding:10px;">NO ANOMALIES DETECTED</td>`;
        tbody.appendChild(tr);
        return;
    }

    anomalies.forEach(d => {
        const tr = document.createElement('tr');
        tr.style.borderBottom = "1px solid #222";
        const time = new Date(d.timestamp).toLocaleTimeString();
        let event;
        let color;

        if (d.policy_prob > 0.5) { event = "POLICY-LIKE PATTERN"; color = "var(--color-orange)"; }
        else if (d.congestion_prob > 0.5) { event = "CONGESTION PATTERN"; color = "var(--color-orange)"; }
        else if (d.psi > 80) { event = "ELEVATED PSI"; color = "var(--color-orange)"; }
        else { event = "SUSPICIOUS ACTIVITY"; color = "#ffd700"; }

        tr.innerHTML = `
            <td style="padding: 5px; font-size: 11px; color: #888;">${time}</td>
            <td style="padding: 5px; font-size: 11px; color: ${color};">${event}</td>
            <td style="padding: 5px; font-size: 11px;">PSI: ${d.psi}</td>
        `;
        tbody.appendChild(tr);
    });
}

setInterval(updateState, 1000);
setInterval(updateDashboard, 5000);

await updateState();
await updateDashboard();
