

const API_BASE = "http://127.0.0.1:8000";

let trafficChart = null;

// Safely display values inside HTML
function escapeHTML(value) {
    return String(value ?? "N/A").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[char]);
}

// Fetch data from API
async function fetchAPI(endpoint) {
    const response = await fetch(`${API_BASE}${endpoint}`);

    if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
    }

    return await response.json();
}

// Format timestamps
function formatTime(timestamp) {
    if (!timestamp) return "N/A";

    const date = new Date(timestamp.replace(" ", "T"));

    if (isNaN(date.getTime())) return escapeHTML(timestamp);

    return date.toLocaleString();
}

// Update system connection status
async function updateStatus() {
    const statusElement = document.getElementById("systemStatus");

    try {
        await fetchAPI("/health");
        statusElement.textContent = "API Connected";
        statusElement.style.color = "#22c55e";
    } catch (error) {
        statusElement.textContent = "API Disconnected";
        statusElement.style.color = "#f87171";
    }
}

// Update summary cards
async function updateSummary() {
    const data = await fetchAPI("/api/summary");

    document.getElementById("totalPackets").textContent =
        data.total_packets ?? 0;

    document.getElementById("totalAlerts").textContent =
        data.total_alerts ?? 0;

    document.getElementById("totalDevices").textContent =
        data.total_devices ?? 0;

    document.getElementById("totalEvents").textContent =
        data.total_system_events ?? 0;
}

// Update network traffic table
async function updateTraffic() {
    const data = await fetchAPI("/api/traffic?limit=20");

    const table = document.getElementById("trafficTable");

    if (!data.length) {
        table.innerHTML =
            '<tr><td colspan="6">No traffic records found</td></tr>';
        return;
    }

    table.innerHTML = data.map(packet => `
        <tr>
            <td>${formatTime(packet.timestamp)}</td>
            <td>${escapeHTML(packet.src_ip)}</td>
            <td>${escapeHTML(packet.dst_ip)}</td>
            <td>${escapeHTML(packet.protocol)}</td>
            <td>${escapeHTML(packet.src_port)}</td>
            <td>${escapeHTML(packet.dst_port)}</td>
        </tr>
    `).join("");

    updateTrafficChart(data);
}

// Update traffic chart
function updateTrafficChart(data) {
    const counts = {};

    data.forEach(packet => {
        const protocol = packet.protocol || "OTHER";
        counts[protocol] = (counts[protocol] || 0) + 1;
    });

    const labels = Object.keys(counts);
    const values = Object.values(counts);

    const context = document.getElementById("trafficChart");

    if (trafficChart) {
        trafficChart.destroy();
    }

    trafficChart = new Chart(context, {
        type: "bar",
        data: {
            labels: labels,
            datasets: [{
                label: "Packets by Protocol",
                data: values,
                backgroundColor: "#38bdf8",
                borderColor: "#0ea5e9",
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: {
                        color: "#e2e8f0"
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: "#cbd5e1" },
                    grid: { color: "#263449" }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: "#cbd5e1",
                        precision: 0
                    },
                    grid: { color: "#263449" }
                }
            }
        }
    });
}

// Update security alerts
async function updateAlerts() {
    const data = await fetchAPI("/api/alerts?limit=20");

    const table = document.getElementById("alertsTable");

    if (!data.length) {
        table.innerHTML =
            '<tr><td colspan="5">No security alerts found</td></tr>';
        return;
    }

    table.innerHTML = data.map(alert => {
        const severity = String(alert.severity || "LOW").toLowerCase();

        return `
            <tr>
                <td>${formatTime(alert.timestamp)}</td>
                <td>${escapeHTML(alert.alert_type || alert.alert_type_name || "N/A")}</td>
                <td class="severity-${escapeHTML(severity)}">
                    ${escapeHTML(alert.severity)}
                </td>
                <td>${escapeHTML(alert.source_ip)}</td>
                <td>${escapeHTML(alert.destination_ip)}</td>
            </tr>
        `;
    }).join("");
}

// Update observed IP endpoints
async function updateDevices() {
    const data = await fetchAPI("/api/devices");

    const table = document.getElementById("devicesTable");

    if (!data.length) {
        table.innerHTML =
            '<tr><td colspan="4">No endpoints found</td></tr>';
        return;
    }

    table.innerHTML = data.map(device => `
        <tr>
            <td>${escapeHTML(device.ip_address)}</td>
            <td>${escapeHTML(device.mac_address)}</td>
            <td>${escapeHTML(device.hostname)}</td>
            <td>${formatTime(device.last_seen)}</td>
        </tr>
    `).join("");
}

// Update system events
async function updateEvents() {
    const data = await fetchAPI("/api/events?limit=20");

    const table = document.getElementById("eventsTable");

    if (!data.length) {
        table.innerHTML =
            '<tr><td colspan="4">No system events found</td></tr>';
        return;
    }

    table.innerHTML = data.map(event => `
        <tr>
            <td>${formatTime(event.timestamp)}</td>
            <td>${escapeHTML(event.event_type)}</td>
            <td>${escapeHTML(event.severity)}</td>
            <td>${escapeHTML(event.message)}</td>
        </tr>
    `).join("");
}

// Refresh all dashboard sections
async function refreshDashboard() {
    await updateStatus();

    const results = await Promise.allSettled([
        updateSummary(),
        updateTraffic(),
        updateAlerts(),
        updateDevices(),
        updateEvents()
    ]);

    results.forEach((result, index) => {
        if (result.status === "rejected") {
            console.error(`Dashboard section ${index + 1} failed:`,
                result.reason);
        }
    });
}

// Start dashboard
document.addEventListener("DOMContentLoaded", () => {
    refreshDashboard();

    // Refresh data every 5 seconds
    setInterval(refreshDashboard, 5000);
});

