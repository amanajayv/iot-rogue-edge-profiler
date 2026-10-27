// ==========================================
// SHARED UTILITIES
// ==========================================
function togglePassword() {
    const pwd = document.getElementById('password');
    if (pwd) {
        pwd.type = pwd.type === 'password' ? 'text' : 'password';
    }
}

function disconnectUser() {
    window.location.href = '/';
}

// ==========================================
// LOGIN PAGE LOGIC
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            
            try {
                const response = await fetch('/api/login', { method: 'POST', body: formData });
                if (response.ok) {
                    localStorage.setItem('soc_user', formData.get('username')); 
                    window.location.href = '/dashboard';
                } else {
                    document.getElementById('error-msg').classList.remove('hidden');
                }
            } catch (err) {
                console.error("Login request failed:", err);
            }
        });
    }
});

// ==========================================
// DASHBOARD PAGE LOGIC
// ==========================================
let globalAlerts = [];

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
        sidebar.classList.toggle('w-64');
        sidebar.classList.toggle('w-20');
    }
}

function switchTab(viewId, btnElement = null) {
    const views = ['dashboard', 'devices', 'device-detail', 'upload'];
    views.forEach(v => {
        const el = document.getElementById(`view-${v}`);
        if (el) el.classList.add('hidden');
    });
    
    const targetView = document.getElementById(`view-${viewId}`);
    if (targetView) targetView.classList.remove('hidden');
    
    if (btnElement) {
        document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
        btnElement.classList.add('active');
    }
}

function openDeviceDetail(deviceName) {
    document.getElementById('detail-title').innerText = deviceName;
    const deviceAlerts = globalAlerts.filter(alert => alert.description.split(':')[0].trim() === deviceName);
    document.getElementById('detail-count').innerText = `${deviceAlerts.length} Persistent Threats`;
    
    const tbody = document.getElementById('device-detail-body');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    deviceAlerts.forEach(alert => {
        let badgeColor = alert.severity === 'CRITICAL' ? 'text-red-400 bg-red-950/50 border border-red-800/50' : 
                         alert.severity === 'HIGH' ? 'text-orange-400 bg-orange-950/40 border border-orange-800/50' : 
                         'text-yellow-400 bg-yellow-950/40 border border-yellow-800/50';

        tbody.innerHTML += `
            <tr class="hover:bg-gray-900/40 transition">
                <td class="px-6 py-4 text-gray-400 font-mono text-xs whitespace-nowrap">${alert.timestamp}</td>
                <td class="px-6 py-4 text-white font-medium whitespace-nowrap">${alert.rule_name}</td>
                <td class="px-6 py-4 text-gray-300">
                    <p class="font-medium">${alert.description}</p>
                    ${alert.ai_analysis ? `<div class="mt-2 text-xs bg-cyan-950/30 text-cyan-300 p-2.5 rounded-lg border border-cyan-900/40 font-mono shadow-sm"><span class="font-semibold flex items-center mb-1"><svg class="w-3.5 h-3.5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg> Gemini SOC Intel:</span>${alert.ai_analysis.replace(/\n/g, '<br>')}</div>` : ''}
                </td>
                <td class="px-6 py-4 text-center whitespace-nowrap">
                    <span class="px-2.5 py-1 rounded text-[10px] font-semibold font-mono ${badgeColor}">${alert.severity}</span>
                </td>
            </tr>
        `;
    });
    
    document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
    switchTab('device-detail');
}

async function loadAlerts() {
    try {
        const statsRes = await fetch('/api/stats');
        const stats = await statsRes.json();
        const flowsEl = document.getElementById('total-flows');
        const alertsEl = document.getElementById('total-alerts');
        
        if (flowsEl) flowsEl.innerText = stats.total_flows.toLocaleString();
        if (alertsEl) alertsEl.innerText = stats.total_alerts;

        const alertsRes = await fetch('/api/alerts');
        const data = await alertsRes.json();
        globalAlerts = data.alerts || [];

        const mainBody = document.getElementById('alerts-body');
        if (mainBody && globalAlerts.length > 0) {
            mainBody.innerHTML = '';
            globalAlerts.forEach(alert => {
                let badgeColor = alert.severity === 'CRITICAL' ? 'text-red-400 bg-red-950/50 border border-red-800/50' : 
                                 alert.severity === 'HIGH' ? 'text-orange-400 bg-orange-950/40 border border-orange-800/50' : 
                                 'text-yellow-400 bg-yellow-950/40 border border-yellow-800/50';

                mainBody.innerHTML += `
                    <tr class="hover:bg-gray-900/40 transition">
                        <td class="px-6 py-4 text-gray-400 font-mono text-xs whitespace-nowrap">${alert.timestamp}</td>
                        <td class="px-6 py-4 text-white font-medium whitespace-nowrap">${alert.rule_name}<br><span class="text-xs text-cyan-400 font-mono">MITRE: ${alert.mitre_technique || 'N/A'}</span></td>
                        <td class="px-6 py-4 text-gray-300">
                            <p class="font-medium">${alert.description}</p>
                            ${alert.ai_analysis ? `<div class="mt-2 text-xs bg-cyan-950/30 text-cyan-300 p-2.5 rounded-lg border border-cyan-900/40 font-mono shadow-sm"><span class="font-semibold flex items-center mb-1"><svg class="w-3.5 h-3.5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg> Gemini SOC Intel:</span>${alert.ai_analysis.replace(/\n/g, '<br>')}</div>` : ''}
                        </td>
                        <td class="px-6 py-4 text-center whitespace-nowrap">
                            <span class="px-2.5 py-1 rounded text-[10px] font-semibold font-mono ${badgeColor}">${alert.severity}</span>
                        </td>
                    </tr>
                `;
            });
        }

        const deviceCounts = {};
        globalAlerts.forEach(alert => {
            const device = alert.description.split(':')[0].trim();
            if (device && !device.startsWith("What Happened")) {
                deviceCounts[device] = (deviceCounts[device] || 0) + 1;
            }
        });

        const grid = document.getElementById('devices-grid');
        if (grid) {
            grid.innerHTML = '';
            const sortedDevices = Object.entries(deviceCounts).sort((a, b) => b[1] - a[1]);
            
            if (sortedDevices.length === 0) {
                grid.innerHTML = `<span class="text-sm text-gray-600 font-mono">No threats detected across edge nodes.</span>`;
            } else {
                sortedDevices.forEach(([device, count]) => {
                    grid.innerHTML += `
                        <div onclick="openDeviceDetail('${device}')" class="glass-panel p-6 rounded-2xl border border-gray-800 hover:border-cyan-500/50 hover:bg-gray-800/30 transition cursor-pointer group relative overflow-hidden">
                            <div class="absolute -right-6 -top-6 w-24 h-24 bg-cyan-500/5 rounded-full blur-xl group-hover:bg-cyan-500/10 transition"></div>
                            <div class="flex items-center justify-between mb-4">
                                <div class="w-10 h-10 rounded-full bg-gray-800 flex items-center justify-center text-cyan-400 group-hover:bg-cyan-950/50 transition">
                                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg>
                                </div>
                                <span class="px-3 py-1 rounded-full text-xs font-bold bg-red-950/80 text-red-400 border border-red-900/50 shadow-sm">${count} Active</span>
                            </div>
                            <h3 class="font-mono text-sm text-gray-200 group-hover:text-cyan-300 transition truncate">${device}</h3>
                            <p class="text-xs text-gray-500 mt-2">Click to inspect persistent issues</p>
                        </div>
                    `;
                });
            }
        }
    } catch (e) {
        console.error("Dashboard synchronization error:", e);
    }
}

// Initialize Dashboard listeners
document.addEventListener('DOMContentLoaded', () => {
    const greetingEl = document.getElementById('user-greeting');
    if (greetingEl) {
        greetingEl.innerText = localStorage.getItem('soc_user') || 'Admin';
        loadAlerts();
        setInterval(loadAlerts, 4000);
    }

    const fileInput = document.getElementById('file-input');
    if (fileInput) {
        fileInput.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const statusDiv = document.getElementById('upload-status');
            statusDiv.classList.remove('hidden');
            statusDiv.innerHTML = `<span class="text-cyan-400">Uploading ${file.name}...</span>`;

            const formData = new FormData();
            formData.append('file', file);

            try {
                const response = await fetch('/api/upload', { method: 'POST', body: formData });
                const result = await response.json();
                
                if (response.ok) {
                    statusDiv.innerHTML = `<span class="text-emerald-400">Success: ${file.name} saved to pcaps directory. Run ingestion engine to process.</span>`;
                } else {
                    statusDiv.innerHTML = `<span class="text-red-400">Error: ${result.detail || 'Upload failed'}</span>`;
                }
            } catch (err) {
                statusDiv.innerHTML = `<span class="text-red-400">Connection error during upload.</span>`;
            }
        });
    }
});