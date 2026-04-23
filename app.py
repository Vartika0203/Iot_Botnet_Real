from flask import Flask, render_template_string, jsonify, send_file
from flask_socketio import SocketIO, emit
from detector import NetworkMonitor
import threading
import time
import socket
import io
import csv
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'iot-detection-secret'
socketio = SocketIO(app, cors_allowed_origins="*")

monitor = NetworkMonitor()

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Botnet Detection System</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0f0f1a;
            color: #e0e0e0;
            padding: 24px;
        }
        
        .container { max-width: 1400px; margin: 0 auto; }
        
        .header { margin-bottom: 32px; }
        .header h1 { font-size: 24px; font-weight: 600; color: #fff; }
        .header p { font-size: 14px; color: #888; margin-top: 6px; }
        
        .badge {
            display: inline-block;
            background: #1e2a2e;
            color: #4ecdc4;
            font-size: 12px;
            padding: 4px 12px;
            border-radius: 20px;
            margin-top: 12px;
        }
        
        .defense-badge {
            display: inline-block;
            background: #2a1e2e;
            color: #ff6b6b;
            font-size: 12px;
            padding: 4px 12px;
            border-radius: 20px;
            margin-top: 12px;
            margin-left: 10px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }
        
        .stat-card {
            background: #1a1a2a;
            border-radius: 12px;
            padding: 20px;
            border: 1px solid #2a2a3a;
        }
        
        .stat-value { font-size: 32px; font-weight: 600; color: #fff; margin-bottom: 6px; }
        .stat-label { font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 0.5px; }
        
        .three-columns {
            display: flex;
            gap: 24px;
            margin-bottom: 32px;
            flex-wrap: wrap;
        }
        
        .graph-panel {
            flex: 2;
            min-width: 300px;
            background: #1a1a2a;
            border-radius: 12px;
            padding: 20px;
            border: 1px solid #2a2a3a;
        }
        
        .info-panel {
            flex: 1;
            min-width: 250px;
            background: #1a1a2a;
            border-radius: 12px;
            padding: 20px;
            border: 1px solid #2a2a3a;
        }
        
        .defense-panel {
            flex: 1;
            min-width: 250px;
            background: #1a1a2a;
            border-radius: 12px;
            padding: 20px;
            border: 1px solid #2a2a3a;
            display: flex;
            flex-direction: column;
        }
        
        .panel-title {
            font-size: 13px;
            font-weight: 600;
            color: #aaa;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid #2a2a3a;
            flex-shrink: 0;
        }
        
        canvas { max-height: 300px; width: 100%; }
        
        .live-stats {
            display: flex;
            justify-content: space-between;
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid #2a2a3a;
        }
        
        .live-stat { text-align: center; }
        .live-stat-label { font-size: 11px; color: #666; margin-bottom: 4px; }
        .live-stat-value { font-size: 20px; font-weight: 600; color: #fff; }
        
        .legend { display: flex; gap: 20px; margin-bottom: 20px; }
        .legend-item { display: flex; align-items: center; gap: 8px; font-size: 12px; }
        .legend-color { width: 20px; height: 3px; border-radius: 2px; }
        .legend-normal { background: #4ecdc4; }
        .legend-attack { background: #ff6b6b; }
        
        .attack-list { margin-bottom: 0; }
        .attack-item {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            padding: 10px 0;
            border-bottom: 1px solid #2a2a3a;
        }
        .attack-icon {
            width: 32px;
            height: 32px;
            background: #252535;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: 600;
        }
        .attack-info { flex: 1; }
        .attack-name { font-size: 12px; font-weight: 600; color: #fff; margin-bottom: 2px; }
        .attack-desc { font-size: 10px; color: #888; }
        
        .defense-list-container {
            flex: 1;
            overflow-y: auto;
            max-height: 280px;
            margin-bottom: 12px;
            padding-right: 4px;
        }
        
        .defense-list-container::-webkit-scrollbar {
            width: 4px;
        }
        
        .defense-list-container::-webkit-scrollbar-track {
            background: #2a2a3a;
            border-radius: 4px;
        }
        
        .defense-list-container::-webkit-scrollbar-thumb {
            background: #4ecdc4;
            border-radius: 4px;
        }
        
        .defense-item {
            background: #151525;
            border-left: 3px solid #4ecdc4;
            padding: 10px;
            margin-bottom: 8px;
            border-radius: 8px;
        }
        
        .defense-time { font-size: 10px; color: #666; margin-bottom: 4px; }
        .defense-action { font-size: 12px; font-weight: 500; color: #4ecdc4; }
        .defense-target { font-size: 10px; color: #888; margin-top: 4px; }
        .defense-status { font-size: 9px; color: #ffaa00; margin-top: 2px; }
        
        .defense-stats {
            flex-shrink: 0;
            padding-top: 12px;
            border-top: 1px solid #2a2a3a;
            margin-top: 4px;
        }
        
        .block-count {
            font-size: 12px;
            color: #4ecdc4;
            text-align: center;
        }
        
        .attack-stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }
        
        .attack-stat-card {
            background: #1a1a2a;
            border-radius: 12px;
            padding: 16px;
            text-align: center;
            border: 1px solid #2a2a3a;
        }
        
        .attack-stat-number { font-size: 28px; font-weight: 600; }
        .attack-stat-label { font-size: 11px; color: #888; margin-top: 6px; }
        
        .alerts-panel {
            background: #1a1a2a;
            border-radius: 12px;
            padding: 20px;
            border: 1px solid #2a2a3a;
            max-height: 280px;
            overflow-y: auto;
            margin-bottom: 16px;
        }
        
        .alerts-panel::-webkit-scrollbar {
            width: 4px;
        }
        
        .alerts-panel::-webkit-scrollbar-track {
            background: #2a2a3a;
            border-radius: 4px;
        }
        
        .alerts-panel::-webkit-scrollbar-thumb {
            background: #ff6b6b;
            border-radius: 4px;
        }
        
        .alert-item {
            background: #151525;
            border-left: 3px solid #ff6b6b;
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 8px;
        }
        
        .alert-time { font-size: 10px; color: #666; margin-bottom: 4px; }
        .alert-message { font-size: 12px; font-weight: 500; margin-bottom: 4px; }
        .alert-confidence { font-size: 10px; color: #4ecdc4; }
        .alert-defense { font-size: 10px; color: #ff6b6b; margin-top: 4px; }
        
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 500;
        }
        .status-normal { background: #1e3a2e; color: #4ecdc4; }
        .status-attack { background: #3a1e1e; color: #ff6b6b; animation: pulse 1s infinite; }
        
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
        
        .report-btn {
            background: #4ecdc4;
            color: #0f0f1a;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            margin-right: 10px;
            transition: all 0.2s;
        }
        
        .report-btn:hover {
            background: #ff6b6b;
            color: #fff;
            transform: scale(1.02);
        }
        
        .clear-btn {
            background: #2a2a3a;
            color: #fff;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .clear-btn:hover {
            background: #ff6b6b;
        }
        
        .footer {
            text-align: center;
            margin-top: 32px;
            padding-top: 20px;
            border-top: 1px solid #2a2a3a;
            font-size: 11px;
            color: #555;
        }
        
        .badge-small {
            background: #4ecdc4;
            color: #0f0f1a;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 600;
        }
        
        .button-group {
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>IoT Botnet Detection System</h1>
        <p>Real-time network traffic analysis with Auto-Defense Mechanism</p>
        <div class="badge">REAL ATTACK DETECTION ACTIVE</div>
        <div class="defense-badge">AUTO-DEFENSE ACTIVE</div>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card"><div class="stat-value" id="totalPackets">0</div><div class="stat-label">Total Packets</div></div>
        <div class="stat-card"><div class="stat-value" id="normalPercent">0%</div><div class="stat-label">Normal Traffic</div></div>
        <div class="stat-card"><div class="stat-value" id="attackPercent">0%</div><div class="stat-label">Attack Traffic</div></div>
        <div class="stat-card"><div class="stat-value" id="statusText">Normal</div><div class="stat-label">Status</div></div>
    </div>
    
    <div class="three-columns">
        <div class="graph-panel">
            <div class="panel-title">Live Traffic</div>
            <canvas id="trafficChart"></canvas>
            <div class="live-stats">
                <div class="live-stat"><div class="live-stat-label">Current</div><div class="live-stat-value" id="livePPS">0</div></div>
                <div class="live-stat"><div class="live-stat-label">Baseline</div><div class="live-stat-value" id="baseline">0</div></div>
                <div class="live-stat"><div class="live-stat-label">Ratio</div><div class="live-stat-value" id="ratio">0x</div></div>
            </div>
        </div>
        
        <div class="info-panel">
            <div class="panel-title">Understanding the Graph</div>
            <div class="legend">
                <div class="legend-item"><div class="legend-color legend-normal"></div><span>Normal Traffic</span></div>
                <div class="legend-item"><div class="legend-color legend-attack"></div><span>Attack Detected</span></div>
            </div>
            <div class="attack-list">
                <div class="attack-item">
                    <div class="attack-icon">D</div>
                    <div class="attack-info">
                        <div class="attack-name">DDoS Attack</div>
                        <div class="attack-desc">Traffic spike > 2.5x normal</div>
                    </div>
                </div>
                <div class="attack-item">
                    <div class="attack-icon">R</div>
                    <div class="attack-info">
                        <div class="attack-name">Reconnaissance</div>
                        <div class="attack-desc">Scanning pattern detected</div>
                    </div>
                </div>
                <div class="attack-item">
                    <div class="attack-icon">C</div>
                    <div class="attack-info">
                        <div class="attack-name">C&C Attack</div>
                        <div class="attack-desc">Suspicious communication</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="defense-panel">
            <div class="panel-title">
                Defense Actions 
                <span class="badge-small" id="blockCount">0 blocked</span>
            </div>
            <div class="defense-list-container" id="defenseListContainer">
                <div id="defenseList" style="text-align: center; color: #666; padding: 20px;">No defense actions yet</div>
            </div>
            <div class="defense-stats">
                <div class="block-count">
                    <span id="activeDefense">🛡️ Auto-blocking active</span>
                </div>
            </div>
        </div>
    </div>
    
    <div class="attack-stats">
        <div class="attack-stat-card"><div class="attack-stat-number" id="ddosCount" style="color: #ff6b6b;">0</div><div class="attack-stat-label">DDoS Attacks</div></div>
        <div class="attack-stat-card"><div class="attack-stat-number" id="reconCount" style="color: #ffd93d;">0</div><div class="attack-stat-label">Reconnaissance</div></div>
        <div class="attack-stat-card"><div class="attack-stat-number" id="ccCount" style="color: #6bcb77;">0</div><div class="attack-stat-label">C&C Attacks</div></div>
    </div>
    
    <div class="button-group">
        <button class="report-btn" onclick="downloadReport('csv')">📊 Download CSV Report</button>
        <button class="report-btn" onclick="downloadReport('txt')">📄 Download Text Report</button>
        <button class="clear-btn" onclick="clearAlerts()">🗑️ Clear All Alerts</button>
    </div>
    
    <div class="alerts-panel">
        <div class="panel-title" style="margin-bottom: 16px;">Recent Alerts</div>
        <div id="alertsList">No attacks detected</div>
    </div>
    
    <div class="footer">
        ML Model: Random Forest | Auto-Defense: IP Blocking | 96.2% accuracy
    </div>
</div>

<script>
    const socket = io();
    const ctx = document.getElementById('trafficChart').getContext('2d');
    let currentMode = 'normal';
    
    let lastAlertKey = "";
    let lastAlertTime = 0;
    let blockedCount = 0;
    
    const chart = new Chart(ctx, {
        type: 'line',
        data: { labels: [], datasets: [{ label: 'Packets/sec', data: [], borderColor: '#4ecdc4', backgroundColor: 'rgba(78, 205, 196, 0.05)', borderWidth: 2, fill: true, tension: 0.3, pointRadius: 2 }] },
        options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, grid: { color: '#2a2a3a' }, ticks: { color: '#888' } }, x: { grid: { display: false }, ticks: { color: '#888', maxRotation: 45, font: { size: 10 } } } } }
    });
    
    socket.on('traffic_update', function(data) {
        document.getElementById('livePPS').innerText = data.pps;
        document.getElementById('baseline').innerText = data.baseline;
        document.getElementById('ratio').innerText = (data.pps / data.baseline).toFixed(1) + 'x';
        
        if (data.status === 'attack') {
            document.getElementById('statusText').innerHTML = '<span class="status-badge status-attack">Attack Detected</span>';
            if (currentMode !== 'attack') {
                chart.data.datasets[0].borderColor = '#ff6b6b';
                chart.data.datasets[0].pointBackgroundColor = '#ff6b6b';
                chart.data.datasets[0].backgroundColor = 'rgba(255, 107, 107, 0.05)';
                currentMode = 'attack';
                chart.update();
            }
        } else {
            document.getElementById('statusText').innerHTML = '<span class="status-badge status-normal">System Normal</span>';
            if (currentMode !== 'normal') {
                chart.data.datasets[0].borderColor = '#4ecdc4';
                chart.data.datasets[0].pointBackgroundColor = '#4ecdc4';
                chart.data.datasets[0].backgroundColor = 'rgba(78, 205, 196, 0.05)';
                currentMode = 'normal';
                chart.update();
            }
        }
        
        chart.data.labels.push(data.timestamp);
        chart.data.datasets[0].data.push(data.pps);
        if (chart.data.labels.length > 30) { chart.data.labels.shift(); chart.data.datasets[0].data.shift(); }
        chart.update('none');
    });
    
    socket.on('stats_update', function(data) {
        document.getElementById('totalPackets').innerText = data.total_packets.toLocaleString();
        document.getElementById('normalPercent').innerText = data.normal_percent + '%';
        document.getElementById('attackPercent').innerText = data.attack_percent + '%';
        document.getElementById('ddosCount').innerText = data.ddos_count;
        document.getElementById('reconCount').innerText = data.recon_count;
        document.getElementById('ccCount').innerText = data.cc_count;
    });
    
    socket.on('defense_update', function(defense) {
        const defenseDiv = document.getElementById('defenseList');
        let statusIcon = '';
        if (defense.status === 'success') {
            statusIcon = '✅';
        } else if (defense.status === 'skipped (already blocked)') {
            statusIcon = '⚠️';
        } else {
            statusIcon = '❌';
        }
        
        const newDefense = '<div class="defense-item"><div class="defense-time">' + defense.timestamp + '</div><div class="defense-action">' + defense.action + ' ' + statusIcon + '</div><div class="defense-target">Target: ' + defense.target + '</div><div class="defense-status">Status: ' + defense.status + '</div></div>';
        
        if (defenseDiv.innerHTML === 'No defense actions yet') {
            defenseDiv.innerHTML = newDefense;
        } else {
            defenseDiv.innerHTML = newDefense + defenseDiv.innerHTML;
        }
        
        if (defense.status === 'success') {
            blockedCount++;
            document.getElementById('blockCount').innerText = blockedCount + ' blocked';
        }
    });
    
    socket.on('new_alert', function(alert) {
        const now = Date.now();
        const alertKey = alert.type + "_" + alert.timestamp;
        
        if (alertKey === lastAlertKey && (now - lastAlertTime) < 10000) {
            return;
        }
        
        lastAlertKey = alertKey;
        lastAlertTime = now;
        
        const alertsDiv = document.getElementById('alertsList');
        const defenseText = alert.defense_action ? '<div class="alert-defense">🛡️ Defense: ' + alert.defense_action + '</div>' : '';
        const newAlert = '<div class="alert-item"><div class="alert-time">' + alert.timestamp + '</div><div class="alert-message">' + alert.type.toUpperCase() + ': ' + alert.message + '</div><div class="alert-confidence">Confidence: ' + (alert.confidence * 100).toFixed(1) + '%</div>' + defenseText + '</div>';
        
        if (alertsDiv.innerHTML === 'No attacks detected') alertsDiv.innerHTML = newAlert;
        else alertsDiv.innerHTML = newAlert + alertsDiv.innerHTML;
    });
    
    function downloadReport(format) {
        fetch('/api/download_report/' + format)
            .then(response => response.blob())
            .then(blob => {
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'security_report_' + new Date().toISOString().slice(0,19).replace(/:/g, '-') + (format === 'csv' ? '.csv' : '.txt');
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            });
    }
    
    function clearAlerts() {
        fetch('/api/clear_alerts', { method: 'POST' })
            .then(response => response.json())
            .then(() => {
                document.getElementById('alertsList').innerHTML = 'No attacks detected';
                document.getElementById('defenseList').innerHTML = 'No defense actions yet';
                blockedCount = 0;
                document.getElementById('blockCount').innerText = '0 blocked';
            });
    }
</script>
</body>
</html>
'''

def send_updates():
    while True:
        stats = monitor.get_statistics()
        traffic_data = list(stats['traffic_history'])
        if traffic_data:
            latest = traffic_data[-1]
            socketio.emit('traffic_update', {
                'pps': latest['pps'],
                'status': 'attack' if latest['attack'] else 'normal',
                'timestamp': latest['time'],
                'baseline': stats.get('baseline_pps', 30)
            })
        
        socketio.emit('stats_update', {
            'total_packets': stats['total_packets'],
            'normal_percent': stats['normal_percent'],
            'attack_percent': stats['attack_percent'],
            'ddos_count': stats['ddos_count'],
            'recon_count': stats['recon_count'],
            'cc_count': stats['cc_count']
        })
        
        for defense in stats.get('defense_actions', []):
            socketio.emit('defense_update', defense)
        
        for alert in stats['alerts']:
            socketio.emit('new_alert', alert)
        
        time.sleep(1)

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/download_report/<format>')
def download_report(format):
    stats = monitor.get_statistics()
    
    output = io.StringIO()
    
    if format == 'csv':
        writer = csv.writer(output)
        writer.writerow(['Security Incident Report'])
        writer.writerow(['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow([])
        writer.writerow(['=== ATTACK SUMMARY ==='])
        writer.writerow(['Attack Type', 'Count'])
        writer.writerow(['DDoS Attacks', stats['ddos_count']])
        writer.writerow(['Reconnaissance Attacks', stats['recon_count']])
        writer.writerow(['C&C Attacks', stats['cc_count']])
        writer.writerow([])
        writer.writerow(['=== TOTAL STATISTICS ==='])
        writer.writerow(['Total Packets', stats['total_packets']])
        writer.writerow(['Normal Traffic %', stats['normal_percent']])
        writer.writerow(['Attack Traffic %', stats['attack_percent']])
        writer.writerow(['Baseline PPS', stats['baseline_pps']])
        writer.writerow([])
        writer.writerow(['=== DETAILED ALERTS ==='])
        writer.writerow(['Timestamp', 'Attack Type', 'Message', 'Confidence', 'Defense Action'])
        
        for alert in stats['alerts']:
            writer.writerow([
                alert['timestamp'],
                alert['type'].upper(),
                alert['message'],
                f"{alert['confidence']*100:.1f}%",
                alert.get('defense_action', 'None')
            ])
        
        writer.writerow([])
        writer.writerow(['=== BLOCKED IPS ==='])
        for ip in stats.get('blocked_ips', []):
            writer.writerow([ip])
    
    else:
        output.write("="*60 + "\n")
        output.write("IoT BOTNET DETECTION SYSTEM - SECURITY REPORT\n")
        output.write("="*60 + "\n")
        output.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        output.write("-"*40 + "\n")
        output.write("ATTACK SUMMARY\n")
        output.write("-"*40 + "\n")
        output.write(f"DDoS Attacks: {stats['ddos_count']}\n")
        output.write(f"Reconnaissance Attacks: {stats['recon_count']}\n")
        output.write(f"C&C Attacks: {stats['cc_count']}\n\n")
        
        output.write("-"*40 + "\n")
        output.write("TOTAL STATISTICS\n")
        output.write("-"*40 + "\n")
        output.write(f"Total Packets Analyzed: {stats['total_packets']:,}\n")
        output.write(f"Normal Traffic: {stats['normal_percent']}%\n")
        output.write(f"Attack Traffic: {stats['attack_percent']}%\n")
        output.write(f"Normal Baseline: {stats['baseline_pps']} pps\n\n")
        
        output.write("-"*40 + "\n")
        output.write("DETAILED ALERTS\n")
        output.write("-"*40 + "\n")
        for alert in stats['alerts'][:50]:
            output.write(f"[{alert['timestamp']}] {alert['type'].upper()}: {alert['message']}\n")
            output.write(f"    Confidence: {alert['confidence']*100:.1f}%\n")
            if alert.get('defense_action'):
                output.write(f"    Defense: {alert['defense_action']}\n")
            output.write("\n")
        
        output.write("-"*40 + "\n")
        output.write("BLOCKED IP ADDRESSES\n")
        output.write("-"*40 + "\n")
        for ip in stats.get('blocked_ips', []):
            output.write(f"• {ip}\n")
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv' if format == 'csv' else 'text/plain',
        as_attachment=True,
        download_name=f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.{format}'
    )

@app.route('/api/clear_alerts', methods=['POST'])
def clear_alerts():
    monitor.alerts.clear()
    monitor.defense_actions.clear()
    monitor.blocked_ips.clear()
    return {'status': 'success'}

@socketio.on('connect')
def handle_connect():
    emit('stats_update', monitor.get_statistics())

if __name__ == '__main__':
    monitor.start_monitoring()
    
    update_thread = threading.Thread(target=send_updates)
    update_thread.daemon = True
    update_thread.start()
    
    print("\n" + "="*60)
    print("IoT Botnet Detection System Started")
    print("="*60)
    print("Open browser: http://localhost:5000")
    print("Auto-Defense: Active (blocks attacker IPs)")
    print("Report Generation: Available (CSV and TXT formats)")
    print("="*60 + "\n")
    
    socketio.run(app, host='127.0.0.1', port=5000, debug=False)
