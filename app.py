from flask import Flask, render_template_string, jsonify
from flask_socketio import SocketIO, emit
from detector import NetworkMonitor
import threading
import time

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
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Poppins', 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0a0a2a 0%, #1a1a3e 50%, #0a0a2a 100%);
            color: #ffffff;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container { max-width: 1400px; margin: 0 auto; }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 25px;
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            border: 1px solid rgba(0, 255, 136, 0.2);
        }
        
        .header h1 {
            font-size: 36px;
            font-weight: 700;
            background: linear-gradient(135deg, #00ff88, #00ccff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        
        .header p { color: #aaaaaa; font-size: 14px; }
        
        .badge-real {
            background: #ff4444;
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            margin-top: 10px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .stat-card:hover { transform: translateY(-5px); border-color: rgba(0, 255, 136, 0.3); }
        .stat-value { font-size: 36px; font-weight: 700; color: #00ff88; }
        .stat-label { font-size: 12px; color: #aaaaaa; margin-top: 8px; text-transform: uppercase; letter-spacing: 1px; }
        
        .main-content {
            display: flex;
            gap: 25px;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }
        
        .graph-column { flex: 3; min-width: 300px; }
        .info-column { flex: 1.5; min-width: 300px; }
        
        .graph-container {
            background: rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        canvas { max-height: 350px; width: 100%; }
        
        .live-traffic {
            text-align: center;
            margin-top: 15px;
            padding: 12px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            font-size: 14px;
        }
        
        .live-traffic span { color: #00ff88; font-weight: bold; }
        
        .info-box {
            background: rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 20px;
            height: 100%;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .info-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 20px;
            color: #00ff88;
            border-left: 3px solid #00ff88;
            padding-left: 12px;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 15px;
            padding: 12px;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 12px;
        }
        
        .legend-color { width: 35px; height: 4px; border-radius: 2px; }
        .legend-color.normal { background: #00ff88; box-shadow: 0 0 8px #00ff88; }
        .legend-color.attack { background: #ff4444; box-shadow: 0 0 8px #ff4444; }
        
        .attack-card-detail {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            padding: 12px;
            margin-bottom: 12px;
            border-left: 3px solid;
            transition: all 0.3s;
        }
        
        .attack-card-detail:hover { transform: translateX(5px); }
        .attack-card-detail.ddos { border-left-color: #ff4444; }
        .attack-card-detail.recon { border-left-color: #ff6600; }
        .attack-card-detail.cc { border-left-color: #ffaa00; }
        
        .attack-card-title { font-weight: 600; margin-bottom: 5px; }
        .attack-card-desc { font-size: 11px; color: #cccccc; line-height: 1.4; }
        
        .attack-stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .attack-card-stat {
            background: rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 15px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .attack-number { font-size: 28px; font-weight: 700; }
        
        .alerts-container {
            background: rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 20px;
            max-height: 350px;
            overflow-y: auto;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .alert-item {
            background: rgba(255, 68, 68, 0.1);
            border-left: 4px solid #ff4444;
            padding: 12px 15px;
            margin-bottom: 12px;
            border-radius: 12px;
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .alert-time { font-size: 11px; color: #888888; margin-bottom: 5px; }
        .alert-message { font-weight: bold; margin-bottom: 5px; font-size: 13px; }
        .alert-confidence { font-size: 11px; color: #ffaa00; }
        
        .status-badge {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        .status-normal { background: #00aa44; }
        .status-attack { background: #ff4444; animation: pulse 1s infinite; }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .footer { text-align: center; margin-top: 30px; padding: 20px; color: #666666; font-size: 12px; }
        
        .toast-popup {
            position: fixed;
            bottom: 30px;
            right: 30px;
            min-width: 320px;
            max-width: 380px;
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            border-left: 5px solid;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            z-index: 1000;
            animation: slideInRight 0.3s ease;
        }
        
        .toast-popup.ddos { border-left-color: #ff4444; }
        .toast-popup.recon { border-left-color: #ff6600; }
        .toast-popup.cc { border-left-color: #ffaa00; }
        
        @keyframes slideInRight {
            from { transform: translateX(400px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        .toast-header {
            padding: 10px 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .toast-header.ddos { background: #ff4444; }
        .toast-header.recon { background: #ff6600; }
        .toast-header.cc { background: #ffaa00; color: #1a1a2e; }
        
        .toast-close {
            background: none;
            border: none;
            color: white;
            font-size: 18px;
            cursor: pointer;
            margin-left: auto;
        }
        
        .toast-body { padding: 12px 15px; }
        .toast-confidence { font-size: 11px; color: #ffaa00; margin-top: 5px; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>IoT Botnet Detection System</h1>
        <p>Real-time Network Traffic Analysis | DDoS | Reconnaissance | C&C Detection</p>
        <div class="badge-real">REAL ATTACK DETECTION ACTIVE</div>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card"><div class="stat-value" id="totalPackets">0</div><div class="stat-label">Total Packets</div></div>
        <div class="stat-card"><div class="stat-value" id="normalPercent">0%</div><div class="stat-label">Normal Traffic</div></div>
        <div class="stat-card"><div class="stat-value" id="attackPercent">0%</div><div class="stat-label">Attack Traffic</div></div>
        <div class="stat-card"><div class="stat-value" id="statusText">Normal</div><div class="stat-label">Status</div></div>
    </div>
    
    <div class="main-content">
        <div class="graph-column">
            <div class="graph-container">
                <h3>Live Network Traffic</h3>
                <canvas id="trafficChart"></canvas>
                <div class="live-traffic">
                    Current: <span id="livePPS">0</span> packets/sec | 
                    Baseline: <span id="baseline">0</span> packets/sec
                </div>
            </div>
        </div>
        
        <div class="info-column">
            <div class="info-box">
                <div class="info-title">Understanding the Dashboard</div>
                <div class="legend-item"><div class="legend-color normal"></div><div><strong>Green Line</strong> = Normal Safe Traffic</div></div>
                <div class="legend-item"><div class="legend-color attack"></div><div><strong>Red Line</strong> = Attack Detected</div></div>
                
                <div class="info-title" style="margin-top: 20px;">What We Detect</div>
                
                <div class="attack-card-detail ddos">
                    <div class="attack-card-title">DDoS Attack</div>
                    <div class="attack-card-desc">Massive traffic flood - detected when traffic spikes above 3x normal</div>
                </div>
                
                <div class="attack-card-detail recon">
                    <div class="attack-card-title">Reconnaissance Attack</div>
                    <div class="attack-card-desc">System scanning - detected when traffic shows scanning patterns</div>
                </div>
                
                <div class="attack-card-detail cc">
                    <div class="attack-card-title">C&C Attack</div>
                    <div class="attack-card-desc">Malware communication - detected on suspicious connections</div>
                </div>
                
                <div class="attack-card-detail" style="border-left-color: #00ff88; margin-top: 15px;">
                    <div class="attack-card-title">How to Test</div>
                    <div class="attack-card-desc">Run a speed test (speedtest.net) or download a large file to generate real traffic spikes. The system will detect it as a DDoS attack!</div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="attack-stats">
        <div class="attack-card-stat"><h4>DDoS Attacks</h4><div class="attack-number" style="color:#ff4444" id="ddosCount">0</div></div>
        <div class="attack-card-stat"><h4>Reconnaissance</h4><div class="attack-number" style="color:#ff6600" id="reconCount">0</div></div>
        <div class="attack-card-stat"><h4>C&C Attacks</h4><div class="attack-number" style="color:#ffaa00" id="ccCount">0</div></div>
    </div>
    
    <div class="alerts-container">
        <h3>Attack Alerts</h3>
        <div id="alertsList">No attacks detected</div>
    </div>
    
    <div class="footer">
        <p>REAL ATTACK DETECTION: Run speedtest.net or download a large file to generate real traffic</p>
    </div>
</div>

<script>
    const socket = io();
    const ctx = document.getElementById('trafficChart').getContext('2d');
    let currentMode = 'normal';
    let lastToastTime = 0;
    
    const chart = new Chart(ctx, {
        type: 'line',
        data: { labels: [], datasets: [{ label: 'Packets Per Second', data: [], borderColor: '#00ff88', backgroundColor: 'rgba(0, 255, 136, 0.1)', borderWidth: 3, fill: true, tension: 0.3, pointRadius: 3 }] },
        options: { responsive: true, maintainAspectRatio: true, scales: { y: { beginAtZero: true, grid: { color: '#333' }, ticks: { color: '#fff' } }, x: { grid: { color: '#333' }, ticks: { color: '#fff' } } } }
    });
    
    function showToast(attackType, message, confidence) {
        const now = Date.now();
        if (now - lastToastTime < 15000) return;
        lastToastTime = now;
    
        const toast = document.createElement('div');
        toast.className = 'toast-popup ' + attackType;
        
        let icon = '';
        let headerText = '';
        
        if (attackType === 'ddos') {
            icon = 'W';
            headerText = 'DDOS ATTACK DETECTED!';
        } else if (attackType === 'recon') {
            icon = 'O';
            headerText = 'RECONNAISSANCE ATTACK DETECTED!';
        } else {
            icon = 'X';
            headerText = 'C&C ATTACK DETECTED!';
        }
        
        toast.innerHTML = '<div class="toast-header ' + attackType + '"><strong>' + icon + ' ' + headerText + '</strong><button class="toast-close" onclick="this.parentElement.parentElement.remove()">x</button></div><div class="toast-body"><p>' + message + '</p><div class="toast-confidence">Confidence: ' + (confidence * 100).toFixed(1) + '%</div></div>';
        document.body.appendChild(toast);
        
        setTimeout(function() { if(toast && toast.parentNode) toast.remove(); }, 10000);
    }
    
    socket.on('traffic_update', function(data) {
        document.getElementById('livePPS').innerText = data.pps;
        document.getElementById('baseline').innerText = data.baseline;
        
        if (data.status === 'attack') {
            document.getElementById('statusText').innerHTML = '<span class="status-badge status-attack">ATTACK DETECTED</span>';
            if (currentMode !== 'attack') {
                chart.data.datasets[0].borderColor = '#ff4444';
                chart.data.datasets[0].backgroundColor = 'rgba(255, 68, 68, 0.1)';
                currentMode = 'attack';
                chart.update();
            }
        } else {
            document.getElementById('statusText').innerHTML = '<span class="status-badge status-normal">SYSTEM NORMAL</span>';
            if (currentMode !== 'normal') {
                chart.data.datasets[0].borderColor = '#00ff88';
                chart.data.datasets[0].backgroundColor = 'rgba(0, 255, 136, 0.1)';
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
    
    socket.on('new_alert', function(alert) {
        showToast(alert.type, alert.message, alert.confidence);
        
        const alertsDiv = document.getElementById('alertsList');
        let icon = '';
        if (alert.type === 'ddos') icon = 'W';
        else if (alert.type === 'recon') icon = 'O';
        else icon = 'X';
        
        const newAlert = '<div class="alert-item"><div class="alert-time">' + alert.timestamp + '</div><div class="alert-message">' + icon + ' ' + alert.message + '</div><div class="alert-confidence">Confidence: ' + (alert.confidence * 100).toFixed(1) + '%</div></div>';
        
        if (alertsDiv.innerHTML === 'No attacks detected') alertsDiv.innerHTML = newAlert;
        else alertsDiv.innerHTML = newAlert + alertsDiv.innerHTML;
    });
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
                'baseline': stats.get('baseline_pps', 40)
            })
        
        socketio.emit('stats_update', {
            'total_packets': stats['total_packets'],
            'normal_percent': stats['normal_percent'],
            'attack_percent': stats['attack_percent'],
            'ddos_count': stats['ddos_count'],
            'recon_count': stats['recon_count'],
            'cc_count': stats['cc_count']
        })
        
        for alert in stats['alerts']:
            socketio.emit('new_alert', alert)
        
        time.sleep(1)

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@socketio.on('connect')
def handle_connect():
    emit('stats_update', monitor.get_statistics())

if __name__ == '__main__':
    monitor.start_monitoring()
    
    update_thread = threading.Thread(target=send_updates)
    update_thread.daemon = True
    update_thread.start()
    
    print("\n" + "="*60)
    print("IOT BOTNET DETECTION SYSTEM STARTED")
    print("="*60)
    print("Open browser: http://localhost:5000")
    print("\nREAL DETECTION: Run speedtest.net to generate real traffic")
    print("="*60 + "\n")
    
    socketio.run(app, host='127.0.0.1', port=5000, debug=False)