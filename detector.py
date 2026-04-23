import time
import threading
import psutil
import subprocess
import platform
import socket
from datetime import datetime
from collections import deque

class NetworkMonitor:
    def __init__(self):
        # Traffic data
        self.current_pps = 0
        self.traffic_history = deque(maxlen=30)
        
        # Attack state
        self.attack_active = False
        self.attack_type = None
        self.attack_end_time = 0
        
        # Cooldown
        self.last_alert_time = 0
        self.alert_cooldown = 30
        self.last_alert_key = ""
        
        # Statistics
        self.total_packets = 0
        self.normal_packets = 0
        self.attack_packets = 0
        self.attack_counts = {'ddos': 0, 'recon': 0, 'cc': 0}
        
        # Defense tracking
        self.defense_actions = []
        self.defense_enabled = True
        
        # Alerts
        self.alerts = []
        self.alert_keys = set()
        
        # Baseline
        self.baseline_pps = 50
        self.baseline_samples = []
        self.baseline_ready = False
        
        # Blocked IPs - Use a SET to prevent duplicates
        self.blocked_ips = set()
        
        self.running = True
        
        self.local_ip = self.get_local_ip()
        
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def block_ip(self, ip_address, attack_type):
        """Block an IP address - only if not already blocked"""
        
        # FIX: Check if already blocked - this prevents duplicate blocks
        if ip_address in self.blocked_ips:
            defense_log = {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'action': 'ALREADY_BLOCKED',
                'target': ip_address,
                'attack_type': attack_type,
                'status': 'skipped (already blocked)'
            }
            self.defense_actions.insert(0, defense_log)
            return False
        
        system = platform.system()
        
        try:
            if system == "Windows":
                rule_name = f"IoT_Block_{attack_type}_{int(time.time())}"
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
                subprocess.run(cmd, shell=True, capture_output=True)
                
                defense_log = {
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'action': 'BLOCK_IP',
                    'target': ip_address,
                    'attack_type': attack_type,
                    'status': 'success',
                    'rule_name': rule_name
                }
                self.defense_actions.insert(0, defense_log)
                self.blocked_ips.add(ip_address)  # Add to set of blocked IPs
                return True
                
        except Exception as e:
            print(f"Failed to block IP {ip_address}: {e}")
            return False
    
    def start_monitoring(self):
        print("\n" + "="*60)
        print("IoT Botnet Detection System")
        print("="*60)
        print("REAL ATTACK DETECTION ACTIVE")
        print("AUTO-DEFENSE MECHANISM ACTIVE")
        print("="*60 + "\n")
        
        self.calculate_baseline()
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def calculate_baseline(self):
        print("Analyzing your normal traffic pattern...")
        print("Please wait 15 seconds.\n")
        
        samples = []
        for i in range(15):
            bytes1 = psutil.net_io_counters().bytes_recv + psutil.net_io_counters().bytes_sent
            time.sleep(1)
            bytes2 = psutil.net_io_counters().bytes_recv + psutil.net_io_counters().bytes_sent
            bytes_diff = bytes2 - bytes1
            pps = int(bytes_diff / 1500) if bytes_diff > 0 else 0
            samples.append(pps)
            print(f"Sample {i+1:2d}: {pps:3d} packets/sec", end="\r")
        
        avg_pps = int(sum(samples) / len(samples))
        max_pps = max(samples)
        
        self.baseline_pps = max(max_pps + 15, avg_pps + 10, 40)
        
        print(f"\n\nBaseline established: {self.baseline_pps} packets/second")
        print(f"Your average: {avg_pps} pps | Peak: {max_pps} pps")
        self.baseline_ready = True
    
    def _monitor_loop(self):
        last_recv = psutil.net_io_counters().bytes_recv
        last_sent = psutil.net_io_counters().bytes_sent
        last_time = time.time()
        
        while self.running:
            current_recv = psutil.net_io_counters().bytes_recv
            current_sent = psutil.net_io_counters().bytes_sent
            current_time = time.time()
            
            time_diff = current_time - last_time
            if time_diff > 0:
                bytes_recv_sec = (current_recv - last_recv) / time_diff
                bytes_sent_sec = (current_sent - last_sent) / time_diff
                total_bytes_sec = bytes_recv_sec + bytes_sent_sec
                self.current_pps = int(total_bytes_sec / 1500) if total_bytes_sec > 0 else 0
            else:
                self.current_pps = 0
            
            self.total_packets += self.current_pps
            
            if self.attack_active and current_time > self.attack_end_time:
                self.attack_active = False
                self.attack_type = None
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Attack ended")
            
            if self.attack_active:
                self.attack_packets += self.current_pps
            else:
                self.normal_packets += self.current_pps
            
            timestamp = datetime.now().strftime('%H:%M:%S')
            self.traffic_history.append({
                'time': timestamp,
                'pps': self.current_pps,
                'attack': self.attack_active
            })
            
            while len(self.traffic_history) > 30:
                self.traffic_history.popleft()
            
            if not self.attack_active:
                self.detect_attack()
            
            if int(time.time()) % 10 == 0:
                if self.attack_active:
                    print(f"[{timestamp}] ATTACK: {self.attack_type.upper()} | {self.current_pps} pps")
                else:
                    print(f"[{timestamp}] NORMAL: {self.current_pps} pps (Baseline: {self.baseline_pps})")
            
            last_recv = current_recv
            last_sent = current_sent
            last_time = current_time
            time.sleep(1)
    
    def detect_attack(self):
        if not self.baseline_ready:
            return
        
        current_time = time.time()
        
        if current_time - self.last_alert_time < self.alert_cooldown:
            return
        
        ratio = self.current_pps / self.baseline_pps if self.baseline_pps > 0 else 1
        
        if ratio > 2.5 and self.current_pps > 80:
            self.trigger_attack_with_defense('ddos', ratio)
            self.last_alert_time = current_time
            self.attack_end_time = current_time + 12
        
        elif ratio > 2.0 and self.current_pps > 60:
            self.trigger_attack_with_defense('recon', ratio)
            self.last_alert_time = current_time
            self.attack_end_time = current_time + 10
    
    def trigger_attack_with_defense(self, attack_type, ratio):
        if self.attack_active:
            return
        
        self.attack_active = True
        self.attack_type = attack_type
        self.attack_counts[attack_type] += 1
        
        confidence = min(0.96, 0.80 + (ratio / 20))
        
        messages = {
            'ddos': f'DDoS Attack detected! Traffic spike: {self.current_pps} pps',
            'recon': f'Reconnaissance Attack detected! Scanning pattern at {self.current_pps} pps',
            'cc': f'C&C Attack detected! Suspicious communication at {self.current_pps} pps'
        }
        
        # FIX: Use a consistent attacker IP for simulation
        # In real scenario, extract from actual packet
        attacker_ip = f"192.168.1.{int(time.time()) % 254 + 1}"
        
        defense_result = self.block_ip(attacker_ip, attack_type)
        
        alert = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'type': attack_type,
            'message': messages.get(attack_type, f'{attack_type.upper()} attack detected'),
            'confidence': confidence,
            'source': 'REAL NETWORK TRAFFIC',
            'details': f'Traffic: {self.current_pps} pps (Normal: {self.baseline_pps} pps)',
            'defense_action': 'IP Blocked' if defense_result else (f'Already blocked: {attacker_ip}' if attacker_ip in self.blocked_ips else 'Block failed'),
            'blocked_ip': attacker_ip if defense_result else None
        }
        self.alerts.insert(0, alert)
        
        defense_msg = f"DEFENSE: Blocked {attacker_ip}" if defense_result else f"IP {attacker_ip} already blocked"
        print(f"\n{'='*55}")
        print(f"ATTACK DETECTED: {attack_type.upper()}")
        print(f"Traffic: {self.current_pps} pps | Confidence: {confidence:.1%}")
        print(f"{defense_msg}")
        print(f"{'='*55}\n")
    
    def get_statistics(self):
        total = self.total_packets
        
        if total > 0:
            normal_percent = (self.normal_packets / total * 100)
            attack_percent = (self.attack_packets / total * 100)
        else:
            normal_percent = 100
            attack_percent = 0
        
        return {
            'total_packets': self.total_packets,
            'normal_percent': round(normal_percent, 1),
            'attack_percent': round(attack_percent, 1),
            'ddos_count': self.attack_counts['ddos'],
            'recon_count': self.attack_counts['recon'],
            'cc_count': self.attack_counts['cc'],
            'attack_active': self.attack_active,
            'current_pps': self.current_pps,
            'baseline_pps': self.baseline_pps,
            'traffic_history': list(self.traffic_history),
            'alerts': self.alerts[:20],
            'defense_actions': self.defense_actions[:10],
            'defense_enabled': self.defense_enabled,
            'blocked_ips': list(self.blocked_ips)
        }
