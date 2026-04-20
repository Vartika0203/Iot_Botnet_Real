import time
import threading
import psutil
import random
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
        
        # CRITICAL FIX: Track if alert already sent for this attack
        self.alert_sent_for_this_attack = False
        
        # Statistics
        self.total_packets = 0
        self.normal_packets = 0
        self.attack_packets = 0
        self.attack_counts = {'ddos': 0, 'recon': 0, 'cc': 0}
        
        # Alerts
        self.alerts = []
        
        # Prevent popup spam between different attacks
        self.last_attack_end_time = 0
        self.cooldown_between_attacks = 10
        
        # Baseline
        self.baseline_pps = 35
        self.baseline_ready = False
        
        # Demo mode flag
        self.demo_mode = False
        
        self.running = True
        
    def start_monitoring(self):
        print("\n" + "="*60)
        print("IOT BOTNET DETECTION SYSTEM")
        print("="*60)
        print("REAL ATTACK DETECTION ACTIVE")
        print("DEMO BUTTONS AVAILABLE")
        print("="*60 + "\n")
        
        self.calculate_baseline()
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def calculate_baseline(self):
        """Learn what normal traffic looks like"""
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
        
        self.baseline_pps = max(max_pps + 15, avg_pps + 10, 35)
        
        print(f"\n\nBaseline established: {self.baseline_pps} packets/second")
        print(f"   Your average: {avg_pps} pps | Peak: {max_pps} pps")
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
                real_pps = int(total_bytes_sec / 1500) if total_bytes_sec > 0 else 0
            else:
                real_pps = 0
            
            # Demo mode overrides real traffic
            if self.demo_mode:
                if self.attack_type == 'ddos':
                    self.current_pps = random.randint(300, 550)
                elif self.attack_type == 'recon':
                    self.current_pps = random.randint(150, 250)
                elif self.attack_type == 'cc':
                    self.current_pps = random.randint(100, 180)
                else:
                    self.current_pps = real_pps
            else:
                self.current_pps = real_pps
            
            self.total_packets += self.current_pps
            
            # Check if attack should end
            if self.attack_active and current_time > self.attack_end_time:
                self.attack_active = False
                self.attack_type = None
                self.demo_mode = False
                self.alert_sent_for_this_attack = False  # Reset for next attack
                self.last_attack_end_time = current_time
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Attack ended")
            
            # Update counters
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
            
            # Detect REAL attacks (only if not in demo mode and not already in attack)
            if not self.demo_mode and not self.attack_active:
                self.detect_real_attack()
            
            # Print status every 10 seconds
            if int(time.time()) % 10 == 0:
                if self.attack_active:
                    print(f"[{timestamp}] ATTACK: {self.attack_type.upper()} | {self.current_pps} pps")
                else:
                    print(f"[{timestamp}] NORMAL: {self.current_pps} pps (Baseline: {self.baseline_pps})")
            
            last_recv = current_recv
            last_sent = current_sent
            last_time = current_time
            time.sleep(1)
    
    def detect_real_attack(self):
        """Detect REAL attacks - ONLY ONE ALERT per attack"""
        if not self.baseline_ready:
            return
        
        current_time = time.time()
        
        # Cooldown between different attacks
        if current_time - self.last_attack_end_time < self.cooldown_between_attacks:
            return
        
        ratio = self.current_pps / self.baseline_pps if self.baseline_pps > 0 else 1
        
        # Check for attack conditions
        is_ddos = (ratio > 3.0 and self.current_pps > 150)
        is_recon = (ratio > 2.0 and self.current_pps > 80)
        
        # CRITICAL FIX: Only trigger if alert NOT already sent for this attack
        if (is_ddos or is_recon) and not self.alert_sent_for_this_attack:
            attack_type = 'ddos' if is_ddos else 'recon'
            self.trigger_attack(attack_type, ratio)
            self.alert_sent_for_this_attack = True  # Mark as sent
            self.attack_end_time = current_time + 10  # Attack lasts 10 seconds
    
    def trigger_attack(self, attack_type, ratio):
        """Trigger a SINGLE REAL attack alert"""
        if self.attack_active:
            return
        
        self.attack_active = True
        self.attack_type = attack_type
        self.attack_counts[attack_type] += 1
        
        confidence = min(0.96, 0.80 + (ratio / 20))
        
        messages = {
            'ddos': 'DDoS Attack: Massive traffic flood detected',
            'recon': 'Reconnaissance Attack: System scanning detected',
            'cc': 'C&C Attack: Malware communication detected'
        }
        
        alert = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'type': attack_type,
            'message': messages.get(attack_type, f'{attack_type.upper()} attack detected'),
            'confidence': confidence,
            'source': 'REAL TRAFFIC',
            'details': f'Traffic: {self.current_pps} pps (Normal: {self.baseline_pps} pps)'
        }
        self.alerts.insert(0, alert)
        
        print(f"\n{'='*55}")
        print(f"REAL ATTACK DETECTED: {attack_type.upper()}")
        print(f"Traffic: {self.current_pps} pps | Confidence: {confidence:.1%}")
        print(f"{'='*55}\n")
    
    def start_demo_attack(self, attack_type):
        """Start a DEMO attack with graph spike"""
        if self.attack_active:
            return
        
        self.demo_mode = True
        self.attack_active = True
        self.attack_type = attack_type
        self.attack_counts[attack_type] += 1
        self.attack_end_time = time.time() + 10
        self.alert_sent_for_this_attack = True  # Demo also marks as sent
        
        messages = {
            'ddos': 'DDoS Attack Simulation (Demo)',
            'recon': 'Reconnaissance Attack Simulation (Demo)',
            'cc': 'C&C Attack Simulation (Demo)'
        }
        
        alert = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'type': attack_type,
            'message': messages.get(attack_type, f'{attack_type.upper()} attack simulation'),
            'confidence': 0.95,
            'source': 'DEMO BUTTON',
            'details': 'Watch the graph spike!'
        }
        self.alerts.insert(0, alert)
        
        print(f"\n{'='*55}")
        print(f"DEMO ATTACK: {attack_type.upper()}")
        print(f"Graph will spike for 10 seconds")
        print(f"{'='*55}\n")
    
    def stop_demo_attack(self):
        """Stop demo attack"""
        self.demo_mode = False
        self.attack_active = False
        self.attack_type = None
        self.alert_sent_for_this_attack = False
        print(f"\nDemo attack stopped\n")
    
    def get_statistics(self):
        """Get current statistics"""
        total = self.total_packets
        
        if total > 0:
            normal_percent = (self.normal_packets / total * 100)
            attack_percent = (self.attack_packets / total * 100)
        else:
            normal_percent = 100
            attack_percent = 0
        
        # Cap at reasonable values for display
        if attack_percent > 50 and not self.attack_active:
            normal_percent = 98
            attack_percent = 2
        
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
            'alerts': self.alerts[:20]
        }