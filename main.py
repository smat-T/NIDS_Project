import asyncio
import platform
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, simpledialog
import threading
from scapy.all import *
import logging
import json
import time
import bcrypt
from collections import defaultdict
import pygame
import numpy as np

# Logging setup with JSON formatter
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record.created)),
            'level': record.levelname,
            'message': record.msg
        }
        return json.dumps(log_entry)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('NIDS')
handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logger.addHandler(handler)

# Thresholds and configuration
CONFIG_DEFAULTS = {
    'DOS_THRESHOLD': 100,
    'PORT_SCAN_THRESHOLD': 10,
    'BRUTEFORCE_THRESHOLD': 5,
    'ARP_THRESHOLD': 50,
    'PAYLOAD_THRESHOLD': 1000
}

packet_count = defaultdict(int)
port_scan_count = defaultdict(int)
failed_logins = defaultdict(int)
arp_count = defaultdict(int)
last_alert = defaultdict(lambda: 0)
ALERT_COOLDOWN = 30  # Seconds to prevent alert spam

# Admin credentials (hashed)
hashed_username = bcrypt.hashpw(b"admin", bcrypt.gensalt())
hashed_password = bcrypt.hashpw(b"password", bcrypt.gensalt())

# GUI Setup
root = tk.Tk()
root.title("Advanced Network Intrusion Detection System")
root.geometry("800x600")

# Initialize PyGame for sound
pygame.mixer.init()

# Function to generate sound array (Pyodide-compatible)
def generate_alert_sound():
    try:
        sample_rate = 44100
        duration = 1.0
        freq = 440
        t = np.linspace(0, duration, int(sample_rate * duration), False)
        sound_array = (np.sin(2 * np.pi * freq * t) * 32767).astype(np.int16)
        sound_array = np.column_stack((sound_array, sound_array))  # Stereo
        sound = pygame.sndarray.make_sound(sound_array)
        sound.play()
    except Exception as e:
        logger.error(f"Could not play sound: {e}")

# GUI elements
log_display = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=90, height=20)
log_display.grid(column=0, row=0, padx=10, pady=10, columnspan=4)

status_label = tk.Label(root, text="Status: Stopped", fg="red")
status_label.grid(column=0, row=1, padx=5, pady=5)

stats_display = tk.Label(root, text="Packets Processed: 0 | Alerts: 0")
stats_display.grid(column=1, row=1, columnspan=2, padx=5, pady=5)

# Counters for statistics
total_packets = 0
total_alerts = 0

# Log alert function
def log_alert(alert, critical=False):
    global total_alerts
    current_time = time.time()
    alert_key = alert[:50]  # Unique key for alert
    if current_time - last_alert[alert_key] > ALERT_COOLDOWN:
        logger.info(alert)
        log_display.insert(tk.END, alert + "\n")
        log_display.yview(tk.END)
        if critical:
            generate_alert_sound()
            messagebox.showwarning("Critical Alert", alert)
        total_alerts += 1
        last_alert[alert_key] = current_time
        update_stats()

# Update statistics display
def update_stats():
    stats_display.config(text=f"Packets Processed: {total_packets} | Alerts: {total_alerts}")

# Login check
def check_login(username, password):
    global failed_login_attempts
    try:
        if bcrypt.checkpw(username.encode('utf-8'), hashed_username) and bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            return True
        else:
            failed_login_attempts += 1
            if failed_login_attempts >= CONFIG_DEFAULTS['BRUTEFORCE_THRESHOLD']:
                log_alert("[ALERT] Brute force login attempt detected!", critical=True)
            return False
    except Exception as e:
        logger.error(f"Login check failed: {e}")
        return False

# Login prompt
def login_prompt(is_start=True):
    username = simpledialog.askstring("Login", "Enter Username:")
    password = simpledialog.askstring("Login", "Enter Password:", show="*")
    if not check_login(username, password):
        messagebox.showerror("Login Failed", "Incorrect credentials! Try again.")
        if is_start:
            root.quit()
        return False
    return True

# Advanced detection functions
def detect_dos_ddos(packet):
    global total_packets
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        packet_count[src_ip] += 1
        total_packets += 1
        if packet_count[src_ip] > CONFIG_DEFAULTS['DOS_THRESHOLD']:
            log_alert(f"[ALERT] Possible DoS/DDoS attack from {src_ip}", critical=True)

def detect_port_scan(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        src_ip = packet[IP].src
        port_scan_count[src_ip] += 1
        if port_scan_count[src_ip] > CONFIG_DEFAULTS['PORT_SCAN_THRESHOLD']:
            log_alert(f"[ALERT] Port scanning detected from {src_ip}", critical=True)

def detect_arp_spoofing(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
        src_ip = packet[ARP].psrc
        arp_count[src_ip] += 1
        if arp_count[src_ip] > CONFIG_DEFAULTS['ARP_THRESHOLD']:
            log_alert(f"[ALERT] Possible ARP spoofing from {src_ip}", critical=True)

def detect_suspicious_payload(packet):
    if packet.haslayer(Raw):
        payload_size = len(packet[Raw].load)
        if payload_size > CONFIG_DEFAULTS['PAYLOAD_THRESHOLD']:
            log_alert(f"[ALERT] Suspicious payload size from {packet[IP].src}: {payload_size} bytes", critical=True)

# Sniffing function
def start_sniffing():
    try:
        sniff(filter="ip or tcp or arp", prn=lambda x: (
            detect_dos_ddos(x),
            detect_port_scan(x),
            detect_arp_spoofing(x),
            detect_suspicious_payload(x)
        ), store=0)
    except Exception as e:
        logger.error(f"Sniffing error: {e}")
        log_alert(f"[ERROR] Sniffing stopped: {e}")

# Start and stop IDS
sniffing = False

def start_system():
    global sniffing
    if not sniffing:
        sniffing = True
        status_label.config(text="Status: Running", fg="green")
        sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        sniff_thread.start()
        log_alert("[INFO] IDS started...")

def stop_system():
    global sniffing
    if sniffing:
        if login_prompt(is_start=False):
            sniffing = False
            status_label.config(text="Status: Stopped", fg="red")
            log_alert("[INFO] IDS stopped.")
        else:
            messagebox.showerror("Login Failed", "Incorrect credentials! Cannot stop the system.")

# Reset counters periodically
def reset_counts():
    while True:
        time.sleep(10)
        packet_count.clear()
        port_scan_count.clear()
        arp_count.clear()
        failed_logins.clear()

# Set thresholds from GUI
def set_thresholds():
    try:
        CONFIG_DEFAULTS['DOS_THRESHOLD'] = int(dos_entry.get())
        CONFIG_DEFAULTS['PORT_SCAN_THRESHOLD'] = int(port_scan_entry.get())
        CONFIG_DEFAULTS['BRUTEFORCE_THRESHOLD'] = int(bruteforce_entry.get())
        CONFIG_DEFAULTS['ARP_THRESHOLD'] = int(arp_entry.get())
        CONFIG_DEFAULTS['PAYLOAD_THRESHOLD'] = int(payload_entry.get())
        log_alert(f"[INFO] Thresholds updated: DoS={CONFIG_DEFAULTS['DOS_THRESHOLD']}, "
                  f"Port Scan={CONFIG_DEFAULTS['PORT_SCAN_THRESHOLD']}, "
                  f"Brute Force={CONFIG_DEFAULTS['BRUTEFORCE_THRESHOLD']}, "
                  f"ARP Spoof={CONFIG_DEFAULTS['ARP_THRESHOLD']}, "
                  f"Payload={CONFIG_DEFAULTS['PAYLOAD_THRESHOLD']}")
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter valid numbers for thresholds.")

# Export logs to JSON
def export_logs():
    log_file = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
    if log_file:
        try:
            with open('ids_log.txt', 'r') as log_f:
                logs = [json.loads(line) for line in log_f if line.strip()]
            with open(log_file, 'w') as out_f:
                json.dump(logs, out_f, indent=2)
            messagebox.showinfo("Export Logs", "Logs exported successfully!")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export logs: {e}")

# GUI elements for thresholds
tk.Label(root, text="DoS Threshold:").grid(column=0, row=2, padx=5, pady=5)
dos_entry = tk.Entry(root)
dos_entry.grid(column=1, row=2, padx=5, pady=5)
dos_entry.insert(0, str(CONFIG_DEFAULTS['DOS_THRESHOLD']))

tk.Label(root, text="Port Scan Threshold:").grid(column=0, row=3, padx=5, pady=5)
port_scan_entry = tk.Entry(root)
port_scan_entry.grid(column=1, row=3, padx=5, pady=5)
port_scan_entry.insert(0, str(CONFIG_DEFAULTS['PORT_SCAN_THRESHOLD']))

tk.Label(root, text="Brute Force Threshold:").grid(column=0, row=4, padx=5, pady=5)
bruteforce_entry = tk.Entry(root)
bruteforce_entry.grid(column=1, row=4, padx=5, pady=5)
bruteforce_entry.insert(0, str(CONFIG_DEFAULTS['BRUTEFORCE_THRESHOLD']))

tk.Label(root, text="ARP Spoof Threshold:").grid(column=0, row=5, padx=5, pady=5)
arp_entry = tk.Entry(root)
arp_entry.grid(column=1, row=5, padx=5, pady=5)
arp_entry.insert(0, str(CONFIG_DEFAULTS['ARP_THRESHOLD']))

tk.Label(root, text="Payload Size Threshold:").grid(column=0, row=6, padx=5, pady=5)
payload_entry = tk.Entry(root)
payload_entry.grid(column=1, row=6, padx=5, pady=5)
payload_entry.insert(0, str(CONFIG_DEFAULTS['PAYLOAD_THRESHOLD']))

set_threshold_button = tk.Button(root, text="Set Thresholds", command=set_thresholds)
set_threshold_button.grid(column=2, row=2, rowspan=5, padx=5, pady=5)

# Buttons
start_button = tk.Button(root, text="Start IDS", command=start_system)
start_button.grid(column=0, row=7, padx=5, pady=5)

stop_button = tk.Button(root, text="Stop IDS", command=stop_system)
stop_button.grid(column=1, row=7, padx=5, pady=5)

export_button = tk.Button(root, text="Export Logs", command=export_logs)
export_button.grid(column=2, row=7, padx=5, pady=5)

# Async main for Pyodide compatibility
async def main():
    reset_thread = threading.Thread(target=reset_counts, daemon=True)
    reset_thread.start()
    if not login_prompt():
        root.quit()
    root.mainloop()

if platform.system() == "Emscripten":
    asyncio.ensure_future(main())
else:
    if __name__ == "__main__":
        asyncio.run(main())