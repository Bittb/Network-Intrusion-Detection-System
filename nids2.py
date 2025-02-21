import sqlite3
import time
import smtplib
from email.mime.text import MIMEText
from flask import Flask, jsonify, request
import threading
from scapy.all import sniff, IP, TCP, UDP, DNS
from collections import deque
import psutil
from sklearn.ensemble import IsolationForest
import numpy as np

# Initialize Flask app
app = Flask(__name__)

# Database connection with thread safety
def connect_db():
    try:
        conn = sqlite3.connect('nids_signatures.db', check_same_thread=False)  # Allow multi-threading access
        return conn
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
        return None

# Preload attack signatures from the database
def preload_signatures(conn):
    if not conn:
        return {}
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT source_ip, destination_ip, protocol, port, packet_length, payload_pattern, attack_name FROM AttackSignatures")
        signature_map = {}
        for row in cursor.fetchall():
            source_ip, dest_ip, protocol, port, pkt_len, payload_pattern, attack_name = row
            signature_map[(source_ip, dest_ip, protocol, port, pkt_len, payload_pattern)] = attack_name
        return signature_map
    except sqlite3.Error as e:
        print(f"Error loading signatures: {e}")
        return {}

# Fetch active IPv4 addresses on the system
def get_active_ips():
    active_ips = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # IPv4 address
                active_ips.append(addr.address)
    return active_ips

# Load user configurations from the database
def load_user_config(conn):
    default_config = {
        'email_alert_enabled': False,
        'alert_email': '',
        'packet_size_threshold': 1500,
        'monitored_ips': []
    }
    if not conn:
        return default_config
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT email_alert_enabled, alert_email, packet_size_threshold FROM Configurations LIMIT 1")
        row = cursor.fetchone()
        if row:
            return {
                'email_alert_enabled': row[0],
                'alert_email': row[1],
                'packet_size_threshold': row[2],
                'monitored_ips': get_active_ips()
            }
        return default_config
    except sqlite3.Error as e:
        print(f"Error loading user config: {e}")
        return default_config

# Periodically refresh monitored IPs
def refresh_monitored_ips(user_config, interval=60):
    while True:
        user_config['monitored_ips'] = get_active_ips()
        print(f"Refreshed monitored IPs: {user_config['monitored_ips']}")
        time.sleep(interval)

# Store detected anomalies in the database
def log_anomaly(conn, anomaly_type, description, packet, packet_size):
    if not conn:
        return
    try:
        cursor = conn.cursor()
        source_ip = packet[IP].src if packet.haslayer(IP) else None
        dest_ip = packet[IP].dst if packet.haslayer(IP) else None
        protocol = 'TCP' if packet.haslayer(TCP) else 'UDP' if packet.haslayer(UDP) else 'DNS' if packet.haslayer(DNS) else 'Unknown'
        cursor.execute("INSERT INTO Anomalies (timestamp, anomaly_type, description, packet_size, source_ip, destination_ip, protocol) VALUES (datetime('now'), ?, ?, ?, ?, ?, ?)",
                       (anomaly_type, description, packet_size, source_ip, dest_ip, protocol))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error logging anomaly: {e}")

# Send email alert
def send_email_alert(subject, message, recipient_email):
    try:
        sender_email = 'nids@example.com'  # Change this to your email
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = recipient_email

        with smtplib.SMTP('smtp.example.com', 587) as server:
            server.starttls()
            server.login('your_email@example.com', 'password')  # Login details for SMTP server
            server.sendmail(sender_email, [recipient_email], msg.as_string())
    except Exception as e:
        print(f"Error sending email: {e}")

# Check if a packet matches known attack signatures
def check_signature(packet, signature_map):
    if not signature_map:
        return "Signature detection disabled (no database available)."
    source_ip = packet[IP].src if packet.haslayer(IP) else None
    dest_ip = packet[IP].dst if packet.haslayer(IP) else None
    payload = str(packet['Raw'].load) if packet.haslayer('Raw') else ""
    packet_length = len(packet)

    protocol = None
    port = None
    if packet.haslayer(TCP):
        protocol = "TCP"
        port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        port = packet[UDP].dport
    elif packet.haslayer(DNS):
        protocol = "DNS"
        port = 53

    if (source_ip, dest_ip, protocol, port, packet_length, payload) in signature_map:
        return f"Alert: {signature_map[(source_ip, dest_ip, protocol, port, packet_length, payload)]} detected!"
    return "No known attacks detected."

# Enhanced anomaly detection using Isolation Forest
def ml_anomaly_detection(packet, model):
    packet_features = [
        len(packet),
        1 if packet.haslayer(TCP) else 0,
        1 if packet.haslayer(UDP) else 0,
        1 if packet.haslayer(DNS) else 0
    ]
    prediction = model.predict([packet_features])
    if prediction[0] == -1:  # -1 indicates an anomaly
        return "Anomaly detected via ML"
    return None

# Detect anomalies with combined methods
def detect_anomalies(packet, packet_sizes, conn, user_config, ml_model):
    packet_size = len(packet)
    packet_sizes.append(packet_size)

    if packet_size > user_config['packet_size_threshold']:
        print(f"Anomaly Detected: Large packet (size: {packet_size}).")
        log_anomaly(conn, "Packet Size", f"Large packet detected: {packet_size}", packet, packet_size)

    ml_alert = ml_anomaly_detection(packet, ml_model)
    if ml_alert:
        print(ml_alert)
        log_anomaly(conn, "ML Detection", ml_alert, packet, packet_size)

# Process packet
def process_packet(packet, signature_map, packet_sizes, user_config, conn, ml_model):
    # Create a new database connection for this thread
    conn = connect_db()

    source_ip = packet[IP].src if packet.haslayer(IP) else None
    dest_ip = packet[IP].dst if packet.haslayer(IP) else None

    if source_ip not in user_config['monitored_ips'] and dest_ip not in user_config['monitored_ips']:
        return  # Ignore packets not involving monitored IPs

    alert = check_signature(packet, signature_map)
    if "Alert" in alert and user_config['email_alert_enabled']:
        send_email_alert("NIDS Alert", alert, user_config['alert_email'])

    detect_anomalies(packet, packet_sizes, conn, user_config, ml_model)

# Capture and process packets
def capture_and_process_packets(signature_map, user_config, conn, ml_model):
    packet_sizes = deque(maxlen=100)
    while True:
        packet = sniff(count=1)[0]
        threading.Thread(target=process_packet, args=(packet, signature_map, packet_sizes, user_config, conn, ml_model)).start()

# Main NIDS initialization
def main():
    conn = connect_db()
    signature_map = preload_signatures(conn)
    user_config = load_user_config(conn)

    # Start thread to refresh monitored IPs
    threading.Thread(target=refresh_monitored_ips, args=(user_config,), daemon=True).start()

    # Train Isolation Forest model
    ml_model = IsolationForest(contamination=0.1)
    ml_model.fit(np.random.rand(100, 4))  # Dummy training data

    print("NIDS starting...")
    capture_and_process_packets(signature_map, user_config, conn, ml_model)

if __name__ == '__main__':
    threading.Thread(target=main).start()
    app.run(host='0.0.0.0', port=5000)

