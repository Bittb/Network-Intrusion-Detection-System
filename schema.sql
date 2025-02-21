CREATE TABLE AttackSignatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    port INTEGER,
    packet_length INTEGER,
    payload_pattern TEXT,
    attack_name TEXT
);

CREATE TABLE Configurations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_alert_enabled BOOLEAN,
    alert_email TEXT,
    packet_size_threshold INTEGER,
    monitored_ips TEXT
);

CREATE TABLE Anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    anomaly_type TEXT,
    description TEXT,
    packet_size INTEGER,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT
);

CREATE TABLE Blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT
);

