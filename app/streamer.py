import time
import random
from datetime import datetime
from database import get_db_connection
from threat_intel import generate_threat_intel

# Sample mock IoT devices and threats for live streaming
DEVICE_POOL = [
    ("Smart Thermostat", "192.168.1.102", "MQTT"),
    ("ESP32-CAM", "192.168.1.45", "HTTP/TLS"),
    ("Smart TV", "192.168.1.200", "DNS"),
    ("IP Camera", "192.168.1.55", "UPnP"),
    ("Smart Lock", "192.168.1.88", "HTTPS"),
]

THREAT_PROMPTS = [
    (
        "UNENCRYPTED_MQTT",
        "Edge device transmitting plaintext telemetry over port 1883.",
    ),
    (
        "SSRF_LOOPBACK_ABUSE",
        "Attempted internal loopback metadata exfiltration via port 80.",
    ),
    (
        "ANOMALOUS_DNS_BEACON",
        "High-frequency DNS queries to an unrecognized external sink domain.",
    ),
    (
        "UNAUTHORIZED_UPNP_FWD",
        "External gateway port-forwarding request initiated automatically.",
    ),
]


def simulate_live_traffic():
    print("[*] Starting Live IoT Telemetry & Threat Streamer...", flush=True)

    while True:
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Increment total flows randomly to make telemetry counters tick up
        cursor.execute(
            "INSERT INTO flows (pcap_name, timestamp, src_ip, dst_ip, protocol, info) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "live-stream.pcap",
                str(datetime.now()),
                random.choice(DEVICE_POOL)[1],
                "10.0.0.1",
                "TCP",
                "Live telemetry packet stream",
            ),
        )

        # 2. Occasionally inject a rogue alert (roughly every 15-20 seconds)
        if random.random() < 0.4:
            device, ip, proto = random.choice(DEVICE_POOL)
            rule, desc = random.choice(THREAT_PROMPTS)
            full_desc = f"{device} ({ip}): {desc}"

            # Fetch automated Gemini AI analysis
            ai_analysis = generate_threat_intel(rule, full_desc)

            cursor.execute(
                """
                INSERT INTO alerts (pcap_name, rule_name, description, mitre_technique, severity, ai_analysis, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    "live-stream.pcap",
                    rule,
                    full_desc,
                    "T1071 (Application Layer)",
                    "HIGH",
                    ai_analysis,
                    str(datetime.now()),
                ),
            )

            print(
                f"[+] Live Threat Injected & Analyzed by Gemini: {rule} from {device}",
                flush=True,
            )

        conn.commit()
        conn.close()

        # Wait 30 seconds before the next tick
        time.sleep(30)


if __name__ == "__main__":
    simulate_live_traffic()
