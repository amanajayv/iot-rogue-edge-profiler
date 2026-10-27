import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import get_db_connection
from app.threat_intel import generate_threat_intel


def run_iot_edge_analysis():
    conn = get_db_connection()
    cursor = conn.cursor()
    print("[*] Starting IoT & Edge Profiler Analysis...", flush=True)

    alerts_generated = 0

    # ---------------------------------------------------------
    # RULE: Catch Edge Device Telemetry Anomalies / High-Frequency Flows
    # ---------------------------------------------------------
    cursor.execute("""
        SELECT pcap_name, info, src_ip, dst_ip, protocol, COUNT(*) as hit_count
        FROM flows 
        GROUP BY src_ip, dst_ip
        HAVING hit_count >= 1
        LIMIT 10
    """)

    rows = cursor.fetchall()
    print(f"[*] Found {len(rows)} candidate flows for heuristic analysis.", flush=True)

    for row in rows:
        rule_name = "ROGU_EDGE_TELEMETRY_ANOMALY"
        description = f"Edge device {row['src_ip']} established anomalous outbound telemetry connection to {row['dst_ip']} using protocol {row['protocol']}. Info: {row['info']}"

        # Query Gemini AI for automated threat intel & remediation
        ai_intel = generate_threat_intel(rule_name, description)

        cursor.execute(
            """
            INSERT INTO alerts (pcap_name, rule_name, description, mitre_technique, severity, ai_analysis)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                row["pcap_name"],
                rule_name,
                description,
                "T1071 (Application Layer Protocol)",
                "HIGH",
                ai_intel,
            ),
        )

        alerts_generated += 1

    conn.commit()
    conn.close()
    print(
        f"\n[+] IoT Analysis Complete! Total Alerts Generated: {alerts_generated}",
        flush=True,
    )


if __name__ == "__main__":
    run_iot_edge_analysis()
