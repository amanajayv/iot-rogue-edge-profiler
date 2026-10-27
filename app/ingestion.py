import sys
import os

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyshark
from app.database import get_db_connection


def parse_and_store_pcap(pcap_path: str):
    if not os.path.exists(pcap_path):
        print(f"[!] Error: File {pcap_path} not found.", flush=True)
        return

    pcap_name = os.path.basename(pcap_path)
    print(f"[*] Starting ingestion for: {pcap_name}", flush=True)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Optimized filter: Extract DNS, HTTP, and TLS SNI Client Hellos
    cap = pyshark.FileCapture(
        pcap_path,
        display_filter="dns or http or tls.handshake.type == 1",
        keep_packets=False,
    )

    flow_records = []
    packet_count = 0

    print("[*] Processing packet stream...", flush=True)

    for packet in cap:
        packet_count += 1

        if packet_count % 50 == 0:
            print(f"[>] Ingested {packet_count} packets...", flush=True)

        try:
            timestamp = str(packet.sniff_time)

            if hasattr(packet, "ip"):
                src_ip = str(packet.ip.src)
                dst_ip = str(packet.ip.dst)
            elif hasattr(packet, "ipv6"):
                src_ip = str(packet.ipv6.src)
                dst_ip = str(packet.ipv6.dst)
            else:
                continue

            protocol = (
                str(packet.transport_layer)
                if (hasattr(packet, "transport_layer") and packet.transport_layer)
                else "OTHER"
            )

            info = ""
            if hasattr(packet, "dns"):
                if hasattr(packet.dns, "qry_name"):
                    info = f"DNS Query: {packet.dns.qry_name}"
                elif hasattr(packet.dns, "resp_name"):
                    info = f"DNS Response: {packet.dns.resp_name}"
            elif hasattr(packet, "http"):
                host = getattr(packet.http, "host", "")
                uri = getattr(packet.http, "request_uri", "")
                info = f"HTTP {getattr(packet.http, 'request_method', '')} {host}{uri}".strip()
            elif hasattr(packet, "ssl") or hasattr(packet, "tls"):
                tls_layer = packet.ssl if hasattr(packet, "ssl") else packet.tls
                if hasattr(tls_layer, "handshake_extensions_server_name"):
                    info = f"TLS SNI: {tls_layer.handshake_extensions_server_name}"

            if not info and hasattr(packet, "highest_layer"):
                info = f"Layer: {packet.highest_layer}"

            # Cast every tuple element strictly to string for SQLite parameter binding
            flow_records.append(
                (
                    str(pcap_name),
                    str(timestamp),
                    str(src_ip),
                    str(dst_ip),
                    str(protocol),
                    str(info),
                )
            )

            if len(flow_records) >= 100:
                cursor.executemany(
                    "INSERT INTO flows (pcap_name, timestamp, src_ip, dst_ip, protocol, info) VALUES (?, ?, ?, ?, ?, ?)",
                    flow_records,
                )
                conn.commit()
                flow_records.clear()

        except Exception:
            continue

    if flow_records:
        try:
            cursor.executemany(
                "INSERT INTO flows (pcap_name, timestamp, src_ip, dst_ip, protocol, info) VALUES (?, ?, ?, ?, ?, ?)",
                flow_records,
            )
            conn.commit()
        except Exception as e:
            print(f"[!] Error inserting final batch: {e}", flush=True)

    conn.close()
    cap.close()
    print(
        f"\n[+] Ingestion Complete! Total Packets: {packet_count} from {pcap_name}",
        flush=True,
    )


if __name__ == "__main__":
    pcaps_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pcaps"
    )

    pcap_files = [
        f
        for f in os.listdir(pcaps_dir)
        if (f.endswith(".pcap") or f.endswith(".pcapng"))
        and os.path.isfile(os.path.join(pcaps_dir, f))
    ]

    if pcap_files:
        target = os.path.join(pcaps_dir, pcap_files[0])
        parse_and_store_pcap(target)
    else:
        print("[!] No valid .pcap files found in pcaps/ directory.", flush=True)
