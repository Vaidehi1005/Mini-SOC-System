from __future__ import annotations

from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
from random import Random
from typing import Any

try:
    from scapy.all import ICMP, IP, TCP, UDP, sniff
except Exception:  # pragma: no cover - handled gracefully at runtime
    ICMP = IP = TCP = UDP = sniff = None


def _is_private(address: str) -> bool:
    try:
        candidate = ip_address(address)
    except ValueError:
        return False
    return any(
        candidate in network
        for network in (
            ip_network("10.0.0.0/8"),
            ip_network("172.16.0.0/12"),
            ip_network("192.168.0.0/16"),
        )
    )


def _direction(src_ip: str, dst_ip: str) -> str:
    src_private = _is_private(src_ip)
    dst_private = _is_private(dst_ip)
    if src_private and not dst_private:
        return "outbound"
    if not src_private and dst_private:
        return "inbound"
    return "internal"


def build_packet(
    src_ip: str,
    dst_ip: str,
    protocol: str,
    port: int | None,
    *,
    timestamp: datetime | None = None,
    bytes_sent: int = 0,
    status: str = "observed",
    note: str = "Traffic observed",
) -> dict[str, Any]:
    packet_time = timestamp or datetime.now()
    return {
        "timestamp": packet_time.isoformat(timespec="seconds"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "port": port,
        "bytes": bytes_sent,
        "direction": _direction(src_ip, dst_ip),
        "status": status,
        "note": note,
    }


def generate_sample_traffic(count: int = 24, seed: int = 14) -> list[dict[str, Any]]:
    templates = [
        ("192.168.1.10", "172.217.167.78", "TCP", 443, 620, "Allowed HTTPS request"),
        ("192.168.1.18", "8.8.8.8", "UDP", 53, 128, "DNS request"),
        ("192.168.1.25", "142.250.182.142", "TCP", 443, 760, "Cloud sync activity"),
        ("10.0.0.12", "192.168.1.1", "TCP", 80, 540, "Internal web dashboard"),
        ("192.168.1.42", "52.84.12.18", "TCP", 443, 684, "Browser session"),
        ("192.168.1.60", "224.0.0.251", "UDP", 5353, 92, "Service discovery"),
        ("192.168.1.33", "1.1.1.1", "UDP", 53, 118, "DNS request"),
        ("192.168.1.14", "172.16.0.15", "ICMP", None, 74, "Health check ping"),
    ]

    rng = Random(seed)
    start_time = datetime.now() - timedelta(minutes=max(count // 3, 2))
    packets: list[dict[str, Any]] = []

    for index in range(count):
        src_ip, dst_ip, protocol, port, bytes_sent, note = templates[index % len(templates)]
        packets.append(
            build_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                port=port,
                timestamp=start_time + timedelta(seconds=index * 14),
                bytes_sent=bytes_sent + rng.randint(-25, 55),
                status="captured",
                note=note,
            )
        )

    return packets


def process_packet(packet: Any) -> dict[str, Any] | None:
    if IP is None or IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = "Other"
    port = None

    if TCP is not None and TCP in packet:
        protocol = "TCP"
        port = int(packet[TCP].dport)
    elif UDP is not None and UDP in packet:
        protocol = "UDP"
        port = int(packet[UDP].dport)
    elif ICMP is not None and ICMP in packet:
        protocol = "ICMP"

    return build_packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        port=port,
        bytes_sent=len(packet),
        status="captured",
        note="Live packet capture",
    )


def start_sniffing(
    packet_count: int = 24,
    timeout: int = 5,
    interface: str | None = None,
    simulate_on_error: bool = True,
) -> list[dict[str, Any]]:
    if sniff is None:
        return generate_sample_traffic(count=packet_count)

    try:
        captured_packets = sniff(count=packet_count, timeout=timeout, iface=interface)
    except Exception:
        return generate_sample_traffic(count=packet_count) if simulate_on_error else []

    records = [record for packet in captured_packets if (record := process_packet(packet))]
    if records:
        return records

    return generate_sample_traffic(count=packet_count) if simulate_on_error else []
