from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Any

DEFAULT_RULES = {
    "dos_threshold": 12,
    "port_scan_threshold": 7,
    "brute_force_threshold": 5,
    "auth_ports": {21, 22, 3389},
    "high_risk_ports": {21, 22, 23, 3389, 3306, 5432},
}

SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def _normalize_packet(packet: Any) -> dict[str, Any]:
    if isinstance(packet, dict):
        return {
            "timestamp": packet.get("timestamp", datetime.now().isoformat(timespec="seconds")),
            "src_ip": packet.get("src_ip", "unknown"),
            "dst_ip": packet.get("dst_ip", "unknown"),
            "protocol": packet.get("protocol", "Other"),
            "port": packet.get("port"),
            "bytes": packet.get("bytes", 0),
            "status": packet.get("status", "observed"),
            "note": packet.get("note", "Traffic observed"),
        }

    src_ip, dst_ip, protocol, port = packet[:4]
    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "port": port,
        "bytes": 0,
        "status": "observed",
        "note": "Legacy packet format",
    }


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


def _build_alert(
    alert_id: int,
    timestamp: str,
    rule_name: str,
    src_ip: str,
    dst_ip: str,
    protocol: str,
    severity: str,
    details: str,
    recommendation: str,
) -> dict[str, str]:
    return {
        "id": f"ALT-{alert_id:03d}",
        "timestamp": timestamp,
        "rule_name": rule_name,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "severity": severity,
        "details": details,
        "recommendation": recommendation,
    }


def detect_attacks(data: list[Any], rules: dict[str, Any] | None = None) -> list[dict[str, str]]:
    if not data:
        return []

    config = DEFAULT_RULES.copy()
    if rules:
        config.update(rules)

    packets = [_normalize_packet(packet) for packet in data]
    source_counts = Counter()
    source_ports: dict[str, set[int]] = defaultdict(set)
    auth_attempts = Counter()
    unauthorized_attempts: dict[str, list[dict[str, Any]]] = defaultdict(list)
    high_risk_access: dict[str, list[dict[str, Any]]] = defaultdict(list)
    destinations: dict[str, set[str]] = defaultdict(set)
    protocol_counts: dict[str, Counter] = defaultdict(Counter)
    latest_packet: dict[str, dict[str, Any]] = {}

    for packet in packets:
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]
        protocol = packet["protocol"]
        port = packet.get("port")

        source_counts[src_ip] += 1
        destinations[src_ip].add(dst_ip)
        protocol_counts[src_ip][protocol] += 1
        latest_packet[src_ip] = packet

        if isinstance(port, int):
            source_ports[src_ip].add(port)
            if port in config["auth_ports"]:
                auth_attempts[src_ip] += 1
            if port in config["high_risk_ports"]:
                high_risk_access[src_ip].append(packet)

        if not _is_private(src_ip) and _is_private(dst_ip):
            unauthorized_attempts[src_ip].append(packet)

    alerts: list[dict[str, str]] = []
    alert_id = 1

    for src_ip, count in source_counts.items():
        packet = latest_packet[src_ip]
        top_protocol = protocol_counts[src_ip].most_common(1)[0][0]
        dst_value = "multiple" if len(destinations[src_ip]) > 1 else next(iter(destinations[src_ip]))

        if count >= config["dos_threshold"]:
            alerts.append(
                _build_alert(
                    alert_id,
                    packet["timestamp"],
                    "DoS / Traffic Spike",
                    src_ip,
                    dst_value,
                    top_protocol,
                    "Critical",
                    f"{count} packets were captured from this source in the active window.",
                    "Rate-limit or block the source and validate service health.",
                )
            )
            alert_id += 1

        if len(source_ports[src_ip]) >= config["port_scan_threshold"]:
            alerts.append(
                _build_alert(
                    alert_id,
                    packet["timestamp"],
                    "Port Scan Activity",
                    src_ip,
                    dst_value,
                    top_protocol,
                    "High",
                    f"The source touched {len(source_ports[src_ip])} unique ports in a short period.",
                    "Inspect the host, review firewall logs, and block recon traffic if needed.",
                )
            )
            alert_id += 1

        if auth_attempts[src_ip] >= config["brute_force_threshold"]:
            alerts.append(
                _build_alert(
                    alert_id,
                    packet["timestamp"],
                    "Brute Force Attempt",
                    src_ip,
                    dst_value,
                    top_protocol,
                    "High",
                    f"{auth_attempts[src_ip]} attempts targeted authentication-related services.",
                    "Reset credentials, enforce MFA, and review access logs for account misuse.",
                )
            )
            alert_id += 1

        if unauthorized_attempts[src_ip]:
            alerts.append(
                _build_alert(
                    alert_id,
                    unauthorized_attempts[src_ip][-1]["timestamp"],
                    "Unauthorized Access Pattern",
                    src_ip,
                    dst_value,
                    top_protocol,
                    "Medium",
                    "External traffic attempted to reach private network space.",
                    "Validate the source, review segmentation rules, and confirm whether access is expected.",
                )
            )
            alert_id += 1

        risky_hits = len(high_risk_access[src_ip])
        if risky_hits >= 3 and auth_attempts[src_ip] < config["brute_force_threshold"]:
            alerts.append(
                _build_alert(
                    alert_id,
                    high_risk_access[src_ip][-1]["timestamp"],
                    "High-Risk Service Access",
                    src_ip,
                    dst_value,
                    top_protocol,
                    "Medium",
                    f"{risky_hits} requests targeted sensitive service ports such as SSH, RDP, or databases.",
                    "Validate exposure of sensitive services and restrict access to trusted IP ranges.",
                )
            )
            alert_id += 1

    alerts.sort(
        key=lambda alert: (
            SEVERITY_RANK.get(alert["severity"], 0),
            alert["timestamp"],
        ),
        reverse=True,
    )
    return alerts
