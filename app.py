from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from attack import available_profiles, generate_attack_traffic
from encryption import decrypt_file, encrypt_with_generated_key
from ids import detect_attacks
from scanner import scan_url, summarize_scan_results
from sniffer import generate_sample_traffic, start_sniffing

LOG_FILE = Path(__file__).with_name("logs.txt")
SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

st.set_page_config(page_title="Mini SOC Platform", layout="wide")


def apply_theme() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;700&display=swap');

        :root {
            --soc-bg: #f3f7f4;
            --soc-panel: rgba(255, 255, 255, 0.88);
            --soc-ink: #111111;
            --soc-muted: #3f4a46;
            --soc-accent: #1d7d5f;
            --soc-accent-soft: #eef6f2;
            --soc-shadow: 0 14px 34px rgba(22, 49, 43, 0.10);
        }

        .stApp {
            background:
                radial-gradient(circle at top left, rgba(29, 125, 95, 0.18), transparent 28%),
                radial-gradient(circle at top right, rgba(181, 71, 39, 0.12), transparent 24%),
                linear-gradient(180deg, #f7faf7 0%, var(--soc-bg) 100%);
            color: var(--soc-ink);
            font-family: "IBM Plex Sans", sans-serif;
        }

        h1, h2, h3 {
            font-family: "Space Grotesk", sans-serif;
            color: var(--soc-ink);
            letter-spacing: -0.02em;
        }

        p, label, .stMarkdown, .stCaption {
            color: var(--soc-ink) !important;
        }

        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #fbfdfb 0%, #eef4ef 100%);
            border-right: 1px solid rgba(17, 17, 17, 0.08);
        }

        [data-testid="stSidebar"] * {
            color: #111111 !important;
        }

        .hero {
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.94), rgba(238, 246, 242, 0.96));
            border: 1px solid rgba(17, 17, 17, 0.08);
            border-radius: 26px;
            box-shadow: var(--soc-shadow);
            color: var(--soc-ink);
            display: grid;
            gap: 1rem;
            grid-template-columns: 2fr 1fr;
            margin-bottom: 1rem;
            padding: 1.8rem;
        }

        .hero-kicker {
            color: var(--soc-muted);
            font-size: 0.82rem;
            font-weight: 700;
            letter-spacing: 0.14em;
            margin-bottom: 0.7rem;
            text-transform: uppercase;
        }

        .hero-title {
            font-family: "Space Grotesk", sans-serif;
            font-size: 2.2rem;
            font-weight: 700;
            line-height: 1.1;
            margin: 0;
        }

        .hero-text {
            color: var(--soc-ink);
            margin-top: 0.8rem;
            max-width: 56rem;
        }

        .hero-panel {
            background: rgba(238, 246, 242, 0.95);
            border: 1px solid rgba(17, 17, 17, 0.08);
            border-radius: 20px;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            justify-content: center;
            padding: 1.2rem;
        }

        .status-label {
            color: var(--soc-muted);
            font-size: 0.84rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .status-value {
            color: var(--soc-ink);
            font-family: "Space Grotesk", sans-serif;
            font-size: 1.4rem;
            font-weight: 700;
        }

        .status-note {
            color: var(--soc-ink);
            font-size: 0.92rem;
        }

        .module-card {
            background: var(--soc-panel);
            border: 1px solid rgba(22, 49, 43, 0.08);
            border-radius: 22px;
            box-shadow: var(--soc-shadow);
            padding: 1rem 1.15rem;
        }

        .module-label {
            color: var(--soc-muted);
            font-size: 0.8rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            margin-bottom: 0.4rem;
            text-transform: uppercase;
        }

        .module-value {
            color: var(--soc-ink);
            font-family: "Space Grotesk", sans-serif;
            font-size: 1.7rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }

        .module-note {
            color: var(--soc-muted);
            font-size: 0.92rem;
        }

        .section-header {
            background: rgba(255, 255, 255, 0.82);
            border: 1px solid rgba(17, 17, 17, 0.08);
            border-radius: 20px;
            box-shadow: var(--soc-shadow);
            margin: 1.35rem 0 1rem;
            padding: 1rem 1.2rem;
        }

        .section-kicker {
            color: var(--soc-muted);
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0.12em;
            margin-bottom: 0.35rem;
            text-transform: uppercase;
        }

        .section-title {
            color: var(--soc-ink);
            font-family: "Space Grotesk", sans-serif;
            font-size: 1.45rem;
            font-weight: 700;
        }

        .section-note {
            color: var(--soc-ink);
            font-size: 0.95rem;
            margin-top: 0.45rem;
        }

        .stButton > button,
        .stDownloadButton > button {
            background: #ffffff;
            border: 1px solid rgba(17, 17, 17, 0.14);
            border-radius: 14px;
            box-shadow: 0 8px 20px rgba(17, 17, 17, 0.08);
            color: #111111;
            font-size: 0.96rem;
            font-weight: 700;
            padding: 0.6rem 1rem;
        }

        .stButton > button:hover,
        .stDownloadButton > button:hover {
            background: var(--soc-accent-soft);
            border-color: rgba(29, 125, 95, 0.45);
            color: #111111;
        }

        .stButton > button:focus,
        .stDownloadButton > button:focus {
            border-color: #1d7d5f;
            box-shadow: 0 0 0 0.18rem rgba(29, 125, 95, 0.18);
            color: #111111;
        }

        [data-testid="stSidebar"] .stButton > button,
        [data-testid="stSidebar"] .stDownloadButton > button {
            background: #ffffff !important;
            color: #111111 !important;
        }

        [data-testid="stSidebar"] .stButton > button p,
        [data-testid="stSidebar"] .stDownloadButton > button p,
        [data-testid="stSidebar"] .stButton > button span,
        [data-testid="stSidebar"] .stDownloadButton > button span {
            color: #111111 !important;
        }

        .stTextInput input,
        .stTextArea textarea,
        .stSelectbox div[data-baseweb="select"] > div,
        .stMultiSelect div[data-baseweb="select"] > div {
            background: rgba(255, 255, 255, 0.92);
            color: #111111 !important;
        }

        [data-testid="stMetricLabel"],
        [data-testid="stMetricLabel"] *,
        [data-testid="stMetricValue"],
        [data-testid="stMetricValue"] *,
        [data-testid="stFileUploaderDropzone"] *,
        .stAlert,
        .stAlert * {
            color: #111111 !important;
        }

        @media (max-width: 960px) {
            .hero {
                grid-template-columns: 1fr;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def build_signature(record: dict) -> str:
    return "|".join(
        str(record.get(field, "")).strip()
        for field in ("category", "severity", "event", "source", "details")
    )


def read_logs(limit: int | None = 200) -> pd.DataFrame:
    LOG_FILE.touch(exist_ok=True)

    records: list[dict] = []
    for line in LOG_FILE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            records.append(
                {
                    "timestamp": "",
                    "category": "legacy",
                    "severity": "Info",
                    "event": line.strip(),
                    "source": "-",
                    "details": line.strip(),
                }
            )

    log_df = pd.DataFrame(records)
    if log_df.empty:
        return pd.DataFrame(
            columns=["timestamp", "category", "severity", "event", "source", "details"]
        )

    return log_df.tail(limit) if limit is not None else log_df


def append_log_records(records: list[dict]) -> None:
    if not records:
        return

    if "logged_signatures" not in st.session_state:
        existing_df = read_logs(limit=None)
        st.session_state.logged_signatures = {
            build_signature(record) for record in existing_df.to_dict("records")
        }

    with LOG_FILE.open("a", encoding="utf-8") as log_file:
        for record in records:
            signature = build_signature(record)
            if signature in st.session_state.logged_signatures:
                continue
            st.session_state.logged_signatures.add(signature)
            log_file.write(json.dumps(record) + "\n")


def initialize_state() -> None:
    LOG_FILE.touch(exist_ok=True)
    if "traffic" not in st.session_state:
        st.session_state.traffic = generate_sample_traffic(count=24)
    if "monitoring_mode" not in st.session_state:
        st.session_state.monitoring_mode = "Sample Baseline"
    if "scan_results" not in st.session_state:
        st.session_state.scan_results = []
    if "scan_target" not in st.session_state:
        st.session_state.scan_target = ""
    if "logged_signatures" not in st.session_state:
        existing_df = read_logs(limit=None)
        st.session_state.logged_signatures = {
            build_signature(record) for record in existing_df.to_dict("records")
        }


def refresh_traffic(
    data_source: str,
    packet_count: int,
    capture_timeout: int,
    simulation_profile: str,
) -> None:
    if data_source == "Sample Baseline":
        st.session_state.traffic = generate_sample_traffic(count=packet_count)
        st.session_state.monitoring_mode = "Sample Baseline"
    elif data_source == "Attack Simulation":
        st.session_state.traffic = generate_attack_traffic(
            profile=simulation_profile,
            count=packet_count,
        )
        st.session_state.monitoring_mode = simulation_profile
    else:
        st.session_state.traffic = start_sniffing(
            packet_count=packet_count,
            timeout=capture_timeout,
            simulate_on_error=True,
        )
        st.session_state.monitoring_mode = "Live Capture"


def build_traffic_frame(traffic: list[dict]) -> pd.DataFrame:
    traffic_df = pd.DataFrame(traffic)
    if traffic_df.empty:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "src_ip",
                "dst_ip",
                "protocol",
                "port",
                "bytes",
                "direction",
                "status",
                "note",
            ]
        )

    traffic_df["timestamp"] = pd.to_datetime(traffic_df["timestamp"], errors="coerce")
    traffic_df["port"] = pd.to_numeric(traffic_df["port"], errors="coerce")
    traffic_df["bytes"] = pd.to_numeric(traffic_df["bytes"], errors="coerce").fillna(0)
    return traffic_df.sort_values("timestamp", ascending=False)


def highest_severity(alert_df: pd.DataFrame) -> str:
    if alert_df.empty:
        return "Stable"
    return max(alert_df["severity"], key=lambda value: SEVERITY_ORDER.get(value, 0))


def render_stat_card(label: str, value: str, note: str) -> None:
    st.markdown(
        f"""
        <div class="module-card">
            <div class="module-label">{label}</div>
            <div class="module-value">{value}</div>
            <div class="module-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_section_header(kicker: str, title: str, note: str) -> None:
    st.markdown(
        f"""
        <div class="section-header">
            <div class="section-kicker">{kicker}</div>
            <div class="section-title">{title}</div>
            <div class="section-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


apply_theme()
initialize_state()

st.sidebar.title("SOC Controls")
data_source = st.sidebar.radio(
    "Traffic source",
    ["Sample Baseline", "Attack Simulation", "Live Capture"],
)
packet_count = st.sidebar.slider("Traffic records", min_value=12, max_value=72, value=24, step=6)
capture_timeout = st.sidebar.slider("Capture timeout (seconds)", 2, 15, 5)
simulation_profile = "Mixed Attack Demo"
if data_source == "Attack Simulation":
    simulation_profile = st.sidebar.selectbox("Simulation profile", available_profiles())

if st.sidebar.button("Load Traffic", use_container_width=True):
    refresh_traffic(data_source, packet_count, capture_timeout, simulation_profile)

if st.sidebar.button("Clear Logs", use_container_width=True):
    LOG_FILE.write_text("", encoding="utf-8")
    st.session_state.logged_signatures = set()

st.sidebar.caption(
    "Live capture may require administrative privileges. "
    "If capture is unavailable, the dashboard falls back to generated demo traffic."
)

st.sidebar.divider()
st.sidebar.subheader("Filters")
search_ip = st.sidebar.text_input("Search IP")
protocol_options = ["TCP", "UDP", "ICMP", "Other"]
selected_protocols = st.sidebar.multiselect(
    "Protocol filter",
    protocol_options,
    default=protocol_options,
)
severity_options = ["Critical", "High", "Medium", "Low", "Info"]
selected_severities = st.sidebar.multiselect(
    "Alert severity",
    severity_options,
    default=["Critical", "High", "Medium", "Low"],
)

traffic_df = build_traffic_frame(st.session_state.traffic)
alerts = detect_attacks(st.session_state.traffic)
alert_df = pd.DataFrame(alerts)
if not alert_df.empty:
    alert_df["timestamp"] = pd.to_datetime(alert_df["timestamp"], errors="coerce")
    alert_df = alert_df.sort_values(
        by=["severity", "timestamp"],
        ascending=[False, False],
        key=lambda series: series.map(SEVERITY_ORDER)
        if series.name == "severity"
        else series,
    )

append_log_records(
    [
        {
            "timestamp": alert["timestamp"],
            "category": "ids",
            "severity": alert["severity"],
            "event": alert["rule_name"],
            "source": alert["src_ip"],
            "details": alert["details"],
        }
        for alert in alerts
    ]
)

filtered_traffic_df = traffic_df.copy()
if search_ip:
    matches = (
        filtered_traffic_df["src_ip"].astype(str).str.contains(search_ip, case=False, na=False)
        | filtered_traffic_df["dst_ip"].astype(str).str.contains(search_ip, case=False, na=False)
    )
    filtered_traffic_df = filtered_traffic_df[matches]

if selected_protocols:
    filtered_traffic_df = filtered_traffic_df[
        filtered_traffic_df["protocol"].isin(selected_protocols)
    ]

filtered_alert_df = alert_df.copy()
if not filtered_alert_df.empty and selected_severities:
    filtered_alert_df = filtered_alert_df[
        filtered_alert_df["severity"].isin(selected_severities)
    ]

scan_results = st.session_state.scan_results
scan_summary = summarize_scan_results(scan_results)
finding_count = len(filtered_alert_df) + scan_summary["finding_count"]
current_mode = st.session_state.monitoring_mode

st.markdown(
    f"""
    <div class="hero">
        <div>
            <div class="hero-kicker">Integrated Cyber Security Monitoring and Threat Detection System</div>
            <div class="hero-title">Mini SOC Platform</div>
            <div class="hero-text">
                Traffic monitoring, attack simulation, threat review, web scanning, and secure file handling are now all visible on one page.
            </div>
        </div>
        <div class="hero-panel">
            <div class="status-label">Current Monitoring Mode</div>
            <div class="status-value">{current_mode}</div>
            <div class="status-note">
                {len(traffic_df)} traffic records loaded with {len(alert_df)} IDS alerts in the active capture window.
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

card_cols = st.columns(4)
with card_cols[0]:
    render_stat_card("Traffic Records", str(len(traffic_df)), "Packets or simulated events in the current view")
with card_cols[1]:
    render_stat_card(
        "Alert Queue",
        str(len(filtered_alert_df)),
        "Rule-based IDS findings after applying severity filters",
    )
with card_cols[2]:
    render_stat_card(
        "Unique Sources",
        str(traffic_df["src_ip"].nunique() if not traffic_df.empty else 0),
        "Distinct IPs seen in the latest capture window",
    )
with card_cols[3]:
    render_stat_card(
        "Top Severity",
        highest_severity(filtered_alert_df),
        f"{finding_count} total open findings across IDS and scanner modules",
    )

render_section_header(
    "Overview",
    "Live Traffic Overview",
    "This section shows the active traffic feed, protocol distribution, and high-activity sources.",
)

chart_col, protocol_col = st.columns([1.6, 1.0])
with chart_col:
    if not traffic_df.empty and traffic_df["timestamp"].notna().any():
        timeline_df = (
            traffic_df.sort_values("timestamp")
            .set_index("timestamp")
            .resample("30s")
            .size()
            .rename("events")
            .to_frame()
        )
        st.line_chart(timeline_df)
    else:
        st.info("No timestamped traffic is available yet.")

with protocol_col:
    protocol_counts = traffic_df["protocol"].value_counts().to_frame(name="count")
    if not protocol_counts.empty:
        st.bar_chart(protocol_counts)
    else:
        st.info("Protocol distribution will appear after traffic is loaded.")

top_sources_col, top_ports_col = st.columns(2)
with top_sources_col:
    st.markdown("#### Top Source IPs")
    source_counts = (
        traffic_df["src_ip"].value_counts().head(8).rename_axis("src_ip").reset_index(name="events")
        if not traffic_df.empty
        else pd.DataFrame(columns=["src_ip", "events"])
    )
    st.dataframe(source_counts, width="stretch", hide_index=True)

with top_ports_col:
    st.markdown("#### Most Active Ports")
    port_counts = (
        traffic_df.dropna(subset=["port"])["port"]
        .astype(int)
        .value_counts()
        .head(8)
        .rename_axis("port")
        .reset_index(name="events")
        if not traffic_df.empty
        else pd.DataFrame(columns=["port", "events"])
    )
    st.dataframe(port_counts, width="stretch", hide_index=True)

st.markdown("#### Traffic Records")
st.dataframe(filtered_traffic_df, width="stretch", hide_index=True)

render_section_header(
    "Threat Monitor",
    "Threat Detection and Log Monitoring",
    "Alerts are generated by rule-based detections for traffic spikes, brute force patterns, scans, and unauthorized access.",
)

if filtered_alert_df.empty:
    st.success("No IDS rules are triggered for the current traffic window.")
else:
    st.dataframe(filtered_alert_df, width="stretch", hide_index=True)
    st.download_button(
        "Download Alert Report",
        data=filtered_alert_df.to_csv(index=False).encode("utf-8"),
        file_name="soc_alert_report.csv",
        mime="text/csv",
    )

severity_col, logs_col = st.columns([1.0, 1.3])
with severity_col:
    st.markdown("#### Severity Distribution")
    if not filtered_alert_df.empty:
        severity_chart = (
            filtered_alert_df["severity"]
            .value_counts()
            .reindex(severity_options, fill_value=0)
            .to_frame(name="count")
        )
        st.bar_chart(severity_chart)
    else:
        st.info("Severity distribution appears when alerts are present.")

with logs_col:
    st.markdown("#### Centralized Logs")
    log_df = read_logs(limit=200)
    st.dataframe(log_df, width="stretch", hide_index=True)

render_section_header(
    "Web Scanner",
    "Defensive Web Vulnerability Scanner",
    "The scanner runs lightweight checks for reflection, SQL-style error exposure, risky methods, and missing headers.",
)

scan_target = st.text_input(
    "Target URL",
    value=st.session_state.scan_target,
    placeholder="https://example.com",
)

if st.button("Run Defensive Scan", use_container_width=True):
    st.session_state.scan_target = scan_target
    st.session_state.scan_results = scan_url(scan_target)
    append_log_records(
        [
            {
                "timestamp": result["timestamp"],
                "category": "scanner",
                "severity": result["severity"],
                "event": result["name"],
                "source": scan_target or "-",
                "details": result["details"],
            }
            for result in st.session_state.scan_results
        ]
    )

scan_results = st.session_state.scan_results
scan_summary = summarize_scan_results(scan_results)

summary_cols = st.columns(3)
summary_cols[0].metric("Checks Run", scan_summary["total_checks"])
summary_cols[1].metric("Findings", scan_summary["finding_count"])
summary_cols[2].metric("High Severity", scan_summary["high_severity_count"])

if scan_results:
    scan_df = pd.DataFrame(scan_results)
    scan_df["timestamp"] = pd.to_datetime(scan_df["timestamp"], errors="coerce")
    st.dataframe(scan_df, width="stretch", hide_index=True)
else:
    st.info("Run a scan to populate the vulnerability report.")

render_section_header(
    "Secure Files",
    "Secure File Transfer",
    "The encryption module uses Fernet-based authenticated encryption, which protects both confidentiality and integrity.",
)

encrypt_col, decrypt_col = st.columns(2)

with encrypt_col:
    st.markdown("#### Encrypt a File")
    file_to_encrypt = st.file_uploader("Upload a file", key="encrypt_upload")
    if file_to_encrypt and st.button("Encrypt File", key="encrypt_button", use_container_width=True):
        encrypted_data, key = encrypt_with_generated_key(file_to_encrypt.getvalue())
        st.success("File encrypted successfully.")
        st.code(key.decode("utf-8"), language="text")
        st.download_button(
            "Download Encrypted File",
            data=encrypted_data,
            file_name=f"{file_to_encrypt.name}.soc",
            mime="application/octet-stream",
        )

with decrypt_col:
    st.markdown("#### Decrypt a File")
    file_to_decrypt = st.file_uploader("Upload an encrypted file", key="decrypt_upload")
    user_key = st.text_input("Enter decryption key", key="decrypt_key")
    if (
        file_to_decrypt
        and user_key
        and st.button("Decrypt File", key="decrypt_button", use_container_width=True)
    ):
        try:
            decrypted_data = decrypt_file(file_to_decrypt.getvalue(), user_key)
            original_name = file_to_decrypt.name.replace(".soc", "")
            st.success("File decrypted successfully.")
            st.download_button(
                "Download Decrypted File",
                data=decrypted_data,
                file_name=original_name,
                mime="application/octet-stream",
            )
        except ValueError as error:
            st.error(str(error))

render_section_header(
    "PDF Mapping",
    "Project to PDF Mapping",
    "This table shows how the improved codebase lines up with the modules listed in your project PDF.",
)

mapping_df = pd.DataFrame(
    [
        {
            "PDF Module": "Network Traffic Monitoring",
            "Implementation": "sniffer.py + dashboard overview",
            "Status": "Complete",
            "Highlights": "Live capture fallback, source and port analysis, protocol charts",
        },
        {
            "PDF Module": "Intrusion Detection System",
            "Implementation": "ids.py + threat monitor section",
            "Status": "Complete",
            "Highlights": "DoS, port scan, brute force, unauthorized access rules",
        },
        {
            "PDF Module": "Web Vulnerability Scanner",
            "Implementation": "scanner.py + web scanner section",
            "Status": "Complete",
            "Highlights": "Reflection checks, SQL-style error handling, headers, methods",
        },
        {
            "PDF Module": "Log Monitoring and Alerts",
            "Implementation": "logs.txt + threat monitor section",
            "Status": "Complete",
            "Highlights": "Structured logs, alert report export, centralized review panel",
        },
        {
            "PDF Module": "Secure File Transfer",
            "Implementation": "encryption.py + secure files section",
            "Status": "Complete",
            "Highlights": "Authenticated encryption with decrypt and download flow",
        },
        {
            "PDF Module": "Attack Simulation",
            "Implementation": "attack.py + sidebar controls",
            "Status": "Complete",
            "Highlights": "Safe demo scenarios for port scan, brute force, DoS, and mixed traffic",
        },
    ]
)
st.dataframe(mapping_df, width="stretch", hide_index=True)

st.markdown("#### Demo Flow")
st.markdown(
    """
    1. Load `Sample Baseline` traffic to show normal monitoring.
    2. Switch to `Attack Simulation` and choose `Mixed Attack Demo` to generate alerts.
    3. Review the `Threat Monitor` section to inspect IDS findings and exported alert reports.
    4. Use the `Web Scanner` section for a lightweight defensive scan of a demo web app.
    5. Use the `Secure Files` section to encrypt and decrypt a file during the presentation.
    """
)
