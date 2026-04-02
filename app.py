import streamlit as st
import pandas as pd
from datetime import datetime
import matplotlib.pyplot as plt

st.set_page_config(page_title="Advanced SOC Dashboard", layout="wide")

# ------------------ PREMIUM STYLE ------------------
st.markdown("""
<style>
body {
    background-color: #0f172a;
    color: white;
}
section[data-testid="stSidebar"] {
    background-color: #020617;
}
.card {
    background: rgba(255, 255, 255, 0.05);
    padding: 20px;
    border-radius: 15px;
    backdrop-filter: blur(10px);
    box-shadow: 0px 0px 20px rgba(0,0,0,0.3);
    margin-bottom: 20px;
}
h1, h2, h3 {
    color: #38bdf8;
}
.stButton>button {
    background-color: #38bdf8;
    color: black;
    border-radius: 10px;
}
</style>
""", unsafe_allow_html=True)

# ------------------ SIDEBAR ------------------
st.sidebar.markdown("## ⚙️ Control Panel")
search_ip = st.sidebar.text_input("🔍 Search IP")
protocol = st.sidebar.selectbox("📡 Protocol", ["All", "TCP", "UDP", "ICMP"])

# ------------------ HEADER ------------------
st.markdown("""
<div class="card">
    <h1>🛡️ Advanced SOC Dashboard</h1>
    <p>Real-Time Cyber Security Monitoring</p>
</div>
""", unsafe_allow_html=True)

# ------------------ LIVE TRAFFIC DATA ------------------
traffic = pd.DataFrame([
    ["192.168.1.99", "192.168.1.1", "TCP", 3971],
    ["203.0.113.99", "8.8.8.8", "UDP", 8080],
    ["192.168.1.20", "8.8.8.8", "ICMP", None],
    ["192.168.1.99", "192.168.1.1", "TCP", 3971],
], columns=["Source IP","Destination IP","Protocol","Port"])

# ------------------ CALCULATIONS ------------------
active_ports = traffic["Port"].dropna().nunique()
unique_ips = traffic["Source IP"].nunique()

try:
    total_logs = len(open("logs.txt").read().splitlines())
except:
    total_logs = 0

# ------------------ METRICS ------------------
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(f'<div class="card"><h3>📊 Total Logs</h3><h1>{total_logs}</h1></div>', unsafe_allow_html=True)

with col2:
    st.markdown(f'<div class="card"><h3>🌐 Unique IPs</h3><h1>{unique_ips}</h1></div>', unsafe_allow_html=True)

with col3:
    st.markdown(f'<div class="card"><h3>🔌 Active Ports</h3><h1>{active_ports}</h1></div>', unsafe_allow_html=True)

with col4:
    st.markdown('<div class="card"><h3>🚨 Threat Level</h3><h1 style="color:red;">HIGH</h1></div>', unsafe_allow_html=True)

# ------------------ ALERT ------------------
st.markdown("""
<div class="card" style="border-left: 5px solid red;">
    🚨 <b>Critical Alert:</b> DoS Attack detected from 192.168.1.10
</div>
""", unsafe_allow_html=True)

# ------------------ THREAT DATA ------------------
data = pd.DataFrame([
    [33, datetime.now(), "DoS Attack", "192.168.1.10", "TCP", "CRITICAL"],
    [32, datetime.now(), "Brute Force", "192.168.1.20", "UDP", "HIGH"],
    [31, datetime.now(), "DoS Attack", "10.0.0.5", "TCP", "CRITICAL"]
], columns=["ID","Time","Attack","IP","Protocol","Severity"])

# Filters
if search_ip:
    data = data[data["IP"].str.contains(search_ip)]

if protocol != "All":
    data = data[data["Protocol"] == protocol]

# ------------------ THREAT PANEL ------------------
st.markdown('<div class="card">', unsafe_allow_html=True)
st.subheader("🚨 Threat Detection Panel")
st.dataframe(data, use_container_width=True)
st.markdown('</div>', unsafe_allow_html=True)

# ------------------ LIVE TRAFFIC ------------------
st.markdown('<div class="card">', unsafe_allow_html=True)
st.subheader("📡 Live Network Traffic")
st.dataframe(traffic, use_container_width=True)
st.markdown('</div>', unsafe_allow_html=True)

# ------------------ ACTIVE PORTS LIST ------------------
st.markdown('<div class="card">', unsafe_allow_html=True)
st.subheader("🔌 Active Ports")

ports = traffic["Port"].dropna().unique()
st.write(list(ports))

# Top port
if len(ports) > 0:
    top_port = traffic["Port"].mode()[0]
    st.info(f"🔥 Most Used Port: {top_port}")

st.markdown('</div>', unsafe_allow_html=True)

# ------------------ GRAPH ------------------
st.markdown('<div class="card">', unsafe_allow_html=True)
st.subheader("📊 Network Traffic Overview")

labels = ["ICMP", "TCP", "UDP"]
values = [
    len(traffic[traffic["Protocol"] == "ICMP"]),
    len(traffic[traffic["Protocol"] == "TCP"]),
    len(traffic[traffic["Protocol"] == "UDP"])
]

fig, ax = plt.subplots()
ax.bar(labels, values)

ax.set_facecolor("#0f172a")
fig.patch.set_facecolor("#0f172a")

st.pyplot(fig)
st.markdown('</div>', unsafe_allow_html=True)

# ------------------ SCANNER ------------------
st.markdown('<div class="card">', unsafe_allow_html=True)
st.subheader("🌐 Vulnerability Scanner")

url = st.text_input("Enter target URL")

if st.button("Scan"):
    st.success("Scan Completed")
    st.error("SQL Injection: Vulnerable")
    st.success("XSS: Safe")

st.markdown('</div>', unsafe_allow_html=True)

# ------------------ FILE TRANSFER ------------------
st.markdown('<div class="card">', unsafe_allow_html=True)
st.subheader("🔐 Secure File Transfer")

file = st.file_uploader("Upload file")

if file:
    st.success("File secured successfully 🔐")

st.markdown('</div>', unsafe_allow_html=True)

# ------------------ LOGS ------------------
st.markdown('<div class="card">', unsafe_allow_html=True)
st.subheader("📜 Logs")

try:
    with open("logs.txt", "r") as f:
        logs = f.read().splitlines()

    df = pd.DataFrame(logs, columns=["Events"])
    st.dataframe(df)

except:
    st.write("No logs yet")

st.markdown('</div>', unsafe_allow_html=True)