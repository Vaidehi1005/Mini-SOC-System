import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from cryptography.fernet import Fernet

from sniffer import start_sniffing
from ids import detect_attacks
from scanner import scan_url

st.set_page_config(page_title="Cyber Security Dashboard", layout="wide")

# ------------------ STYLE ------------------
st.markdown("""
<style>
body {background-color:#f5f5f5;}

.card {
    background:white;
    padding:20px;
    border-radius:12px;
    box-shadow:0px 2px 10px rgba(0,0,0,0.1);
    margin-bottom:20px;
}
</style>
""", unsafe_allow_html=True)

# ------------------ SIDEBAR ------------------
st.sidebar.title("🔎 Filters")
search_ip = st.sidebar.text_input("Search by IP")
protocol = st.sidebar.selectbox("Protocol", ["All","TCP","UDP","ICMP"])

# ------------------ HEADER ------------------
st.title("🛡️ Cyber Security Dashboard")
st.caption("Real-Time SOC Monitoring System")

st.success("System Active 🚀")

# ------------------ DATA ------------------
try:
    packets = start_sniffing()
except:
    packets = []

if not packets:
    packets = [
        ["192.168.1.10","192.168.1.1","TCP",80],
        ["192.168.1.20","8.8.8.8","UDP",53],
        ["203.0.113.99","10.0.0.1","TCP",443],
        ["192.168.1.99","192.168.1.1","TCP",3000],
    ]

# IDS
alerts = detect_attacks(packets)

df = pd.DataFrame(packets, columns=["src_ip","dst_ip","protocol","port"])
df["timestamp"] = datetime.now()

# ------------------ METRICS ------------------
col1, col2, col3 = st.columns(3)

col1.metric("Total Logs", len(df))
col2.metric("Unique IPs", df["src_ip"].nunique())
col3.metric("Active Ports", df["port"].nunique())

# ------------------ TOP ATTACKER ------------------
top_ip = df["src_ip"].value_counts().idxmax()
top_count = df["src_ip"].value_counts().max()

st.warning(f"🔥 Top Attacker: {top_ip} ({top_count} requests)")

# ------------------ THREAT DETECTION PANEL ------------------
st.subheader("🚨 Threat Detection Panel")

threat_table = []
for i, alert in enumerate(alerts):
    threat_table.append([
        i,
        datetime.now(),
        alert,
        df.iloc[i]["src_ip"],
        df.iloc[i]["dst_ip"],
        df.iloc[i]["protocol"],
        "Suspicious activity",
        "CRITICAL"
    ])

if threat_table:
    threat_df = pd.DataFrame(threat_table,
        columns=["id","timestamp","rule_name","src_ip","dst_ip","protocol","details","severity"])
    st.dataframe(threat_df, use_container_width=True)
else:
    st.success("No threats detected")

st.error("🔴 Real IDS Alerts Detected")

# ------------------ FILTER ------------------
if search_ip:
    df = df[df["src_ip"].str.contains(search_ip)]

if protocol != "All":
    df = df[df["protocol"] == protocol]

# ------------------ LIVE TRAFFIC ------------------
st.subheader("📡 Live Network Traffic")
st.dataframe(df, use_container_width=True)

# ------------------ GRAPH ------------------
st.subheader("📊 Network Traffic Overview")

fig, ax = plt.subplots()
df["protocol"].value_counts().plot(kind="bar", ax=ax)
st.pyplot(fig)

# ------------------ SCANNER ------------------
st.subheader("🌐 Web Vulnerability Scanner")

url = st.text_input("Enter target URL")

if st.button("🔍 Scan Website"):
    results = scan_url(url)
    st.success("Scan Completed")

    for r in results:
        if "SQL" in r:
            st.error(r)
        else:
            st.success(r)

# ------------------ FILE ENCRYPTION ------------------
st.subheader("🔐 Secure File Transfer")

key = Fernet.generate_key()
cipher = Fernet(key)

file = st.file_uploader("Upload file for encryption")

if file:
    encrypted = cipher.encrypt(file.read())
    st.success("File encrypted successfully")
    st.code(key.decode(), language="text")

# ------------------ DECRYPT FILE ------------------
st.subheader("🔓 Decrypt File")

enc_file = st.file_uploader("Upload encrypted file")
user_key = st.text_input("Enter encryption key")

if enc_file and user_key:
    try:
        cipher = Fernet(user_key.encode())
        decrypted = cipher.decrypt(enc_file.read())
        st.success("File decrypted successfully")
        st.download_button("Download Decrypted File", decrypted)
    except:
        st.error("Invalid key or file")