"""
SOC Log Analyzer - Streamlit Dashboard
No plotly dependency - uses streamlit native charts
"""

import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
from pathlib import Path
from collections import defaultdict

st.set_page_config(page_title="SOC Log Analyzer", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .stApp { background-color: #020b12; }
    h1, h2, h3 { color: #00d4ff !important; font-family: monospace !important; }
    .stSidebar { background-color: #071520 !important; }
    div[data-testid="metric-container"] {
        background: #071520; border: 1px solid #0f3a52; border-radius: 8px; padding: 16px;
    }
</style>
""", unsafe_allow_html=True)

SEV_COLORS = {"CRITICAL": "#ff3c5a", "HIGH": "#ffb300", "MEDIUM": "#00d4ff", "LOW": "#4caf50"}

def generate_sample_logs():
    import random
    events = []
    base_time = datetime(2024, 3, 15, 8, 0, 0)
    for i in range(8):
        events.append({"event_id": 4625, "event_name": "Failed Login", "severity": "HIGH",
            "timestamp": base_time.replace(minute=i*2).isoformat(),
            "username": "admin", "source_ip": "203.0.113.42", "process_name": "-"})
    events.append({"event_id": 4624, "event_name": "Successful Login", "severity": "LOW",
        "timestamp": base_time.replace(minute=20).isoformat(),
        "username": "admin", "source_ip": "203.0.113.42", "process_name": "-"})
    events.append({"event_id": 4672, "event_name": "Admin Privilege Assigned", "severity": "HIGH",
        "timestamp": base_time.replace(minute=21).isoformat(),
        "username": "admin", "source_ip": "203.0.113.42", "process_name": "-"})
    events.append({"event_id": 4688, "event_name": "New Process Created", "severity": "MEDIUM",
        "timestamp": base_time.replace(minute=22).isoformat(),
        "username": "admin", "source_ip": "-", "process_name": "powershell.exe"})
    events.append({"event_id": 1102, "event_name": "Audit Log Cleared", "severity": "CRITICAL",
        "timestamp": base_time.replace(minute=25).isoformat(),
        "username": "admin", "source_ip": "-", "process_name": "-"})
    users = ["john.doe", "jane.smith", "svc_account"]
    ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
    for i in range(10):
        events.append({"event_id": 4624, "event_name": "Successful Login", "severity": "LOW",
            "timestamp": base_time.replace(hour=9, minute=i*5).isoformat(),
            "username": random.choice(users), "source_ip": random.choice(ips), "process_name": "-"})
    events.append({"event_id": 4720, "event_name": "User Account Created", "severity": "HIGH",
        "timestamp": base_time.replace(hour=10, minute=5).isoformat(),
        "username": "backdoor_user", "source_ip": "203.0.113.42", "process_name": "-"})
    return events

def detect_all(events):
    alerts = []
    failed = defaultdict(list)
    for e in events:
        if e["event_id"] == 4625:
            failed[e["source_ip"]].append(e["timestamp"])
    for ip, ts in failed.items():
        if len(ts) >= 5:
            alerts.append({"type": "BRUTE FORCE", "severity": "CRITICAL",
                "description": f"{len(ts)} failed logins from {ip}", "ip": ip, "user": "Multiple", "mitre": "T1110"})
    failed_ips = set(failed.keys())
    for e in events:
        if e["event_id"] == 4672 and e["source_ip"] in failed_ips:
            alerts.append({"type": "PRIVILEGE ESCALATION", "severity": "CRITICAL",
                "description": f"Admin rights after failed logins by {e['username']}",
                "ip": e["source_ip"], "user": e["username"], "mitre": "T1078"})
    for e in events:
        if e["event_id"] == 1102:
            alerts.append({"type": "AUDIT LOG CLEARED", "severity": "CRITICAL",
                "description": "Security log cleared!", "ip": "-", "user": e["username"], "mitre": "T1070"})
    for e in events:
        if e["event_id"] == 4688 and "powershell" in e["process_name"].lower():
            alerts.append({"type": "SUSPICIOUS PROCESS", "severity": "HIGH",
                "description": f"{e['process_name']} launched", "ip": "-", "user": e["username"], "mitre": "T1059"})
    user_ips = defaultdict(set)
    for e in events:
        if e["event_id"] == 4624 and e["source_ip"] not in ["-", "Unknown"]:
            user_ips[e["username"]].add(e["source_ip"])
    for user, ips in user_ips.items():
        if len(ips) >= 3:
            alerts.append({"type": "LATERAL MOVEMENT", "severity": "HIGH",
                "description": f"{user} logged in from {len(ips)} IPs",
                "ip": ", ".join(ips), "user": user, "mitre": "T1021"})
    for e in events:
        if e["event_id"] == 4720:
            ip = e["source_ip"]
            if not ip.startswith("192.168") and not ip.startswith("10.") and ip != "-":
                alerts.append({"type": "BACKDOOR USER", "severity": "HIGH",
                    "description": f"New user '{e['username']}' from external IP",
                    "ip": ip, "user": e["username"], "mitre": "T1136"})
    return alerts

@st.cache_data
def load_data():
    db_path = Path("soc_events.db")
    if db_path.exists():
        try:
            conn = sqlite3.connect(str(db_path))
            events_df = pd.read_sql("SELECT * FROM events", conn)
            alerts_df = pd.read_sql("SELECT * FROM alerts", conn)
            conn.close()
            events = events_df.to_dict('records')
            alerts = [{"type": r.get('alert_type','?'), "severity": r.get('severity','HIGH'),
                "description": r.get('description',''), "ip": r.get('source_ip','-'),
                "user": r.get('username','-'), "mitre": "N/A"} for _, r in alerts_df.iterrows()]
            return events, alerts
        except:
            pass
    events = generate_sample_logs()
    return events, detect_all(events)

# Sidebar
with st.sidebar:
    st.markdown("## 🛡️ SOC ANALYZER")
    st.markdown("---")
    page = st.radio("Navigation", ["📊 Dashboard", "🚨 Alerts", "📋 Events", "📁 Upload Logs"])
    st.markdown("---")
    st.success("🟢 System Online")
    st.caption(f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    st.markdown("---")
    st.caption("Built by Kiruthika Thirumoorthy")

events, alerts = load_data()
df = pd.DataFrame(events)

# DASHBOARD
if page == "📊 Dashboard":
    st.title("🛡️ SOC Threat Dashboard")
    st.markdown("---")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("📋 Total Events", len(events))
    c2.metric("🔴 Critical", len([e for e in events if e.get('severity')=='CRITICAL']))
    c3.metric("🟡 High", len([e for e in events if e.get('severity')=='HIGH']))
    c4.metric("🚨 Alerts", len(alerts))
    st.markdown("---")

    st.subheader("📈 Event Timeline")
    if not df.empty and 'timestamp' in df.columns:
        df['hour'] = pd.to_datetime(df['timestamp'], errors='coerce').dt.strftime('%H:00')
        st.line_chart(df.groupby('hour').size().rename('Events'))

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("📊 Severity Count")
        if not df.empty:
            st.bar_chart(df['severity'].value_counts())
    with col_b:
        st.subheader("🌍 Top Source IPs")
        if not df.empty:
            ip_df = df[~df['source_ip'].isin(['-','Unknown',''])]
            st.bar_chart(ip_df['source_ip'].value_counts().head(8))

    st.markdown("---")
    st.subheader("🚨 Recent Alerts")
    for a in alerts[:5]:
        color = SEV_COLORS.get(a.get('severity','HIGH'), '#ffb300')
        st.markdown(f"""<div style="background:#071520;border-left:4px solid {color};
        border-radius:6px;padding:10px 14px;margin:6px 0;">
        <b style="color:{color}">[{a.get('severity','')}]</b>
        <span style="color:#00d4ff"> {a.get('type','')}</span><br>
        <small style="color:#c8e8f4">{a.get('description','')}</small><br>
        <small style="color:#4a7a96">MITRE: {a.get('mitre','N/A')} | IP: {a.get('ip','-')}</small>
        </div>""", unsafe_allow_html=True)

# ALERTS
elif page == "🚨 Alerts":
    st.title("🚨 Active Alerts")
    st.caption(f"{len(alerts)} alerts detected")
    st.markdown("---")
    for a in alerts:
        color = SEV_COLORS.get(a.get('severity','HIGH'), '#ffb300')
        st.markdown(f"""<div style="background:#071520;border-left:5px solid {color};
        border-radius:8px;padding:16px;margin:10px 0;">
        <b style="color:{color}">[{a.get('severity','')}] {a.get('type','')}</b>
        <span style="float:right;color:{color};font-size:12px">MITRE: {a.get('mitre','N/A')}</span><br><br>
        <span style="color:#c8e8f4">{a.get('description','')}</span><br>
        <small style="color:#4a7a96">👤 {a.get('user','-')} | 🌐 {a.get('ip','-')}</small>
        </div>""", unsafe_allow_html=True)

# EVENTS
elif page == "📋 Events":
    st.title("📋 All Events")
    st.markdown("---")
    if not df.empty:
        sev_filter = st.multiselect("Filter Severity", df['severity'].unique().tolist(), default=df['severity'].unique().tolist())
        search = st.text_input("🔍 Search")
        filtered = df[df['severity'].isin(sev_filter)]
        if search:
            filtered = filtered[filtered['username'].str.contains(search, case=False, na=False) | filtered['source_ip'].str.contains(search, case=False, na=False)]
        cols = ['timestamp','event_id','event_name','severity','username','source_ip','process_name']
        st.dataframe(filtered[[c for c in cols if c in filtered.columns]], use_container_width=True, height=500)

# UPLOAD
elif page == "📁 Upload Logs":
    st.title("📁 Upload Log Files")
    st.markdown("---")
    uploaded = st.file_uploader("Drop .evtx file", type=['evtx'])
    if uploaded:
        st.success(f"✅ {uploaded.name} uploaded!")
    st.markdown("""### How to export Windows logs:
1. `Windows + R` → `eventvwr.msc` → Enter
2. **Windows Logs** → **Security**
3. **Save All Events As...** → `security.evtx`
4. Copy to project folder → run `python log_parser.py`""")
    c1, c2 = st.columns(2)
    c1.metric("Total Events", len(events))
    c2.metric("Total Alerts", len(alerts))
    if st.button("🔄 Refresh"):
        st.cache_data.clear()
        st.rerun()
