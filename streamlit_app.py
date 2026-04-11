"""
SOC Log Analyzer - Streamlit Dashboard
Deploy: streamlit.io (Free!)
Run locally: streamlit run streamlit_app.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sqlite3
import json
from datetime import datetime
from pathlib import Path

# ── Page Config ──────────────────────────────
st.set_page_config(
    page_title="SOC Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Dark Theme CSS ────────────────────────────
st.markdown("""
<style>
    .main { background-color: #020b12; }
    .stApp { background-color: #020b12; }
    
    .metric-card {
        background: #071520;
        border: 1px solid #0f3a52;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .metric-value {
        font-size: 42px;
        font-weight: 900;
        font-family: monospace;
    }
    .metric-label {
        font-size: 12px;
        letter-spacing: 3px;
        color: #4a7a96;
        text-transform: uppercase;
    }
    .critical { color: #ff3c5a; }
    .high     { color: #ffb300; }
    .medium   { color: #00d4ff; }
    .low      { color: #4caf50; }
    .accent   { color: #00d4ff; }

    .alert-card {
        background: #071520;
        border-left: 4px solid #ff3c5a;
        border-radius: 6px;
        padding: 12px 16px;
        margin: 8px 0;
    }
    .alert-card.high { border-left-color: #ffb300; }
    .alert-card.medium { border-left-color: #00d4ff; }

    h1, h2, h3 { color: #00d4ff !important; font-family: monospace !important; }
    .stSidebar { background-color: #071520 !important; }
    
    div[data-testid="metric-container"] {
        background: #071520;
        border: 1px solid #0f3a52;
        border-radius: 8px;
        padding: 16px;
    }
</style>
""", unsafe_allow_html=True)

# ── Import Detection Logic ────────────────────
def generate_sample_logs():
    """Generate sample attack logs for demo"""
    from datetime import datetime
    import random

    events = []
    base_time = datetime(2024, 3, 15, 8, 0, 0)

    # Brute force
    for i in range(8):
        events.append({
            "event_id": 4625, "event_name": "Failed Login", "severity": "HIGH",
            "timestamp": base_time.replace(minute=i*2).isoformat(),
            "username": "admin", "source_ip": "203.0.113.42",
            "process_name": "-", "raw_message": f"Failed login attempt {i+1}"
        })

    # Successful login after brute force
    events.append({
        "event_id": 4624, "event_name": "Successful Login", "severity": "LOW",
        "timestamp": base_time.replace(minute=20).isoformat(),
        "username": "admin", "source_ip": "203.0.113.42",
        "process_name": "-", "raw_message": "Successful login after brute force"
    })

    # Privilege escalation
    events.append({
        "event_id": 4672, "event_name": "Admin Privilege Assigned", "severity": "HIGH",
        "timestamp": base_time.replace(minute=21).isoformat(),
        "username": "admin", "source_ip": "203.0.113.42",
        "process_name": "-", "raw_message": "Admin privileges assigned"
    })

    # Suspicious process
    events.append({
        "event_id": 4688, "event_name": "New Process Created", "severity": "MEDIUM",
        "timestamp": base_time.replace(minute=22).isoformat(),
        "username": "admin", "source_ip": "-",
        "process_name": "powershell.exe", "raw_message": "PowerShell spawned"
    })

    # Log cleared
    events.append({
        "event_id": 1102, "event_name": "Audit Log Cleared", "severity": "CRITICAL",
        "timestamp": base_time.replace(minute=25).isoformat(),
        "username": "admin", "source_ip": "-",
        "process_name": "-", "raw_message": "Security log cleared!"
    })

    # Normal activity
    users = ["john.doe", "jane.smith", "svc_account"]
    normal_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
    for i in range(10):
        events.append({
            "event_id": 4624, "event_name": "Successful Login", "severity": "LOW",
            "timestamp": base_time.replace(hour=9, minute=i*5).isoformat(),
            "username": random.choice(users), "source_ip": random.choice(normal_ips),
            "process_name": "-", "raw_message": "Normal login"
        })

    # New user from external IP
    events.append({
        "event_id": 4720, "event_name": "User Account Created", "severity": "HIGH",
        "timestamp": base_time.replace(hour=10, minute=5).isoformat(),
        "username": "backdoor_user", "source_ip": "203.0.113.42",
        "process_name": "-", "raw_message": "Backdoor user created"
    })

    return events


def detect_all(events):
    """Run all detection rules"""
    alerts = []
    from collections import defaultdict

    # Rule 1: Brute Force
    failed = defaultdict(list)
    for e in events:
        if e["event_id"] == 4625:
            failed[e["source_ip"]].append(e["timestamp"])
    for ip, ts in failed.items():
        if len(ts) >= 5:
            alerts.append({
                "type": "BRUTE FORCE", "severity": "CRITICAL",
                "description": f"{len(ts)} failed logins from {ip}",
                "ip": ip, "user": "Multiple", "mitre": "T1110"
            })

    # Rule 2: Privilege Escalation
    failed_ips = set(failed.keys())
    for e in events:
        if e["event_id"] == 4672 and e["source_ip"] in failed_ips:
            alerts.append({
                "type": "PRIVILEGE ESCALATION", "severity": "CRITICAL",
                "description": f"Admin rights after failed logins by {e['username']}",
                "ip": e["source_ip"], "user": e["username"], "mitre": "T1078"
            })

    # Rule 3: Log Cleared
    for e in events:
        if e["event_id"] == 1102:
            alerts.append({
                "type": "AUDIT LOG CLEARED", "severity": "CRITICAL",
                "description": "Security log cleared — attacker covering tracks!",
                "ip": "-", "user": e["username"], "mitre": "T1070"
            })

    # Rule 4: Suspicious Process
    suspicious = ["powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe"]
    for e in events:
        if e["event_id"] == 4688:
            for s in suspicious:
                if s in e["process_name"].lower():
                    alerts.append({
                        "type": "SUSPICIOUS PROCESS", "severity": "HIGH",
                        "description": f"{e['process_name']} launched by {e['username']}",
                        "ip": "-", "user": e["username"], "mitre": "T1059"
                    })

    # Rule 5: Lateral Movement
    user_ips = defaultdict(set)
    for e in events:
        if e["event_id"] == 4624 and e["source_ip"] not in ["-", "Unknown"]:
            user_ips[e["username"]].add(e["source_ip"])
    for user, ips in user_ips.items():
        if len(ips) >= 3:
            alerts.append({
                "type": "LATERAL MOVEMENT", "severity": "HIGH",
                "description": f"{user} logged in from {len(ips)} IPs",
                "ip": ", ".join(ips), "user": user, "mitre": "T1021"
            })

    # Rule 6: New User from External IP
    for e in events:
        if e["event_id"] == 4720:
            ip = e["source_ip"]
            if not ip.startswith("192.168") and not ip.startswith("10.") and ip != "-":
                alerts.append({
                    "type": "BACKDOOR USER", "severity": "HIGH",
                    "description": f"New user '{e['username']}' created from external IP",
                    "ip": ip, "user": e["username"], "mitre": "T1136"
                })

    return alerts


# ── Sidebar ───────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ SOC ANALYZER")
    st.markdown("---")

    page = st.radio("Navigation", [
        "📊 Dashboard",
        "🚨 Alerts",
        "📋 Events",
        "📁 Upload Logs"
    ])

    st.markdown("---")
    st.markdown("**Status**")
    st.success("🟢 System Online")
    st.markdown(f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    st.markdown("---")
    st.caption("SOC Log Analyzer v2.0")
    st.caption("Built by Kiruthika Thirumoorthy")


# ── Load Data ─────────────────────────────────
@st.cache_data
def load_data():
    """Load from DB or generate sample"""
    db_path = Path("soc_events.db")
    if db_path.exists():
        try:
            conn = sqlite3.connect(str(db_path))
            events_df = pd.read_sql("SELECT * FROM events", conn)
            alerts_df = pd.read_sql("SELECT * FROM alerts", conn)
            conn.close()
            events = events_df.to_dict('records')
            alerts = alerts_df.to_dict('records')
            # Normalize alerts
            for a in alerts:
                a['type'] = a.get('alert_type', 'UNKNOWN')
                a['ip'] = a.get('source_ip', '-')
                a['user'] = a.get('username', '-')
                a['mitre'] = 'N/A'
            return events, alerts
        except:
            pass

    events = generate_sample_logs()
    alerts = detect_all(events)
    return events, alerts


events, alerts = load_data()
df = pd.DataFrame(events)
alerts_df = pd.DataFrame(alerts) if alerts else pd.DataFrame()

# ── SEVERITY COLORS ───────────────────────────
SEV_COLORS = {
    "CRITICAL": "#ff3c5a",
    "HIGH": "#ffb300",
    "MEDIUM": "#00d4ff",
    "LOW": "#4caf50"
}

# ══════════════════════════════════════════════
# PAGE: DASHBOARD
# ══════════════════════════════════════════════
if page == "📊 Dashboard":
    st.title("🛡️ SOC Threat Dashboard")
    st.caption("Real-time Security Operations Center Monitor")
    st.markdown("---")

    # Stat Cards
    col1, col2, col3, col4 = st.columns(4)

    total = len(events)
    critical = len([e for e in events if e.get('severity') == 'CRITICAL'])
    high = len([e for e in events if e.get('severity') == 'HIGH'])
    total_alerts = len(alerts)

    with col1:
        st.metric("📋 Total Events", total, help="All parsed log events")
    with col2:
        st.metric("🔴 Critical Events", critical, help="Events requiring immediate action")
    with col3:
        st.metric("🟡 High Severity", high, help="Elevated risk events")
    with col4:
        st.metric("🚨 Active Alerts", total_alerts, help="Triggered detections")

    st.markdown("---")

    # Charts Row
    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.subheader("📈 Event Timeline")
        if not df.empty and 'timestamp' in df.columns:
            df['hour'] = pd.to_datetime(df['timestamp'], errors='coerce').dt.strftime('%H:00')
            timeline = df.groupby('hour').size().reset_index(name='count')
            fig = px.line(
                timeline, x='hour', y='count',
                color_discrete_sequence=['#00d4ff'],
                template='plotly_dark'
            )
            fig.update_layout(
                paper_bgcolor='#071520', plot_bgcolor='#071520',
                font_color='#c8e8f4', margin=dict(t=20, b=20)
            )
            fig.update_traces(line_width=2, fill='tozeroy', fillcolor='rgba(0,212,255,0.1)')
            st.plotly_chart(fig, use_container_width=True)

    with col_right:
        st.subheader("🥧 Severity Distribution")
        if not df.empty and 'severity' in df.columns:
            sev_counts = df['severity'].value_counts().reset_index()
            sev_counts.columns = ['severity', 'count']
            colors = [SEV_COLORS.get(s, '#4a7a96') for s in sev_counts['severity']]
            fig2 = px.pie(
                sev_counts, values='count', names='severity',
                color_discrete_sequence=colors,
                hole=0.6, template='plotly_dark'
            )
            fig2.update_layout(
                paper_bgcolor='#071520', font_color='#c8e8f4',
                margin=dict(t=20, b=20)
            )
            st.plotly_chart(fig2, use_container_width=True)

    st.markdown("---")

    # Bottom Row
    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("🚨 Recent Alerts")
        if alerts:
            for a in alerts[:5]:
                sev = a.get('severity', 'HIGH')
                color = SEV_COLORS.get(sev, '#ffb300')
                st.markdown(f"""
                <div style="background:#071520;border-left:4px solid {color};
                border-radius:6px;padding:10px 14px;margin:6px 0;">
                <b style="color:{color}">[{sev}]</b> 
                <span style="color:#00d4ff">{a.get('type','')}</span><br>
                <small style="color:#8ab8cc">{a.get('description','')}</small><br>
                <small style="color:#4a7a96">IP: {a.get('ip','-')} | MITRE: {a.get('mitre','N/A')}</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No alerts detected")

    with col_b:
        st.subheader("🌍 Top Source IPs")
        if not df.empty and 'source_ip' in df.columns:
            ip_counts = df[df['source_ip'].notna() & (df['source_ip'] != '-') & (df['source_ip'] != 'Unknown')]
            ip_counts = ip_counts['source_ip'].value_counts().head(8).reset_index()
            ip_counts.columns = ['IP Address', 'Count']
            fig3 = px.bar(
                ip_counts, x='Count', y='IP Address',
                orientation='h', color_discrete_sequence=['#00d4ff'],
                template='plotly_dark'
            )
            fig3.update_layout(
                paper_bgcolor='#071520', plot_bgcolor='#071520',
                font_color='#c8e8f4', margin=dict(t=10, b=10),
                yaxis={'categoryorder': 'total ascending'}
            )
            st.plotly_chart(fig3, use_container_width=True)


# ══════════════════════════════════════════════
# PAGE: ALERTS
# ══════════════════════════════════════════════
elif page == "🚨 Alerts":
    st.title("🚨 Active Alerts")
    st.caption(f"Total: {len(alerts)} alerts detected")
    st.markdown("---")

    if alerts:
        for a in alerts:
            sev = a.get('severity', 'HIGH')
            color = SEV_COLORS.get(sev, '#ffb300')
            st.markdown(f"""
            <div style="background:#071520;border:1px solid #0f3a52;
            border-left:5px solid {color};border-radius:8px;
            padding:16px 20px;margin:10px 0;">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="color:{color};font-weight:bold;font-size:16px">
                    [{sev}] {a.get('type','')}
                </span>
                <span style="background:{color}22;color:{color};
                padding:3px 10px;border-radius:20px;font-size:12px;
                border:1px solid {color}">
                    MITRE: {a.get('mitre','N/A')}
                </span>
            </div>
            <p style="color:#c8e8f4;margin:8px 0">{a.get('description','')}</p>
            <small style="color:#4a7a96">
                👤 User: {a.get('user','-')} &nbsp;|&nbsp; 
                🌐 IP: {a.get('ip','-')}
            </small>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.success("✅ No alerts detected!")


# ══════════════════════════════════════════════
# PAGE: EVENTS
# ══════════════════════════════════════════════
elif page == "📋 Events":
    st.title("📋 All Events")
    st.markdown("---")

    if not df.empty:
        # Filters
        col1, col2 = st.columns(2)
        with col1:
            sev_filter = st.multiselect(
                "Filter by Severity",
                options=df['severity'].unique().tolist(),
                default=df['severity'].unique().tolist()
            )
        with col2:
            search = st.text_input("🔍 Search by username or IP")

        filtered = df[df['severity'].isin(sev_filter)]
        if search:
            filtered = filtered[
                filtered['username'].str.contains(search, case=False, na=False) |
                filtered['source_ip'].str.contains(search, case=False, na=False)
            ]

        st.markdown(f"**Showing {len(filtered)} events**")
        st.dataframe(
            filtered[['timestamp', 'event_id', 'event_name', 'severity', 'username', 'source_ip', 'process_name']],
            use_container_width=True,
            height=500
        )
    else:
        st.warning("No events found. Upload a log file first!")


# ══════════════════════════════════════════════
# PAGE: UPLOAD
# ══════════════════════════════════════════════
elif page == "📁 Upload Logs":
    st.title("📁 Upload Log Files")
    st.caption("Upload Windows Event Log (.evtx) files for analysis")
    st.markdown("---")

    uploaded = st.file_uploader(
        "Drop your .evtx file here",
        type=['evtx'],
        help="Export from Windows Event Viewer → Security → Save All Events As"
    )

    if uploaded:
        st.success(f"✅ File uploaded: {uploaded.name}")
        st.info("💡 Save the file to your project folder as 'security.evtx' and restart the app!")

        st.markdown("### 📋 How to export Windows logs:")
        st.markdown("""
        1. Press `Windows + R` → type `eventvwr.msc` → Enter
        2. Left panel → **Windows Logs** → **Security**
        3. Right panel → **Save All Events As...**
        4. Save as `security.evtx`
        5. Copy to your project folder
        6. Run: `python log_parser.py`
        """)

    st.markdown("---")
    st.subheader("📊 Current Data Summary")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Events", len(events))
    with col2:
        st.metric("Total Alerts", len(alerts))
    with col3:
        data_source = "Real DB" if Path("soc_events.db").exists() else "Sample Data"
        st.metric("Data Source", data_source)

    if st.button("🔄 Refresh Data"):
        st.cache_data.clear()
        st.rerun()
