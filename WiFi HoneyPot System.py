# app.py
import streamlit as st
import pandas as pd
import numpy as np
import altair as alt
import random, csv, os, uuid, time
from pathlib import Path
from datetime import datetime, timezone, timedelta

# -------------------------
# Config
# -------------------------
DATA_DIR = Path("data")
LOG_CSV = DATA_DIR / "logs.csv"
DATA_DIR.mkdir(parents=True, exist_ok=True)
MAX_GEN = 1000

# -------------------------
# Constants
# -------------------------
SSIDS = [
    "Campus_Hotspot","Free_WiFi","Airport_Guest","CoffeeCornerNet","Library_WiFi",
    "Mall_Free_WiFi","Hotel_Guest","TrainStationNet","Bus_Stop_Free","University_Guest",
    "Office_Public","Conference_WiFi","Gym_Guest","RestaurantNet","Campus_Staff"
]
NORMAL_CLIENTS = [f"AA:BB:CC:{i:02X}:{j:02X}:{k:02X}" for i,j,k in zip([1]*12, range(10,22), range(20,32))]
ATTACK_CLIENTS = [f"DE:AD:BE:EF:{i:02X}:{j:02X}" for i,j in zip(range(1,12), range(11,23))]
ATTACK_TYPES = ["Evil Twin","Deauthentication","Brute Force","MITM","ARP Spoofing","Probe","DoS","Fake Login"]
SEVERITY_LEVELS = ["Low","Medium","High","Critical"]
ATTACK_VECTORS = [
    "Fake SSID Broadcast","Beacon Flood","Dictionary Attack","Session Hijacking",
    "ARP Cache Poisoning","Probe Request Flood","Traffic Flood","Captive Portal Phish"
]
TARGET_DEVICES = ["Android","iOS","Windows","Linux","MacOS","IoT"]

CSV_HEADERS = [
    "id","timestamp","ssid","bssid","client_mac","client_ip",
    "event_type","attack_type","severity","attack_vector","target_device",
    "packet_count","bytes","duration_s","is_attack","details"
]

# -------------------------
# Utilities: CSV, events
# -------------------------
def ensure_csv_and_seed():
    if not LOG_CSV.exists():
        with open(LOG_CSV, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADERS)
        # seed with some default mixed events so app isn't empty
        append_rows(generate_mixed(120), create_if_missing=False)

def append_rows(rows, create_if_missing=True):
    if create_if_missing:
        ensure_csv_and_seed()
    with open(LOG_CSV, "a", newline="") as f:
        writer = csv.writer(f)
        for r in rows:
            writer.writerow([
                r.get("id"), r.get("timestamp"), r.get("ssid"), r.get("bssid"),
                r.get("client_mac"), r.get("client_ip"), r.get("event_type"),
                r.get("attack_type",""), r.get("severity",""), r.get("attack_vector",""),
                r.get("target_device",""), r.get("packet_count",0), r.get("bytes",0),
                r.get("duration_s",0.0), r.get("is_attack", False), r.get("details","")
            ])

def load_logs():
    ensure_csv_and_seed()
    try:
        df = pd.read_csv(LOG_CSV)
    except Exception:
        df = pd.DataFrame(columns=CSV_HEADERS)
    if "timestamp" in df.columns:
        df["timestamp_parsed"] = pd.to_datetime(df["timestamp"], errors="coerce")
    else:
        df["timestamp_parsed"] = pd.NaT
    if "is_attack" in df.columns:
        # coerce to bool (some CSV writes may create string)
        df["is_attack"] = df["is_attack"].astype(bool)
    return df

def iso_now():
    return datetime.now(timezone.utc).isoformat()

def rand_bssid():
    return ":".join("%02X" % random.randint(0,255) for _ in range(6))

def rand_client(attack=False):
    return random.choice(ATTACK_CLIENTS if attack else NORMAL_CLIENTS)

def make_event(is_attack=False, extra=None, timestamp=None):
    ev = {}
    ev["id"] = str(uuid.uuid4())
    ev["timestamp"] = (timestamp.isoformat() if timestamp else iso_now())
    ssid = random.choice(SSIDS)
    ev["ssid"] = ssid
    ev["bssid"] = rand_bssid()
    ev["client_mac"] = rand_client(attack=is_attack)
    ev["client_ip"] = f"10.0.{random.randint(1,254)}.{random.randint(2,254)}"
    if is_attack:
        attack_type = random.choice(ATTACK_TYPES)
        severity = random.choices(SEVERITY_LEVELS, weights=[0.4,0.35,0.2,0.05])[0]
        attack_vector = random.choice(ATTACK_VECTORS)
        packet_count = random.randint(5,2000)
        ev.update({
            "event_type":"attack",
            "attack_type": attack_type,
            "severity": severity,
            "attack_vector": attack_vector,
            "target_device": random.choice(TARGET_DEVICES),
            "packet_count": packet_count,
            "bytes": 0,
            "duration_s": 0.0,
            "is_attack": True,
            "details": f"{attack_type} via {attack_vector} (pkts={packet_count})"
        })
    else:
        event_type = random.choices(["assoc_success","dns_query","http_get","browse"], weights=[0.1,0.3,0.4,0.2])[0]
        bytes_ = random.randint(200,5_000_000) if event_type in ("http_get","browse") else 0
        dur = round(random.uniform(1,300),2) if event_type=="browse" else 0.0
        ev.update({
            "event_type": event_type,
            "attack_type": "",
            "severity": "Low",
            "attack_vector": "",
            "target_device": random.choice(TARGET_DEVICES),
            "packet_count": random.randint(1,20),
            "bytes": bytes_,
            "duration_s": dur,
            "is_attack": False,
            "details": f"Normal {event_type}"
        })
    if extra:
        ev.update(extra)
    return ev

def generate_normal(n=8):
    return [make_event(is_attack=False, timestamp=datetime.now(timezone.utc) - timedelta(seconds=random.randint(0,3600))) for _ in range(n)]

def generate_attack(n=8):
    return [make_event(is_attack=True, timestamp=datetime.now(timezone.utc) - timedelta(seconds=random.randint(0,3600))) for _ in range(n)]

def generate_mixed(n=16, attack_ratio=0.35):
    rows = []
    for _ in range(n):
        is_attack = random.random() < attack_ratio
        rows.append(make_event(is_attack=is_attack, timestamp=datetime.now(timezone.utc) - timedelta(seconds=random.randint(0,3600))))
    return rows

# -------------------------
# Scenarios (maps) and helpers
# -------------------------
SCENARIOS = {
    "Probe": [
        (0, "Attacker issues broadcast probe requests scanning for SSIDs",
            {"event_type":"probe","attack_type":"Probe","attack_vector":"Probe Request","severity":"Low","packet_count":5}),
        (2, "Probe response received from AP (beacon)",
            {"event_type":"beacon","attack_type":"Probe","attack_vector":"Probe Response","severity":"Low","packet_count":3}),
        (4, "Attacker continues scanning other SSIDs",
            {"event_type":"probe","attack_type":"Probe","attack_vector":"Probe Request","severity":"Low","packet_count":8})
    ],
    "Brute Force": [
        (0, "Attacker starts WPA2 handshake attempts",
            {"event_type":"wpa_handshake_failed","attack_type":"Brute Force","attack_vector":"Dictionary Attack","severity":"High","packet_count":12}),
        (1, "Multiple handshake failures (attempt 5)",
            {"event_type":"wpa_handshake_failed","attack_type":"Brute Force","attack_vector":"Dictionary Attack","severity":"High","packet_count":20}),
        (2, "Brute force spike; many attempts logged",
            {"event_type":"brute_force_attempt","attack_type":"Brute Force","attack_vector":"Dictionary Attack","severity":"Critical","packet_count":200})
    ],
    "DoS": [
        (0, "High-rate malformed requests begin targeting AP",
            {"event_type":"dos","attack_type":"DoS","attack_vector":"Traffic Flood","severity":"High","packet_count":600}),
        (1, "AP saturation observed; normal clients impacted",
            {"event_type":"dos","attack_type":"DoS","attack_vector":"Traffic Flood","severity":"High","packet_count":1200})
    ],
    "Evil Twin": [
        (0, "Attacker broadcasts fake SSID 'Campus_Hotspot' (evil twin)",
            {"event_type":"evil_twin_broadcast","attack_type":"Evil Twin","attack_vector":"Fake SSID Broadcast","severity":"High","packet_count":30}),
        (2, "Client connects to fake AP; captive portal served",
            {"event_type":"fake_login_attempt","attack_type":"Evil Twin","attack_vector":"Captive Portal","severity":"Critical","packet_count":2}),
        (4, "Credential submission observed on portal",
            {"event_type":"credential_submission","attack_type":"Evil Twin","attack_vector":"Captive Portal","severity":"Critical","packet_count":1})
    ],
    "Fake Login": [
        (0, "Client redirected to captive portal (fake login)",
            {"event_type":"fake_login_attempt","attack_type":"Fake Login","attack_vector":"Captive Portal","severity":"Medium","packet_count":4}),
        (2, "User submitted credentials to fake portal",
            {"event_type":"credential_submission","attack_type":"Fake Login","attack_vector":"Captive Portal","severity":"High","packet_count":1})
    ]
}

def make_event_from_map(map_dict, base_ts=None):
    base_ts = base_ts or datetime.now(timezone.utc)
    ev = make_event(is_attack=True, extra={
        "event_type": map_dict.get("event_type"),
        "attack_type": map_dict.get("attack_type"),
        "attack_vector": map_dict.get("attack_vector"),
        "severity": map_dict.get("severity"),
        "packet_count": map_dict.get("packet_count"),
        "details": map_dict.get("details", "")
    }, timestamp=base_ts)
    return ev

# -------------------------
# Streamlit UI
# -------------------------
st.set_page_config(page_title="Wi-Fi Honeypot Simulation", layout="wide")
st.markdown("""
    <style>
    .stApp { background: #FAFBFC; }
    .card { background:#fff; padding:16px; border-radius:10px; box-shadow:0 6px 18px rgba(15,15,15,0.06); }
    .kpi { font-size:26px; font-weight:700; }
    .small { color:#666; font-size:13px; margin-bottom:6px; }
    </style>
""", unsafe_allow_html=True)

st.title("📡 Wi-Fi Honeypot Simulation Dashboard")
st.markdown("Simulation only — data is synthetic and safe. Use sidebar to generate events or play scenarios.")

# ensure CSV exists and seeded
ensure_csv_and_seed()

# Sidebar: controls
with st.sidebar:
    st.header("Controls")
    view_mode = st.radio("View mode", ["Mixed","Normal","Attack"])
    st.markdown("---")
    st.subheader("Generate events (CSV)")
    gen_type = st.selectbox("Type", ["Mixed","Normal","Attack"])
    gen_count = st.number_input("Count (1 - 1000)", min_value=1, max_value=MAX_GEN, value=200, step=1)
    if st.button("Generate & Append"):
        n = int(gen_count)
        if gen_type == "Normal":
            new_rows = generate_normal(n)
        elif gen_type == "Attack":
            new_rows = generate_attack(n)
        else:
            new_rows = generate_mixed(n)
        append_rows(new_rows)
        st.success(f"Appended {len(new_rows)} events to data/logs.csv")
        # reload by re-running app (safe)
        st.experimental_set_query_params(_refresh=str(time.time()))
        st.rerun()

    st.markdown("---")
    st.subheader("Scenario Playback")
    scenario = st.selectbox("Scenario", ["None"] + list(SCENARIOS.keys()))
    append_playback = st.checkbox("Append scenario events to CSV", value=True)
    if st.button("Play Scenario") and scenario != "None":
        # create persistent playback state in session_state
        seq = SCENARIOS[scenario]
        base_ts = datetime.now(timezone.utc)
        playback_msgs = []
        playback_rows = []
        # don't use time.sleep so steps all appear (and stay). We collect them and display.
        for rel, message, map_dict in seq:
            ts = (base_ts + timedelta(seconds=rel)).strftime("%Y-%m-%d %H:%M:%S UTC")
            playback_msgs.append(f"{ts} — {message}")
            ev = make_event_from_map(map_dict, base_ts=(base_ts + timedelta(seconds=rel)))
            playback_rows.append(ev)
        # store into session state under key 'playback'
        st.session_state['playback'] = {
            "scenario": scenario,
            "messages": playback_msgs,
            "rows": playback_rows,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        if append_playback and playback_rows:
            append_rows(playback_rows)
        st.success(f"Played scenario `{scenario}`")

    if st.button("Clear Playback"):
        if 'playback' in st.session_state:
            del st.session_state['playback']
            st.success("Playback cleared.")

    st.markdown("---")
    st.subheader("Export / Cleanup")
    if LOG_CSV.exists():
        csv_bytes = LOG_CSV.read_bytes()
        st.download_button("Download logs.csv", data=csv_bytes, file_name="logs.csv", mime="text/csv")
    if st.button("Delete logs.csv"):
        if LOG_CSV.exists():
            LOG_CSV.unlink()
            ensure_csv_and_seed()
            st.success("Deleted logs.csv and reseeded default events.")
            st.rerun()

# Main: load logs and apply view filter
df_all = load_logs()
if view_mode == "Normal":
    df = df_all[df_all["is_attack"] == False].copy()
elif view_mode == "Attack":
    df = df_all[df_all["is_attack"] == True].copy()
else:
    df = df_all.copy()

# KPIs
total_events = len(df)
attack_events = int(df["is_attack"].sum()) if not df.empty else 0
normal_events = total_events - attack_events
unique_ssids = int(df["ssid"].nunique()) if not df.empty else 0

c1,c2,c3,c4 = st.columns(4)
c1.markdown(f'<div class="card"><div class="small">Total Events</div><div class="kpi">{total_events:,}</div></div>', unsafe_allow_html=True)
c2.markdown(f'<div class="card"><div class="small">Attack Events</div><div class="kpi" style="color:#c0392b;">{attack_events:,}</div></div>', unsafe_allow_html=True)
c3.markdown(f'<div class="card"><div class="small">Normal Events</div><div class="kpi" style="color:#2e8b57;">{normal_events:,}</div></div>', unsafe_allow_html=True)
c4.markdown(f'<div class="card"><div class="small">Unique SSIDs</div><div class="kpi">{unique_ssids:,}</div></div>', unsafe_allow_html=True)

st.markdown("---")

# -------------------------
# Charts area
# -------------------------
st.markdown("## Visual Analytics")

# First row: Event timeline (larger) + Severity pie (smaller)
st.subheader("Traffic & Severity Overview")
row1_left, row1_right = st.columns([7,3])  # 70% / 30%

with row1_left:
    st.markdown("**Events timeline (per minute) — Normal vs Attack**")
    if not df.empty:
        timeline = df.copy()
        timeline['time_bucket'] = timeline['timestamp_parsed'].dt.floor("T")
        counts = timeline.groupby(['time_bucket','is_attack']).size().reset_index(name='count')
        if not counts.empty:
            timeline_chart = alt.Chart(counts).mark_line(point=True).encode(
                x=alt.X('time_bucket:T', title='Time'),
                y=alt.Y('count:Q', title='Events'),
                color=alt.Color('is_attack:N',
                                scale=alt.Scale(domain=[False,True], range=['#2e8b57','#c0392b']),
                                title='Attack?'),
                tooltip=['time_bucket:T','count:Q','is_attack:N']
            ).properties(height=320)
            st.altair_chart(timeline_chart, use_container_width=True)
        else:
            st.info("No timeline data yet.")
    else:
        st.info("No events yet. Use 'Generate & Append' in the sidebar.")

with row1_right:
    st.markdown("**Severity split (Critical / High / Medium / Low)**")
    if not df.empty:
        sev_counts = df['severity'].fillna("Low").value_counts() \
            .reindex(["Critical","High","Medium","Low"], fill_value=0).reset_index()
        sev_counts.columns = ['severity','count']
        pie = alt.Chart(sev_counts).mark_arc().encode(
            theta='count:Q',
            color=alt.Color('severity:N',
                            sort=["Critical","High","Medium","Low"]),
            tooltip=['severity','count']
        ).properties(height=280)  # slightly smaller than timeline
        st.altair_chart(pie, use_container_width=True)
    else:
        st.write("No severity data.")

st.markdown("---")

# Second row: Attack distribution + Packet size distribution (equal size)
st.subheader("Attack Distribution & Packet Characteristics")
row2_left, row2_right = st.columns(2)

with row2_left:
    st.markdown("**Attack type counts**")
    at_df = df[df["attack_type"].notnull() & (df["attack_type"]!="")]["attack_type"].value_counts().reset_index()
    if not at_df.empty:
        at_df.columns = ["attack_type","count"]
        at_bar = alt.Chart(at_df).mark_bar().encode(
            x=alt.X('attack_type:N', sort='-y', title='Attack type'),
            y=alt.Y('count:Q', title='Count'),
            tooltip=['attack_type','count']
        ).properties(height=320)
        st.altair_chart(at_bar, use_container_width=True)
    else:
        st.write("No attack-type events in current view.")

with row2_right:
    st.markdown("**Packet Size Distribution**")
    if not df.empty:
        pkt_df = df.copy()
        pkt_df['bytes_filled'] = pkt_df['bytes'].fillna(0)
        pkt_df['bucket'] = pd.cut(pkt_df['bytes_filled'],
                                  bins=[-1,100,200,900,4000,1e9],
                                  labels=["<100","100-200","200-900","900-4000",">4000"])
        bucket_counts = pkt_df['bucket'].value_counts().reset_index()
        bucket_counts.columns = ['bucket','count']
        bucket_counts = bucket_counts.sort_values('bucket')
        pkt_bar = alt.Chart(bucket_counts).mark_bar().encode(
            x='bucket:N', y='count:Q', tooltip=['bucket','count']
        ).properties(height=320)
        st.altair_chart(pkt_bar, use_container_width=True)
    else:
        st.write("No packet data.")

st.markdown("---")


# Live logs
st.subheader("Live logs (latest 500)")
if not df.empty:
    display_df = df[['timestamp','ssid','client_mac','event_type','attack_type','severity','packet_count','bytes','details','is_attack']].copy()
    display_df = display_df.sort_values('timestamp', ascending=False).reset_index(drop=True).head(500)
    display_df['label'] = display_df['is_attack'].apply(lambda x: "🔴 Attack" if x else "🟢 Normal")
    st.dataframe(display_df)
else:
    st.write("No logs to display.")

st.markdown("---")

# Playback display area (persistent until scenario changes or Clear Playback pressed)
st.subheader("Playback timeline")
if 'playback' in st.session_state and st.session_state['playback'].get('scenario'):
    pb = st.session_state['playback']
    st.markdown(f"**Scenario:** {pb['scenario']}  &nbsp;&nbsp;  created at: {pb.get('created_at')}")
    for msg in pb['messages']:
        st.write(msg)
else:
    st.info("No active playback. Use Scenario Playback in the sidebar to play a scenario.")
st.markdown("---")
st.subheader("📶 Clients per SSID")

if not df.empty:
    # count unique clients per SSID
    # count unique clients per SSID
    ssid_df = df.groupby('ssid')['client_mac'].nunique().reset_index()
    # randomly perturb the counts a bit and shuffle rows
    np.random.seed(42)  # optional, for reproducible randomness 
    ssid_df['client_mac'] = ssid_df['client_mac'] + np.random.randint(-5, 6, size=len(ssid_df))
    ssid_df['client_mac'] = ssid_df['client_mac'].clip(lower=1)  # prevent negative
    ssid_df = ssid_df.sample(frac=1).reset_index(drop=True)  # shuffle

    ssid_chart = alt.Chart(ssid_df).mark_bar().encode(
        x=alt.X('client_mac:Q', title='Number of unique clients'),
        y=alt.Y('ssid:N', title='SSID', sort='-x'),  # horizontal
        tooltip=['ssid','client_mac']
    ).properties(height=400)
    
    st.altair_chart(ssid_chart, use_container_width=True)
else:
    st.info("No data to display for SSIDs.")

st.markdown("---")
st.caption("This dashboard is a simulation for academic/demo purposes. The CSV is stored locally in the app instance and will persist while the app instance is running.")


