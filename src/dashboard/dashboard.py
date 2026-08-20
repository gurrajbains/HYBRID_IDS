import json
import os

import pandas as pd
import streamlit as st


st.set_page_config(
    page_title="Hybrid IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


METRICS_PATH = "logs/metrics.json"
ALERTS_PATH = "logs/alerts.jsonl"
FLOW_LOG_PATH = "logs/flows.jsonl"
PREDICTION_LOG_PATH = "logs/ml_predictions.jsonl"
MODEL_METRICS_PATH = "models/live_model_metrics.json"
MODEL_PATH = "models/random_forest_live.joblib"


# =========================================================
# DATA
# =========================================================

def load_json_file(file_path, default_value):
    if not os.path.exists(file_path):
        return default_value

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):
        return default_value


def load_jsonl(file_path):
    if not os.path.exists(file_path):
        return []

    records = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    except OSError:
        return []

    return records


default_metrics = {
    "total_packets": 0,
    "protocol_counts": {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "OTHER": 0
    },
    "total_alerts": 0,
    "alert_counts": {},
    "flows_analyzed": 0,
    "flows_classified": 0,
    "active_flows": 0
}


metrics = load_json_file(METRICS_PATH, default_metrics)
metrics = {**default_metrics, **metrics}

alerts = load_jsonl(ALERTS_PATH)
flow_records = load_jsonl(FLOW_LOG_PATH)
predictions = load_jsonl(PREDICTION_LOG_PATH)
model_metrics = load_json_file(MODEL_METRICS_PATH, {})


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.title("🛡️ Hybrid IDS")

page = st.sidebar.radio(
    "Navigation",
    [
        "Overview",
        "Alerts",
        "Network",
        "Machine Learning"
    ]
)

st.sidebar.divider()

theme = st.sidebar.radio(
    "Appearance",
    ["Dark", "Light"],
    horizontal=True
)

palette = st.sidebar.selectbox(
    "Palette",
    [
        "Cyber Blue",
        "SOC Green",
        "Purple",
        "Warning"
    ]
)


# =========================================================
# THEME
# =========================================================

if theme == "Dark":
    background = "#090D14"
    sidebar_background = "#0D131D"
    panel_background = "#111827"
    secondary_background = "#0F172A"
    input_background = "#111827"
    border_color = "#263244"
    text_color = "#F8FAFC"
    muted_text = "#94A3B8"

else:
    background = "#F4F7FB"
    sidebar_background = "#FFFFFF"
    panel_background = "#FFFFFF"
    secondary_background = "#F8FAFC"
    input_background = "#FFFFFF"
    border_color = "#D8E0EA"
    text_color = "#111827"
    muted_text = "#64748B"


if palette == "Cyber Blue":
    accent = "#38BDF8" if theme == "Dark" else "#2563EB"

elif palette == "SOC Green":
    accent = "#34D399" if theme == "Dark" else "#059669"

elif palette == "Purple":
    accent = "#A78BFA" if theme == "Dark" else "#7C3AED"

else:
    accent = "#FBBF24" if theme == "Dark" else "#D97706"


# =========================================================
# CSS
# =========================================================

st.markdown(
    f"""
<style>

/* ---------------------------------------------------------
   STREAMLIT CHROME
--------------------------------------------------------- */

[data-testid="stHeader"] {{
    background: transparent !important;
    height: 0 !important;
}}

[data-testid="stToolbar"] {{
    display: none !important;
}}

[data-testid="stDecoration"] {{
    display: none !important;
}}

#MainMenu {{
    display: none !important;
}}

footer {{
    display: none !important;
}}


/* ---------------------------------------------------------
   MAIN APP
--------------------------------------------------------- */

html,
body,
[data-testid="stApp"],
[data-testid="stAppViewContainer"] {{
    background-color: {background} !important;
    color: {text_color} !important;
}}

[data-testid="stAppViewContainer"] {{
    padding-top: 0 !important;
}}

[data-testid="stAppViewContainer"] > .main {{
    padding-top: 0 !important;
    background-color: {background} !important;
}}

.block-container {{
    max-width: 1500px;
    padding-top: 0.75rem !important;
    padding-bottom: 3rem;
}}


/* ---------------------------------------------------------
   SIDEBAR
--------------------------------------------------------- */

[data-testid="stSidebar"] {{
    background-color: {sidebar_background} !important;
    border-right: 1px solid {border_color} !important;
    transition:
        width 0.2s ease,
        min-width 0.2s ease,
        transform 0.2s ease !important;
}}

[data-testid="stSidebar"][aria-expanded="true"] {{
    width: 380px !important;
    min-width: 380px !important;
    transform: translateX(0) !important;
}}

[data-testid="stSidebar"][aria-expanded="false"] {{
    width: 38px !important;
    min-width: 38px !important;
    max-width: 38px !important;
    transform: translateX(0) !important;
    left: 0 !important;
    margin-left: 0 !important;
    border-right: 1px solid {border_color} !important;
}}

[data-testid="stSidebarContent"],
[data-testid="stSidebar"] > div,
[data-testid="stSidebar"] section {{
    background-color: {sidebar_background} !important;
}}

[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3,
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] span,
[data-testid="stSidebar"] label {{
    color: {text_color} !important;
}}


/* ---------------------------------------------------------
   SIDEBAR COLLAPSED RAIL
--------------------------------------------------------- */

[data-testid="stSidebarHeader"] {{
    background-color: {sidebar_background} !important;
}}

[data-testid="stSidebar"][aria-expanded="false"]
[data-testid="stSidebarHeader"] {{
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
    width: 38px !important;
    min-width: 38px !important;
    max-width: 38px !important;
    padding: 6px 0 !important;
    justify-content: center !important;
    align-items: flex-start !important;
}}

[data-testid="stSidebarCollapseButton"] {{
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
    z-index: 999999 !important;
}}

[data-testid="stSidebarCollapseButton"] button {{
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
    pointer-events: auto !important;
}}

[data-testid="stSidebar"][aria-expanded="false"]
[data-testid="stSidebarCollapseButton"] {{
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
    position: absolute !important;
    top: 8px !important;
    left: -13px !important;
    width: 34px !important;
    height: 34px !important;
    justify-content: center !important;
    align-items: center !important;
    z-index: 999999 !important;
}}

[data-testid="stSidebar"][aria-expanded="false"]
[data-testid="stSidebarCollapseButton"] button {{
    width: 34px !important;
    height: 34px !important;
    padding: 0 !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
}}

[data-testid="stSidebar"][aria-expanded="false"]
[data-testid="stSidebarUserContent"] {{
    display: none !important;
}}

[data-testid="stSidebar"][aria-expanded="false"]
[data-testid="stSidebarContent"] {{
    overflow: hidden !important;
    width: 38px !important;
}}

[data-testid="collapsedControl"] {{
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
    position: fixed !important;
    top: 8px !important;
    left: 2px !important;
    width: 34px !important;
    height: 34px !important;
    z-index: 999999 !important;
}}

[data-testid="collapsedControl"] button {{
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
    width: 34px !important;
    height: 34px !important;
    padding: 0 !important;
    align-items: center !important;
    justify-content: center !important;
}}


/* ---------------------------------------------------------
   RADIO / SELECT INPUTS
--------------------------------------------------------- */

[data-testid="stRadio"],
[data-testid="stRadio"] label,
[data-testid="stRadio"] p {{
    color: {text_color} !important;
}}

[data-baseweb="select"] > div {{
    background-color: {input_background} !important;
    border-color: {border_color} !important;
    color: {text_color} !important;
}}

[data-baseweb="select"] span,
[data-baseweb="select"] input {{
    color: {text_color} !important;
}}

[data-baseweb="popover"],
[data-baseweb="menu"],
[data-baseweb="menu"] ul {{
    background-color: {input_background} !important;
}}

[data-baseweb="menu"] li {{
    background-color: {input_background} !important;
    color: {text_color} !important;
}}

[data-baseweb="menu"] li:hover {{
    background-color: {secondary_background} !important;
}}

[data-testid="stSelectbox"] label,
[data-testid="stSelectbox"] p {{
    color: {text_color} !important;
}}


/* ---------------------------------------------------------
   PAGE HEADER
--------------------------------------------------------- */

.page-header {{
    margin-top: 0;
    margin-bottom: 1.5rem;
}}

.page-title {{
    color: {text_color};
    font-size: 2rem;
    font-weight: 750;
    margin: 0;
    line-height: 1.2;
}}

.page-subtitle {{
    color: {muted_text};
    font-size: 0.9rem;
    margin-top: 0.3rem;
}}

.accent-line {{
    width: 42px;
    height: 3px;
    background-color: {accent};
    border-radius: 50px;
    margin-top: 9px;
}}


/* ---------------------------------------------------------
   SECTIONS
--------------------------------------------------------- */

.section-title {{
    color: {text_color};
    font-size: 1.05rem;
    font-weight: 700;
    margin-top: 1.6rem;
    margin-bottom: 0.75rem;
}}


/* ---------------------------------------------------------
   METRIC CARDS
--------------------------------------------------------- */

.small-card {{
    height: 100px;
    background-color: {panel_background};
    border: 1px solid {border_color};
    border-radius: 12px;
    padding: 16px;
}}

.card-label {{
    color: {muted_text};
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.05rem;
}}

.card-value {{
    color: {text_color};
    font-size: 1.4rem;
    font-weight: 700;
    margin-top: 9px;
}}


/* ---------------------------------------------------------
   PANELS
--------------------------------------------------------- */

.panel {{
    background-color: {panel_background};
    border: 1px solid {border_color};
    border-radius: 12px;
    padding: 18px;
    min-height: 315px;
}}

.panel-title {{
    color: {text_color};
    font-size: 1rem;
    font-weight: 700;
}}

.panel-description {{
    color: {muted_text};
    font-size: 0.75rem;
    margin-top: 3px;
}}

.empty-graph {{
    height: 225px;
    margin-top: 14px;
    background-color: {secondary_background};
    border: 1px solid {border_color};
    border-radius: 9px;
}}


/* ---------------------------------------------------------
   ALERTS
--------------------------------------------------------- */

.alert-row {{
    background-color: {panel_background};
    border: 1px solid {border_color};
    border-left: 3px solid {accent};
    border-radius: 9px;
    padding: 13px 15px;
    margin-bottom: 8px;
}}

.alert-type {{
    color: {text_color};
    font-size: 0.9rem;
    font-weight: 700;
}}

.alert-details {{
    color: {muted_text};
    font-size: 0.75rem;
    margin-top: 4px;
}}


/* ---------------------------------------------------------
   TABLES
--------------------------------------------------------- */

[data-testid="stDataFrame"] {{
    border: 1px solid {border_color};
    border-radius: 12px;
    overflow: hidden;
}}


/* ---------------------------------------------------------
   INFO BOXES
--------------------------------------------------------- */

[data-testid="stAlert"] {{
    background-color: {panel_background} !important;
    color: {text_color} !important;
    border: 1px solid {border_color} !important;
}}


/* ---------------------------------------------------------
   DIVIDERS
--------------------------------------------------------- */

hr {{
    border-color: {border_color} !important;
}}

</style>
""",
    unsafe_allow_html=True
)


# =========================================================
# COMPONENTS
# =========================================================

def page_header(title, subtitle):
    html = f"""
<div class="page-header">
<div class="page-title">{title}</div>
<div class="page-subtitle">{subtitle}</div>
<div class="accent-line"></div>
</div>
"""
    st.markdown(html, unsafe_allow_html=True)


def metric_card(label, value="—"):
    html = f"""
<div class="small-card">
<div class="card-label">{label}</div>
<div class="card-value">{value}</div>
</div>
"""
    st.markdown(html, unsafe_allow_html=True)


def empty_graph_panel(title, description):
    html = f"""
<div class="panel">
<div class="panel-title">{title}</div>
<div class="panel-description">{description}</div>
<div class="empty-graph"></div>
</div>
"""
    st.markdown(html, unsafe_allow_html=True)


def render_alert(alert):
    alert_type = alert.get("type", "Unknown Detection")
    severity = alert.get("severity", "Unknown")
    source_ip = alert.get("source_ip", "Unknown")
    destination_ip = alert.get("destination_ip", "Unknown")
    detector = alert.get("detector", "Unknown")
    timestamp = alert.get("timestamp", "")

    html = f"""
<div class="alert-row">
<div class="alert-type">{alert_type}</div>
<div class="alert-details">{severity} • {source_ip} → {destination_ip} • {detector} • {timestamp}</div>
</div>
"""
    st.markdown(html, unsafe_allow_html=True)


# =========================================================
# CURRENT VALUES
# =========================================================

total_packets = metrics.get("total_packets", 0)
total_alerts = metrics.get("total_alerts", 0)
flows_analyzed = metrics.get("flows_analyzed", 0)
flows_classified = metrics.get("flows_classified", 0)
active_flows = metrics.get("active_flows", 0)

protocol_counts = metrics.get("protocol_counts", {})

tcp_packets = protocol_counts.get("TCP", 0)
udp_packets = protocol_counts.get("UDP", 0)
icmp_packets = protocol_counts.get("ICMP", 0)

if total_alerts == 0:
    threat_level = "Normal"

elif total_alerts <= 3:
    threat_level = "Elevated"

else:
    threat_level = "High"

model_loaded = os.path.exists(MODEL_PATH)
model_status = "Loaded" if model_loaded else "Not Loaded"


# =========================================================
# OVERVIEW
# =========================================================

if page == "Overview":

    page_header(
        "Security Overview",
        "Live status and high-level activity across the Hybrid IDS"
    )

    st.markdown(
        '<div class="section-title">System Status</div>',
        unsafe_allow_html=True
    )

    status1, status2, status3 = st.columns(3)

    with status1:
        metric_card("IDS Engine", "Ready")

    with status2:
        metric_card("Machine Learning Engine", model_status)

    with status3:
        metric_card("Signature Engine", "4 Detectors")

    st.markdown(
        '<div class="section-title">Session Metrics</div>',
        unsafe_allow_html=True
    )

    metric1, metric2, metric3, metric4 = st.columns(4)

    with metric1:
        metric_card("Packets Analyzed", f"{total_packets:,}")

    with metric2:
        metric_card("Total Alerts", f"{total_alerts:,}")

    with metric3:
        metric_card("Flows Analyzed", f"{flows_analyzed:,}")

    with metric4:
        metric_card("Current Threat Level", threat_level)

    st.markdown(
        '<div class="section-title">Monitoring</div>',
        unsafe_allow_html=True
    )

    graph1, graph2 = st.columns(2)

    with graph1:
        empty_graph_panel(
            "Network Activity",
            "Packet and flow activity over time"
        )

    with graph2:
        empty_graph_panel(
            "Detection Activity",
            "Signature and ML detection activity"
        )

    st.markdown(
        '<div class="section-title">Recent Alerts</div>',
        unsafe_allow_html=True
    )

    if alerts:
        for alert in reversed(alerts[-5:]):
            render_alert(alert)

    else:
        st.info("No security alerts have been recorded.")


# =========================================================
# ALERTS
# =========================================================

elif page == "Alerts":

    page_header(
        "Security Alerts",
        "Inspect and filter detections generated by the Hybrid IDS"
    )

    filter1, filter2, filter3 = st.columns(3)

    with filter1:
        severity_filter = st.selectbox(
            "Severity",
            [
                "All",
                "High",
                "Medium",
                "Low"
            ]
        )

    with filter2:
        source_filter = st.selectbox(
            "Detection Source",
            [
                "All",
                "Signature",
                "Machine Learning"
            ]
        )

    attack_types = sorted({
        alert.get("type", "Unknown")
        for alert in alerts
    })

    with filter3:
        attack_filter = st.selectbox(
            "Attack Type",
            ["All"] + attack_types
        )

    filtered_alerts = []

    for alert in alerts:
        severity = alert.get("severity", "Unknown")
        attack_type = alert.get("type", "Unknown")
        detector = alert.get("detector", "")

        if severity_filter != "All" and severity != severity_filter:
            continue

        if attack_filter != "All" and attack_type != attack_filter:
            continue

        is_ml = detector == "RandomForestLiveDetector"

        if source_filter == "Signature" and is_ml:
            continue

        if source_filter == "Machine Learning" and not is_ml:
            continue

        filtered_alerts.append(alert)

    st.markdown(
        '<div class="section-title">Alert Feed</div>',
        unsafe_allow_html=True
    )

    if filtered_alerts:
        for alert in reversed(filtered_alerts):
            render_alert(alert)

    else:
        st.info("No alerts match the selected filters.")


# =========================================================
# NETWORK
# =========================================================

elif page == "Network":

    page_header(
        "Network Analysis",
        "Inspect packet, protocol and flow-level network activity"
    )

    metric1, metric2, metric3, metric4 = st.columns(4)

    with metric1:
        metric_card("TCP Packets", f"{tcp_packets:,}")

    with metric2:
        metric_card("UDP Packets", f"{udp_packets:,}")

    with metric3:
        metric_card("ICMP Packets", f"{icmp_packets:,}")

    with metric4:
        metric_card("Active Flows", f"{active_flows:,}")

    st.markdown(
        '<div class="section-title">Traffic Analysis</div>',
        unsafe_allow_html=True
    )

    graph1, graph2 = st.columns(2)

    with graph1:
        empty_graph_panel(
            "Protocol Distribution",
            "Traffic grouped by network protocol"
        )

    with graph2:
        empty_graph_panel(
            "Flow Activity",
            "Network flow activity over time"
        )

    st.markdown(
        '<div class="section-title">Recent Flow Records</div>',
        unsafe_allow_html=True
    )

    if flow_records:
        flow_dataframe = pd.DataFrame(flow_records[-50:]).iloc[::-1]

        display_columns = [
            "timestamp",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "protocol",
            "packet_count",
            "total_bytes"
        ]

        display_columns = [
            column
            for column in display_columns
            if column in flow_dataframe.columns
        ]

        flow_dataframe = flow_dataframe[display_columns]

        flow_dataframe = flow_dataframe.rename(
            columns={
                "timestamp": "Time",
                "source_ip": "Source IP",
                "source_port": "Source Port",
                "destination_ip": "Destination IP",
                "destination_port": "Destination Port",
                "protocol": "Protocol",
                "packet_count": "Packets",
                "total_bytes": "Bytes"
            }
        )

        st.dataframe(
            flow_dataframe,
            use_container_width=True,
            hide_index=True,
            height=350
        )

    else:
        st.info("No completed flow records have been recorded yet.")


# =========================================================
# MACHINE LEARNING
# =========================================================

elif page == "Machine Learning":

    page_header(
        "Machine Learning",
        "Random Forest flow classification and model analysis"
    )

    accuracy = model_metrics.get("accuracy")
    macro_f1 = model_metrics.get("macro_f1")
    weighted_f1 = model_metrics.get("weighted_f1")

    accuracy_display = f"{accuracy * 100:.2f}%" if accuracy is not None else "—"
    macro_f1_display = f"{macro_f1 * 100:.2f}%" if macro_f1 is not None else "—"
    weighted_f1_display = f"{weighted_f1 * 100:.2f}%" if weighted_f1 is not None else "—"

    feature_count = model_metrics.get("features", 41)

    metric1, metric2, metric3, metric4 = st.columns(4)

    with metric1:
        metric_card("Model Accuracy", accuracy_display)

    with metric2:
        metric_card("Macro F1", macro_f1_display)

    with metric3:
        metric_card("Feature Count", feature_count)

    with metric4:
        metric_card("Flows Classified", f"{flows_classified:,}")

    st.markdown(
        '<div class="section-title">Additional Model Metrics</div>',
        unsafe_allow_html=True
    )

    extra1, extra2 = st.columns(2)

    with extra1:
        metric_card("Weighted F1", weighted_f1_display)

    with extra2:
        metric_card("Model", "Random Forest")

    st.markdown(
        '<div class="section-title">Model Analysis</div>',
        unsafe_allow_html=True
    )

    graph1, graph2 = st.columns(2)

    with graph1:
        empty_graph_panel(
            "Class Performance",
            "Model performance across supported attack classes"
        )

    with graph2:
        empty_graph_panel(
            "Prediction Confidence",
            "Model confidence across classified flows"
        )

    st.markdown(
        '<div class="section-title">Recent Predictions</div>',
        unsafe_allow_html=True
    )

    prediction_filter = st.selectbox(
        "Prediction",
        [
            "All",
            "BENIGN",
            "Suspicious Only"
        ]
    )

    filtered_predictions = []

    for prediction in predictions:
        prediction_class = prediction.get("prediction", "Unknown")

        if prediction_filter == "BENIGN" and prediction_class != "BENIGN":
            continue

        if prediction_filter == "Suspicious Only" and prediction_class == "BENIGN":
            continue

        filtered_predictions.append(prediction)

    if filtered_predictions:
        prediction_dataframe = pd.DataFrame(filtered_predictions[-50:]).iloc[::-1]

        if "confidence" in prediction_dataframe.columns:
            prediction_dataframe["confidence"] = prediction_dataframe["confidence"].apply(
                lambda value: f"{value * 100:.2f}%"
            )

        display_columns = [
            "timestamp",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "protocol",
            "prediction",
            "confidence"
        ]

        display_columns = [
            column
            for column in display_columns
            if column in prediction_dataframe.columns
        ]

        prediction_dataframe = prediction_dataframe[display_columns]

        prediction_dataframe = prediction_dataframe.rename(
            columns={
                "timestamp": "Time",
                "source_ip": "Source IP",
                "source_port": "Source Port",
                "destination_ip": "Destination IP",
                "destination_port": "Destination Port",
                "protocol": "Protocol",
                "prediction": "Prediction",
                "confidence": "Confidence"
            }
        )

        st.dataframe(
            prediction_dataframe,
            use_container_width=True,
            hide_index=True,
            height=400
        )

    else:
        st.info("No ML predictions match the selected filter.")