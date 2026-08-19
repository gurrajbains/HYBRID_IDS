import streamlit as st


st.set_page_config(
    page_title="Hybrid IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


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


# =========================================================
# PALETTE
# =========================================================

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

/* ======================================================
   REMOVE STREAMLIT HEADER
====================================================== */

[data-testid="stHeader"] {{
    display: none !important;
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


/* ======================================================
   APP
====================================================== */

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


/* ======================================================
   SIDEBAR
====================================================== */

[data-testid="stSidebar"] {{
    background-color: {sidebar_background} !important;
    border-right: 1px solid {border_color};
    top: 0 !important;
}}

[data-testid="stSidebarContent"] {{
    background-color: {sidebar_background} !important;
}}

[data-testid="stSidebar"] > div {{
    background-color: {sidebar_background} !important;
}}

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


/* ======================================================
   RADIO CONTROLS
====================================================== */

[data-testid="stRadio"] {{
    color: {text_color} !important;
}}

[data-testid="stRadio"] label {{
    color: {text_color} !important;
}}

[data-testid="stRadio"] p {{
    color: {text_color} !important;
}}


/* ======================================================
   DROPDOWN / PALETTE
====================================================== */

[data-baseweb="select"] > div {{
    background-color: {input_background} !important;
    border-color: {border_color} !important;
    color: {text_color} !important;
}}

[data-baseweb="select"] span {{
    color: {text_color} !important;
}}

[data-baseweb="select"] input {{
    color: {text_color} !important;
}}

[data-baseweb="popover"] {{
    background-color: {input_background} !important;
}}

[data-baseweb="menu"] {{
    background-color: {input_background} !important;
}}

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


/* ======================================================
   PAGE HEADER
====================================================== */

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


/* ======================================================
   SECTION TITLES
====================================================== */

.section-title {{
    color: {text_color};
    font-size: 1.05rem;
    font-weight: 700;
    margin-top: 1.6rem;
    margin-bottom: 0.75rem;
}}


/* ======================================================
   SMALL CARDS
====================================================== */

.small-card {{
    height: 90px;
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


/* ======================================================
   LARGE PANELS
====================================================== */

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


/* ======================================================
   EMPTY GRAPH
====================================================== */

.empty-graph {{
    height: 225px;
    margin-top: 14px;
    background-color: {secondary_background};
    border: 1px solid {border_color};
    border-radius: 9px;
}}


/* ======================================================
   EMPTY TABLE
====================================================== */

.empty-table {{
    height: 260px;
    background-color: {panel_background};
    border: 1px solid {border_color};
    border-radius: 12px;
}}


/* ======================================================
   INPUT LABELS
====================================================== */

[data-testid="stSelectbox"] label,
[data-testid="stSelectbox"] p {{
    color: {text_color} !important;
}}

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


def empty_card(label):
    html = f"""
<div class="small-card">
<div class="card-label">{label}</div>
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


def empty_table():
    st.markdown(
        '<div class="empty-table"></div>',
        unsafe_allow_html=True
    )


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
        empty_card("IDS Engine")

    with status2:
        empty_card("Machine Learning Engine")

    with status3:
        empty_card("Signature Engine")


    st.markdown(
        '<div class="section-title">Session Metrics</div>',
        unsafe_allow_html=True
    )

    metric1, metric2, metric3, metric4 = st.columns(4)

    with metric1:
        empty_card("Packets Analyzed")

    with metric2:
        empty_card("Total Alerts")

    with metric3:
        empty_card("Flows Analyzed")

    with metric4:
        empty_card("Current Threat Level")


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

    empty_table()


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
        st.selectbox(
            "Severity",
            [
                "All",
                "High",
                "Medium",
                "Low"
            ]
        )

    with filter2:
        st.selectbox(
            "Detection Source",
            [
                "All",
                "Signature",
                "Machine Learning"
            ]
        )

    with filter3:
        st.selectbox(
            "Attack Type",
            ["All"]
        )

    st.markdown(
        '<div class="section-title">Alert Feed</div>',
        unsafe_allow_html=True
    )

    empty_table()


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
        empty_card("TCP Packets")

    with metric2:
        empty_card("UDP Packets")

    with metric3:
        empty_card("ICMP Packets")

    with metric4:
        empty_card("Active Flows")


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
        '<div class="section-title">Flow Records</div>',
        unsafe_allow_html=True
    )

    empty_table()


# =========================================================
# MACHINE LEARNING
# =========================================================

elif page == "Machine Learning":

    page_header(
        "Machine Learning",
        "Random Forest flow classification and model analysis"
    )

    metric1, metric2, metric3, metric4 = st.columns(4)

    with metric1:
        empty_card("Model Accuracy")

    with metric2:
        empty_card("Macro F1")

    with metric3:
        empty_card("Feature Count")

    with metric4:
        empty_card("Flows Classified")


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

    empty_table()