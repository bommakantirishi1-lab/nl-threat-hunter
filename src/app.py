import streamlit as st
from src.translator import translate_to_query
from src.hunter import execute_hunt, parse_query_results
from src.enricher import enrich_ioc
import plotly.express as px
import pandas as pd

# Page configuration
st.set_page_config(
    page_title="NL Threat Hunter",
    page_icon="🔍",
    layout="wide"
)

# Sidebar
with st.sidebar:
    st.title("⚙️ Configuration")
    target_lang = st.selectbox(
        "Query Language",
        ["KQL", "EQL"],
        help="Select target query language"
    )
    data_source = st.radio(
        "Data Source",
        ["Simulated Logs", "API Connection"],
        help="Choose data source for hunting"
    )

# Main UI
st.title("🔍 Natural Language Threat Hunter")
st.markdown(
    "Translate English threat hunts to KQL/EQL queries with AI"
)

# Input section
col1, col2 = st.columns([4, 1])
with col1:
    nl_query = st.text_input(
        "Enter threat hunting query (e.g., 'Find suspicious PowerShell from Russia last 24h')",
        placeholder="Type your hunting hypothesis..."
    )

with col2:
    hunt_button = st.button("🔍 Hunt", use_container_width=True)

if hunt_button and nl_query:
    with st.spinner("Translating query and executing hunt..."):
        try:
            # Translate query
            generated_query = translate_to_query(nl_query, target_lang)
            st.success("✅ Query translated successfully")
            
            # Display generated query
            st.subheader(f"Generated {target_lang} Query")
            st.code(generated_query, language="sql")
            
            # Execute hunt
            results = execute_hunt(generated_query)
            
            if not results.empty:
                st.subheader("📊 Hunt Results")
                st.dataframe(results, use_container_width=True)
                
                # Enrichment
                st.subheader("🔗 IOC Enrichment")
                if 'ip' in results.columns:
                    sample_ips = results['ip'].head(3).tolist()
                    for ip in sample_ips:
                        with st.expander(f"Enrich {ip}"):
                            enrichment = enrich_ioc(ip, 'ip')
                            st.json(enrichment)
                
                # Visualization
                st.subheader("📈 Risk Timeline")
                if 'risk_score' in results.columns and 'timestamp' in results.columns:
                    fig = px.bar(
                        results,
                        x='timestamp',
                        y='risk_score',
                        title="Risk Score Over Time",
                        labels={"risk_score": "Risk Score", "timestamp": "Time"}
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                # MITRE Mapping (placeholder)
                st.subheader("🎯 MITRE ATT&CK Mapping")
                st.info("Mapped to: T1078 (Valid Accounts), T1059 (Command & Scripting)")
            else:
                st.warning("⚠️ No threats found or query execution failed")
                
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")

st.divider()
st.caption("NL Threat Hunter v1.0 | Powered by Ollama LLM")
