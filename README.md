# Step 3: Core Code Implementation (Copy My Snippets, Line-by-Line)

## Overview

We'll build MVP: UI input → LLM translate to KQL/EQL → Mock execute on data → Enrich + Display.

## Core Files Implementation

### src/translator.py (LLM translation—heart of it)

```python
import ollama
from langchain.prompts import PromptTemplate

def translate_to_query(nl_query, target_lang='KQL'):
    # Support KQL or EQL
    prompt_template = PromptTemplate.from_template(
        "Translate this natural language threat hunt to {lang} query: '{query}'. "
        "Output ONLY the query string, no explanations. Ensure it's valid syntax."
    )
    prompt = prompt_template.format(lang=target_lang, query=nl_query)
    response = ollama.generate(model='llama2', prompt=prompt)
    return response['response'].strip()  # Clean output
```

### src/hunter.py (Execute query on data—mock for now)

```python
import pandas as pd

def execute_hunt(query, data_path='data/sample_logs.json'):
    # Load simulated data (real: API to Sentinel/Falcon)
    df = pd.read_json(data_path)
    # Mock execution: Filter df based on parsed query (parse query string here)
    # For simplicity, assume query like "process_name == 'powershell.exe' AND ip LIKE '%russia%'"
    # Use eval or safer parsing—crude example:
    try:
        results = df.query(query)  # Pandas query simulates
    except:
        results = pd.DataFrame()  # Handle bad queries
    return results
```

### src/enricher.py (TI enrichment)

```python
import requests
from dotenv import load_dotenv
import os

load_dotenv()

def enrich_ioc(ioc, type='ip'):
    # IOC = IP/hash/etc
    if type == 'ip':
        url = f"https://www.abuseipdb.com/check/{ioc}/json?key={os.getenv('ABUSEIPDB_KEY')}"
        response = requests.get(url)
        return response.json() if response.ok else {}
    # Add VT for hashes/files: Similar requests.get
```

### src/app.py (Streamlit UI—run with `streamlit run app.py`)

```python
import streamlit as st
from translator import translate_to_query
from hunter import execute_hunt
from enricher import enrich_ioc
import plotly.express as px

st.title("NL Threat Hunter")
nl_query = st.text_input("Enter hunt in English (e.g., 'Suspicious logins from Russia last day')")
lang = st.selectbox("Query Language", ["KQL", "EQL"])

if st.button("Hunt"):
    if not nl_query:
        st.error("Input something, idiot.")
        return
    query = translate_to_query(nl_query, lang)
    st.write(f"Generated Query: {query}")
    results = execute_hunt(query)  # Add real data path
    if results.empty:
        st.warning("No threats found—or your query sucks.")
    else:
        st.dataframe(results)
        # Enrich example IP from results
        if 'ip' in results.columns:
            sample_ip = results['ip'].iloc[0]
            enrichment = enrich_ioc(sample_ip)
            st.json(enrichment)
        # Viz: Plot attack chains if NetworkX integrated
        fig = px.bar(results, x='timestamp', y='risk_score')
        st.plotly_chart(fig)
        # MITRE map: Hardcode or API fetch
        st.write("Mapped to MITRE T1078 (e.g.)")
```

## Key Implementation Points

1. **translator.py**: Heart of the system. Uses Ollama (local LLM) to translate natural language to KQL/EQL queries.
2. **hunter.py**: Executes the translated query on simulated/real data using pandas.
3. **enricher.py**: Integrates with threat intelligence APIs (VirusTotal, AbuseIPDB) for IOC enrichment.
4. **app.py**: Streamlit UI that ties everything together for user-friendly interaction.

## Data & Testing

1. Generate `data/sample_logs.json`: Create 100+ entries with realistic telemetry.
2. Unit tests in `tests/test_translator.py`: Use pytest to validate query generation.
3. Manual testing: Input queries, verify outputs, fix LLM hallucinations.
4. Metrics: Track accuracy (aim for 85%+ on 100+ test hunts).

## Next Steps

1. Implement the code snippets above.
2. Set up the data directory with sample logs.
3. Create unit tests for each module.
4. Test the Streamlit app with various queries.
5. Deploy and share for review.
