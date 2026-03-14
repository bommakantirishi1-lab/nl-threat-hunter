# Step 3: Core Code Implementation
## Overview

We'll build MVP: UI input → LLM translate to KQL/EQL → Mock execute on data → Enrich + Display.

## Core Files Implementation

### src/translator.py (LLM Translation Module)
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

### src/hunter.py (Query Execution on Simulated Data)
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



## Overview

# Step 4: Data Generation & Testing
## 1. Generate Sample Data

**File:** `data/sample_logs.json`

Create realistic simulated security logs with 100+ entries. Example structure:

```json
[
  {
    "timestamp": "2026-03-14T10:30:00Z",
    "ip": "192.168.1.100",
    "process": "powershell.exe",
    "risk_score": 80,
    "event_type": "suspicious_execution"
  },
  {
    "timestamp": "2026-03-14T11:45:00Z",
    "ip": "10.0.0.50",
    "process": "cmd.exe",
    "risk_score": 65,
    "event_type": "command_execution"
  }
]
```

**Generation Script** (generate_logs.py):

```python
import json
import random
from datetime import datetime, timedelta

processes = ["powershell.exe", "cmd.exe", "svchost.exe", "rundll32.exe", "explorer.exe"]
ips = [f"192.168.1.{i}" for i in range(1, 255)] + [f"10.0.0.{i}" for i in range(1, 255)]
event_types = ["suspicious_execution", "command_execution", "network_connection", "registry_mod"]

logs = []
base_time = datetime.now() - timedelta(days=1)

for i in range(100):
    logs.append({
        "timestamp": (base_time + timedelta(minutes=i*15)).isoformat() + "Z",
        "ip": random.choice(ips),
        "process": random.choice(processes),
        "risk_score": random.randint(30, 100),
        "event_type": random.choice(event_types)
    })

with open('data/sample_logs.json', 'w') as f:
    json.dump(logs, f, indent=2)

print("Generated 100 sample logs in data/sample_logs.json")
```

Run: `python generate_logs.py`

## 2. Unit Tests

**File:** `tests/test_translator.py`

Test the LLM translation function with pytest:

```python
import pytest
from src.translator import translate_to_query

def test_translate_powershell():
    """Test translation of PowerShell hunting query"""
    result = translate_to_query("hunt for suspicious powershell executions")
    assert "powershell" in result.lower() or "process" in result.lower()

def test_translate_network():
    """Test translation of network hunting query"""
    result = translate_to_query("find unusual network connections")
    assert "network" in result.lower() or "connection" in result.lower() or "ip" in result.lower()

def test_translate_output_format():
    """Test that output is a valid string"""
    result = translate_to_query("test query")
    assert isinstance(result, str)
    assert len(result) > 0
```

Run: `pytest tests/test_translator.py -v`

## 3. Manual Testing

### Test Cases (20+ sample queries):

1. Input: "Hunt for lateral movement from suspicious IPs"
   - Expected output: KQL/EQL query with IP filtering and lateral movement patterns

2. Input: "Find processes with network connections to unknown domains"
   - Expected output: Query filtering on network connections and domain patterns

3. Input: "Detect privilege escalation attempts"
   - Expected output: Query matching privilege escalation TTPs

4. Input: "Search for malware signatures in log files"
   - Expected output: Query filtering on malware indicators

5. Input: "Find command injection attempts"
   - Expected output: Query matching command injection patterns

### Testing Process:

1. Run Streamlit app: `streamlit run src/app.py`
2. Enter query in text box
3. Select query language (KQL or EQL)
4. Click "Hunt"
5. Verify:
   - Generated query syntax is correct
   - Results match expected output
   - MITRE mappings are appropriate
   - Enrichment data loads correctly

### Fix LLM Hallucinations:

Add few-shot examples to improve accuracy:

```python
FEW_SHOT_EXAMPLES = """
Example 1: 
  Input: "find powershell"
  Output: process_name == "powershell.exe"

Example 2:
  Input: "suspicious from russia"
  Output: origin_country == "Russia" AND risk_score > 70

Example 3:
  Input: "network to c2"
  Output: destination_ip IN ('malicious_ips_list') AND protocol IN ('tcp', 'udp')
"""
```

## 4. Metrics & Accuracy

### Tracking Metrics:

**File:** `metrics.json`

```json
{
  "total_tests": 50,
  "successful_translations": 43,
  "accuracy": "86%",
  "average_response_time_ms": 250,
  "false_positives": 2,
  "false_negatives": 5,
  "test_date": "2026-03-14"
}
```

### Accuracy Calculation:

```python
def calculate_accuracy(correct_queries, total_queries):
    return (correct_queries / total_queries) * 100

# Example: 43 correct out of 50 = 86% accuracy
accuracy = calculate_accuracy(43, 50)
print(f"Query Translation Accuracy: {accuracy}%")
```

### Target Metrics:

- **Query Accuracy:** >= 85% (85+ correct translations out of 100 hunts)
- **Response Time:** < 500ms per query
- **False Positive Rate:** < 5%
- **False Negative Rate:** < 10%

## 5. Validation Checklist

- [ ] All 100 sample logs generated in `data/sample_logs.json`
- [ ] All unit tests pass: `pytest tests/ -v`
- [ ] Manual testing with 20+ sample queries completed
- [ ] Metrics calculated and logged
- [ ] Accuracy >= 85%
- [ ] Response time < 500ms
- [ ] LLM hallucinations identified and fixed
- [ ] Results enriched with VT/AbuseIPDB data
- [ ] MITRE mappings validated
- [ ] README updated with metrics

## Next Steps

1. Complete all testing and validation
2. Document any failures or issues found
3. Iterate on LLM prompts to improve accuracy
4. Move to Step 5: Advanced Features & Polish
5. Deploy and showcase results


# Step 5: Advanced Features & Enhancements

Once the core functionality is working, consider adding the following enhancements:

### MITRE ATT&CK Integration
- Use NetworkX to visualize attack chains and map threat hunting results to MITRE ATT&CK techniques
- Fetch technique metadata from the MITRE ATT&CK API to provide context for detected activities

### Production Integration
- Replace simulated data with real SIEM/EDR integration using Microsoft Sentinel API (with MSAL authentication)
- Implement azure-monitor-query library for querying production telemetry

### Error Handling & Reliability
- Implement fallback mechanisms for LLM failures (rule-based query generation for common hunt patterns)
- Add input validation and query syntax checking before execution

### Security Hardening
- Sanitize all user inputs using appropriate libraries (e.g., bleach)
- Encrypt sensitive environment variables and API keys
- Implement proper authentication and authorization for the web interface

### Deployment
- Create a Dockerfile for containerized deployment
- Configure deployment to cloud platforms (Heroku, AWS, or Azure)

# Step 6: Documentation & Deployment

### README Documentation

Create comprehensive documentation including:

- **Project Overview**: Clear description of purpose and capabilities
- **Setup Instructions**: 
  ```bash
  pip install -r requirements.txt
  ollama run llama2
  ```
- **Usage Guide**: Screenshots and examples of the UI in action
- **Architecture Diagram**: Visual representation of system components (use draw.io or text-based diagrams)
- **Performance Metrics**: Document accuracy metrics (e.g., "85% query translation accuracy on 100 test hunts")
- **Future Roadmap**: Planned integrations with real EDR systems and ISO 27001 compliance controls

### Deployment Process

1. Create a Heroku application or equivalent cloud platform
2. Configure environment variables for API keys and sensitive data
3. Push code to the deployment platform
4. Update README with live demo link: `Demo: https://nl-threat-hunter.herokuapp.com`

# Step 7: Project Completion & Next Steps

### Final Tasks

1. **Version Control**: Commit all code changes with descriptive messages
   ```bash
   git add .
   git commit -m "Complete natural language threat hunter implementation"
   git push origin main
   ```

2. **Repository Sharing**: Make your GitHub repository public to showcase your work

3. **Resume Update**: Add this project to your professional resume:
   - "Developed natural language threat hunting tool using Ollama/Streamlit"
   - "Implemented LLM-based translation of plain English queries to KQL/EQL with 85% accuracy"
   - "Integrated threat intelligence enrichment via VirusTotal and AbuseIPDB APIs"

4. **Compliance Documentation**: Document alignment with security frameworks
   - Map features to ISO 27001 controls (e.g., A.13 for communications security)
   - Create audit trail documentation for query execution logs

### Recommended Next Steps

- Conduct thorough testing with diverse threat hunting scenarios
- Gather feedback from SOC analysts and iterate on the user interface
- Explore integration with additional SIEM platforms (Splunk, Elastic)
- Implement advanced features like automated playbook generation
- Consider contributing to open-source threat hunting communities
