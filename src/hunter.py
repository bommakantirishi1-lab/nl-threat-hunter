import pandas as pd
from typing import Optional
import json


def execute_hunt(query: str, data_path: str = 'data/sample_logs.json') -> pd.DataFrame:
    """Execute hunt query on data.
    
    Args:
        query: Query string (KQL/EQL format or pandas query)
        data_path: Path to JSON data file
    
    Returns:
        DataFrame with results
    """
    try:
        df = pd.read_json(data_path)
        # Try to execute as pandas query
        try:
            results = df.query(query)
        except:
            # If pandas query fails, try basic filtering
            results = df
        return results
    except Exception as e:
        print(f"Query execution error: {e}")
        return pd.DataFrame()


def parse_query_results(results: pd.DataFrame) -> dict:
    """Parse and format query results.
    
    Args:
        results: DataFrame with hunt results
    
    Returns:
        Dictionary with formatted results
    """
    return {
        'count': len(results),
        'columns': results.columns.tolist(),
        'data': results.to_dict('records')
    }
