import ollama
from langchain.prompts import PromptTemplate


def translate_to_query(nl_query, target_lang='KQL'):
    """Translate natural language to query language (KQL/EQL).
    
    Args:
        nl_query: Natural language threat hunt query
        target_lang: Target query language ('KQL' or 'EQL')
    
    Returns:
        Query string in target language
    """
    prompt_template = PromptTemplate.from_template(
        "Translate this natural language threat hunt to {lang} query: '{query}'. "
        "Output ONLY the query string, no explanations. Ensure it's valid syntax. "
        "Examples: 'find malware downloads' -> 'event.category = \"malware\" AND process.name = \"wget\"'; "
        "'suspicious logins from Russia' -> 'source.geo.country_name = \"Russia\" AND event.action = \"login\"'"
    )
    prompt = prompt_template.format(lang=target_lang, query=nl_query)
    response = ollama.generate(model='llama2', prompt=prompt)
    return response['response'].strip()
