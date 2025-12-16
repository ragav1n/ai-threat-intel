from threat_summarizer.model_client import query_ollama

def validate_severity(threat_input: str, assigned_severity: str, model="llama3.2:latest") -> str:
    prompt = f"""
You are a cybersecurity severity validation engine.

The following threat input has been assigned a severity level of "{assigned_severity}".

THREAT INPUT:
{threat_input}

Validate whether this severity is appropriate. If it's correct, respond with: VALID.
If it's not appropriate, respond with: INVALID and suggest the correct severity in one word (Low, Medium, High).

Response Format:
- VALID
or
- INVALID: <correct severity>
"""

    response = query_ollama(model, prompt)
    return response.strip()
