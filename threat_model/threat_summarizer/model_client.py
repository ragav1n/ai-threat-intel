"""
Ollama LLM client for threat summarization.
"""
import os
from typing import Optional

import requests
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type


# Configuration
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))  # LLM can be slow


@retry(
    stop=stop_after_attempt(2),
    wait=wait_fixed(3),
    retry=retry_if_exception_type(requests.RequestException),
)
def query_ollama(
    model: str, 
    prompt: str, 
    timeout: Optional[int] = None
) -> str:
    """
    Query Ollama API for text generation.
    
    Args:
        model: The model name (e.g., "llama3.2:latest").
        prompt: The prompt to send to the model.
        timeout: Request timeout in seconds (default from env).
        
    Returns:
        The generated response text.
        
    Raises:
        requests.RequestException: If the API request fails.
    """
    response = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={
            "model": model, 
            "prompt": prompt, 
            "stream": False
        },
        timeout=timeout or OLLAMA_TIMEOUT
    )
    response.raise_for_status()
    return response.json()["response"].strip()


def check_ollama_connection() -> bool:
    """Check if Ollama is running and accessible."""
    try:
        response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False


def list_available_models() -> list[str]:
    """List available models from Ollama."""
    try:
        response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=10)
        if response.status_code == 200:
            data = response.json()
            return [model["name"] for model in data.get("models", [])]
    except requests.RequestException:
        pass
    return []
