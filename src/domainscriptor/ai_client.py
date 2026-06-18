import os
from typing import Optional

import requests

_API_URL = "https://openrouter.ai/api/v1/chat/completions"
_DEFAULT_MODEL = "anthropic/claude-haiku-4-5"


class OpenRouterClient:
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        self.model = model or os.environ.get("OPENROUTER_MODEL", _DEFAULT_MODEL)
        if not self.api_key:
            raise EnvironmentError(
                "OPENROUTER_API_KEY is not set. Export it before starting Domainscriptor:\n"
                "  export OPENROUTER_API_KEY=sk-or-..."
            )

    def chat(self, system_prompt: str, user_message: str, timeout: int = 60) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/domainscriptor",
            "X-Title": "Domainscriptor",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        }
        response = requests.post(_API_URL, headers=headers, json=payload, timeout=timeout)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
