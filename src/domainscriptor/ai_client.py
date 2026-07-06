import os
from abc import ABC, abstractmethod
from typing import Optional

import requests


class AIClient(ABC):
    @abstractmethod
    def chat(self, system_prompt: str, user_message: str, timeout: int = 60) -> str:
        raise NotImplementedError


class OpenRouterClient(AIClient):
    _API_URL = "https://openrouter.ai/api/v1/chat/completions"
    _DEFAULT_MODEL = "anthropic/claude-haiku-4-5"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        self.model = model or os.environ.get("OPENROUTER_MODEL", self._DEFAULT_MODEL)
        if not self.api_key:
            raise EnvironmentError(
                "OPENROUTER_API_KEY is not set.\n"
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
        response = requests.post(self._API_URL, headers=headers, json=payload, timeout=timeout)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]


class AnthropicClient(AIClient):
    _API_URL = "https://api.anthropic.com/v1/messages"
    _DEFAULT_MODEL = "claude-haiku-4-5-20251001"
    _API_VERSION = "2023-06-01"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model or os.environ.get("ANTHROPIC_MODEL", self._DEFAULT_MODEL)
        if not self.api_key:
            raise EnvironmentError(
                "ANTHROPIC_API_KEY is not set.\n"
                "  export ANTHROPIC_API_KEY=sk-ant-..."
            )

    def chat(self, system_prompt: str, user_message: str, timeout: int = 60) -> str:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self._API_VERSION,
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": 2048,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_message},
            ],
        }
        response = requests.post(self._API_URL, headers=headers, json=payload, timeout=timeout)
        response.raise_for_status()
        return response.json()["content"][0]["text"]


class OpenAIClient(AIClient):
    _API_URL = "https://api.openai.com/v1/chat/completions"
    _DEFAULT_MODEL = "gpt-4o-mini"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model or os.environ.get("OPENAI_MODEL", self._DEFAULT_MODEL)
        if not self.api_key:
            raise EnvironmentError(
                "OPENAI_API_KEY is not set.\n"
                "  export OPENAI_API_KEY=sk-..."
            )

    def chat(self, system_prompt: str, user_message: str, timeout: int = 60) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        }
        response = requests.post(self._API_URL, headers=headers, json=payload, timeout=timeout)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]


_PROVIDERS = {
    "openrouter": OpenRouterClient,
    "anthropic": AnthropicClient,
    "openai": OpenAIClient,
}


def get_ai_client() -> AIClient:
    provider = os.environ.get("AI_PROVIDER", "openrouter").lower()
    client_cls = _PROVIDERS.get(provider)
    if not client_cls:
        raise EnvironmentError(
            f"Unknown AI_PROVIDER '{provider}'. Valid options: {', '.join(_PROVIDERS)}"
        )
    return client_cls()
