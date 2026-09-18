"""Configuration and environment handling."""

import os
from dataclasses import dataclass


@dataclass
class Config:
    api_key: str
    model: str = "gpt-4o-mini"
    temperature: float = 0.7
    max_tokens: int = 500
    request_timeout: int = 30
    concurrency: int = 5

    @classmethod
    def from_env(cls, model: str | None = None) -> "Config":
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "OPENAI_API_KEY environment variable is not set. "
                "Export it before running the scanner:\n"
                "  export OPENAI_API_KEY=sk-..."
            )
        return cls(api_key=api_key, model=model or "gpt-4o-mini")
