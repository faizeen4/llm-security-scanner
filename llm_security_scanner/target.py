"""Target LLM wrapper.

Wraps the model under test so the rest of the pipeline doesn't care
which provider or SDK version is behind it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from openai import OpenAI

from .config import Config


@dataclass
class TargetResponse:
    prompt: str
    system_prompt: str | None
    output_text: str
    latency_s: float
    error: str | None = None


class OpenAITarget:
    """A target LLM accessed through the OpenAI-compatible chat API."""

    def __init__(self, config: Config, system_prompt: str | None = None):
        self.config = config
        self.system_prompt = system_prompt
        self.client = OpenAI(api_key=config.api_key)

    def query(self, prompt: str) -> TargetResponse:
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": prompt})

        start = time.monotonic()
        try:
            completion = self.client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                timeout=self.config.request_timeout,
            )
            text = completion.choices[0].message.content or ""
            return TargetResponse(
                prompt=prompt,
                system_prompt=self.system_prompt,
                output_text=text,
                latency_s=time.monotonic() - start,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced in the report
            return TargetResponse(
                prompt=prompt,
                system_prompt=self.system_prompt,
                output_text="",
                latency_s=time.monotonic() - start,
                error=str(exc),
            )
