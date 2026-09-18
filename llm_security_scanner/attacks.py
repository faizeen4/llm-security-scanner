"""Attack dataset loading.

Each dataset file is a JSON list of attack cases:
    {"id": str, "prompt": str, "success_markers": [str, ...]}

success_markers are lowercase substrings that, if found in the model's
response, suggest the attack likely succeeded. They are heuristics, not
proof - the analyzer combines them with structural checks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

DATASET_DIR = Path(__file__).parent / "datasets"

CATEGORIES = {
    "prompt_injection": "Prompt Injection",
    "jailbreak": "Jailbreak Attempts",
    "system_prompt_leakage": "System Prompt Leakage",
    "sensitive_disclosure": "Sensitive Information Disclosure",
}


@dataclass
class AttackCase:
    id: str
    category: str
    category_label: str
    prompt: str
    success_markers: list[str]


def load_category(category: str) -> list[AttackCase]:
    if category not in CATEGORIES:
        raise ValueError(
            f"Unknown category '{category}'. Valid options: {list(CATEGORIES)}"
        )
    path = DATASET_DIR / f"{category}.json"
    with open(path, encoding="utf-8") as f:
        raw_cases = json.load(f)
    return [
        AttackCase(
            id=case["id"],
            category=category,
            category_label=CATEGORIES[category],
            prompt=case["prompt"],
            success_markers=case.get("success_markers", []),
        )
        for case in raw_cases
    ]


def load_all(categories: list[str] | None = None) -> list[AttackCase]:
    selected = categories or list(CATEGORIES)
    cases: list[AttackCase] = []
    for category in selected:
        cases.extend(load_category(category))
    return cases
