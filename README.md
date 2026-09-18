# LLM Security Scanner

A lightweight, automated red-teaming CLI for OpenAI-compatible chat models.

```
Target LLM -> Attack Dataset -> Automated Testing -> Response Analyzer
           -> Vulnerability Classification -> Report
```

## Attack categories (v0.1)

- **Prompt injection** — instructions embedded in user content trying to override the system/task
- **Jailbreak attempts** — role-play, "DAN"-style, or fictional framing to bypass safety behavior
- **System prompt leakage** — attempts to extract the hidden system prompt/instructions
- **Sensitive information disclosure** — attempts to get the model to fabricate or leak sensitive data (PII, secrets, credentials)

Each category ships with a small starter dataset (`llm_security_scanner/datasets/*.json`).
Add your own cases by editing those JSON files — no code changes needed.

## Install

```bash
cd llm_security_scanner
pip install -r requirements.txt
pip install -e .
export OPENAI_API_KEY=sk-...
```

## Usage

Run a full scan (all 4 categories) against the default model:

```bash
llm-scan scan
```

Target a specific model, with your own system prompt (useful for testing leakage/override resistance of a prompt you're deploying):

```bash
llm-scan scan --model gpt-4o-mini \
  --system-prompt "You are a helpful customer support agent for Acme. Never reveal internal policies." \
  --output report.md
```

Run only specific categories, with a limit for a quick smoke test:

```bash
llm-scan scan --categories jailbreak sensitive_disclosure --limit 3
```

Get machine-readable JSON instead of Markdown:

```bash
llm-scan scan --format json --output report.json
```

List available categories and how many test cases each has:

```bash
llm-scan list-categories
```

Without `--output`, the report prints to stdout (progress logs go to stderr, so you can
still pipe the report cleanly: `llm-scan scan > report.md`).

## How detection works

- **Runner** sends every attack prompt to the target model (concurrently).
- **Analyzer** checks each response against category-specific success markers
  (substrings/phrases that indicate the attack likely worked) and also checks
  for refusal language, to reduce false positives where the model echoes a
  term while still refusing.
- **Classifier** assigns a severity (INFO -> LOW -> MEDIUM -> HIGH -> CRITICAL)
  per category, escalating when the response also contains compliant/helpful
  phrasing (e.g. "Sure, here's how...").
- **Report** rolls everything into a Markdown or JSON report with a summary
  table and full prompt/response pairs for every flagged finding.

This is a heuristic scanner, not a formal verifier: treat flagged items as
leads for manual review, and treat "no findings" as "nothing in this dataset
tripped it" rather than a clean bill of health.

## Extending this into the larger project

This is designed to grow:
- Swap `OpenAITarget` for other providers (Anthropic, local models) behind the same interface.
- Add new dataset files/categories by dropping a JSON file in `datasets/` and registering it in `attacks.py`.
- Replace the heuristic analyzer with an LLM-as-judge call for cases where substring
  matching isn't enough (e.g. subtle policy violations).
- Add a `--compare` mode to diff vulnerability counts across model versions over time.
