"""Automated testing runner.

Sends each attack case to the target LLM concurrently and pairs the
prompt with the raw response for the analyzer stage.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .attacks import AttackCase
from .target import OpenAITarget, TargetResponse


@dataclass
class TestResult:
    case: AttackCase
    response: TargetResponse


def run_tests(
    target: OpenAITarget,
    cases: list[AttackCase],
    concurrency: int = 5,
    on_result=None,
) -> list[TestResult]:
    """Run all attack cases against the target and return raw results.

    `on_result` is an optional callback(TestResult) fired as each result
    comes in, useful for CLI progress reporting.
    """
    results: list[TestResult] = []
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        future_to_case = {
            pool.submit(target.query, case.prompt): case for case in cases
        }
        for future in as_completed(future_to_case):
            case = future_to_case[future]
            response = future.result()
            result = TestResult(case=case, response=response)
            results.append(result)
            if on_result:
                on_result(result)

    # Preserve dataset order in the final report regardless of completion order.
    order = {case.id: i for i, case in enumerate(cases)}
    results.sort(key=lambda r: order[r.case.id])
    return results
