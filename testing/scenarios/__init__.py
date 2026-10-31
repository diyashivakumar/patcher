"""Executable test scenarios. Each scenario module exposes TESTS: a list of TestCase."""
from dataclasses import dataclass
from typing import Callable

SECURITY = "security"
REGRESSION = "regression"


@dataclass(frozen=True)
class TestCase:
    __test__ = False       # not a pytest test class

    test_id: str
    scenario: str
    category: str          # SECURITY or REGRESSION
    name: str
    description: str
    expected: str
    run: Callable          # run(client) -> dict with keys passed, actual, evidence, (exploit_succeeded)


def get_tests(scenario):
    from testing.scenarios import chain, idor, sqli

    registry = {"sqli": sqli.TESTS, "idor": idor.TESTS, "chain": chain.TESTS}
    if scenario == "all":  # "all" stays sqli+idor; the composed chain is its own scenario
        return registry["sqli"] + registry["idor"]
    if scenario not in registry:
        raise ValueError(f"Unknown scenario '{scenario}'. Use one of: sqli, idor, chain, all")
    return registry[scenario]
