"""
TestEngine — orchestrates scenario runs across frameworks, collects AuditTrail data.
"""

from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from correctover import AuditTrail, make_guardrail_hook, EnvProtectionProvider

from .adapters.base import FrameworkAdapter, TestResult, Verdict
from .scenarios.base import TestScenario


class TestEngine:
    """Orchestrates self-healing test runs across framework adapters."""

    def __init__(self, adapters: Optional[List[FrameworkAdapter]] = None):
        self.adapters = adapters or []

    def register_adapter(self, adapter: FrameworkAdapter) -> None:
        self.adapters.append(adapter)

    def run_scenario(
        self,
        adapter: FrameworkAdapter,
        scenario: TestScenario,
    ) -> TestResult:
        """Run a single scenario on a single adapter."""
        agent = adapter.create_agent([], {})

        # Inject guardrail — use scenario-appropriate provider
        from correctover import EnvProtectionProvider, DenyAllGuardrailProvider, CompositeGuardrailProvider, ToolListGuardrailProvider
        from .adapters.base import FaultType

        if scenario.fault_type == FaultType.COMMAND_INJECTION:
            # MCP: deny dangerous_exec explicitly
            provider = ToolListGuardrailProvider(denied_tools={"dangerous_exec"})
        elif scenario.fault_type == FaultType.ENV_EXPOSURE:
            provider = EnvProtectionProvider()
        elif scenario.fault_type == FaultType.CONTRACT_BREAK:
            # Contract break: allow all (post-execution validation via CCSValidator)
            from correctover import AllowAllGuardrailProvider
            provider = AllowAllGuardrailProvider()
        else:
            provider = EnvProtectionProvider()

        agent = adapter.register_guardrail(agent, provider)

        # Use the trail from agent (created by register_guardrail)
        trail = getattr(agent, "_correctover_trail", AuditTrail())

        # Run scenario
        return scenario.run(adapter, agent, trail)

    def run_all(
        self,
        scenarios: Optional[List[TestScenario]] = None,
        frameworks: Optional[List[str]] = None,
        max_workers: int = 4,
    ) -> List[TestResult]:
        """Run all scenarios on all (or selected) adapters."""
        from .scenarios import (
            MCPSelfHealScenario,
            EnvProtectionScenario,
            ContractBreakScenario,
        )

        if scenarios is None:
            scenarios = [
                MCPSelfHealScenario(),
                EnvProtectionScenario(),
                ContractBreakScenario(),
            ]

        targets = self.adapters
        if frameworks:
            targets = [a for a in self.adapters if a.name in frameworks]

        results: List[TestResult] = []
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(self.run_scenario, adapter, scenario): (adapter.name, scenario.name)
                for adapter in targets
                for scenario in scenarios
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    fw, sc = futures[future]
                    results.append(TestResult(
                        framework=fw,
                        scenario=sc,
                        verdict=Verdict.FAIL,
                        errors=[str(e)],
                    ))

        return results

    def quick_smoke_test(self) -> List[TestResult]:
        """Run a minimal smoke test: EnvProtectionScenario only."""
        from .scenarios import EnvProtectionScenario
        return self.run_all(scenarios=[EnvProtectionScenario()])
