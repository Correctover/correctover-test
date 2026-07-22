"""
FrameworkAdapter ABC and shared data models.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import time


class FaultType(str, Enum):
    COMMAND_INJECTION = "command_injection"
    ENV_EXPOSURE = "env_exposure"
    CONTRACT_BREAK = "contract_break"


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"


@dataclass
class MetricSnapshot:
    """6-dimensional verification metrics per test run."""
    dimension: str          # integrity | authorization | auditability | latency | coverage | recovery
    value: float
    threshold: float        # pass threshold
    passed: bool
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dimension": self.dimension,
            "value": self.value,
            "threshold": self.threshold,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass
class TestResult:
    """Single scenario run result."""
    framework: str
    scenario: str
    verdict: Verdict
    metrics: List[MetricSnapshot] = field(default_factory=list)
    decisions_count: int = 0
    envelopes_count: int = 0
    integrity_verified: bool = False
    duration_ms: float = 0.0
    errors: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def self_heal_rate(self) -> float:
        """Fraction of metrics that passed."""
        if not self.metrics:
            return 0.0
        return sum(1 for m in self.metrics if m.passed) / len(self.metrics)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework": self.framework,
            "scenario": self.scenario,
            "verdict": self.verdict.value,
            "self_heal_rate": round(self.self_heal_rate, 4),
            "metrics": [m.to_dict() for m in self.metrics],
            "decisions_count": self.decisions_count,
            "envelopes_count": self.envelopes_count,
            "integrity_verified": self.integrity_verified,
            "duration_ms": round(self.duration_ms, 2),
            "errors": self.errors,
            "details": self.details,
        }


class FrameworkAdapter(ABC):
    """Abstract adapter for hooking correctover into an Agent framework."""

    name: str

    @abstractmethod
    def create_agent(self, tools: List[Any], config: Optional[Dict] = None) -> Any:
        """Create a native agent instance for this framework."""
        ...

    @abstractmethod
    def register_guardrail(self, agent: Any, provider: Any) -> Any:
        """
        Inject a correctover GuardrailProvider into the agent.
        Returns the modified agent or a wrapper.
        """
        ...

    @abstractmethod
    def run_task(self, agent: Any, task: str) -> Dict[str, Any]:
        """
        Execute a task through the agent.
        Returns {"output": str, "duration_ms": float, "error": Optional[str]}.
        """
        ...

    @abstractmethod
    def detect_missing_guardrail(self, agent: Any) -> List[Dict]:
        """
        Scan the agent for missing guardrail hooks.
        Returns list of findings, empty list = no issues.
        """
        ...

    @abstractmethod
    def inject_fault(self, agent: Any, fault_type: FaultType) -> Any:
        """
        Inject a fault into the agent's tool call pipeline.
        Returns the modified agent/context.
        """
        ...


class TestScenario(ABC):
    """Abstract test scenario that runs against an adapter+agent pair."""

    name: str
    description: str
    fault_type: FaultType

    @abstractmethod
    def setup(self, adapter: FrameworkAdapter, agent: Any) -> Any:
        """Prepare the agent for this scenario. Return modified agent/context."""
        ...

    @abstractmethod
    def execute(self, adapter: FrameworkAdapter, agent: Any) -> Dict[str, Any]:
        """Run the scenario. Return raw results dict."""
        ...

    @abstractmethod
    def verify(
        self,
        adapter: FrameworkAdapter,
        agent: Any,
        raw_result: Dict[str, Any],
        trail: Any,  # correctover.AuditTrail
    ) -> List[MetricSnapshot]:
        """Verify the 6-dimension metrics from AuditTrail."""
        ...

    def run(
        self,
        adapter: FrameworkAdapter,
        agent: Any,
        trail: Any,
    ) -> TestResult:
        """Orchestrate full scenario lifecycle."""
        t0 = time.time()
        errors = []

        try:
            agent = self.setup(adapter, agent)
        except Exception as e:
            errors.append(f"setup: {e}")
            return TestResult(
                framework=adapter.name,
                scenario=self.name,
                verdict=Verdict.FAIL,
                errors=errors,
                details={"phase": "setup"},
            )

        try:
            raw = self.execute(adapter, agent)
        except Exception as e:
            errors.append(f"execute: {e}")
            return TestResult(
                framework=adapter.name,
                scenario=self.name,
                verdict=Verdict.FAIL,
                errors=errors,
                details={"phase": "execute"},
            )

        try:
            metrics = self.verify(adapter, agent, raw, trail)
        except Exception as e:
            errors.append(f"verify: {e}")
            metrics = []

        duration_ms = (time.time() - t0) * 1000
        all_pass = all(m.passed for m in metrics) if metrics else False
        integrity_ok = trail.verify_all() if trail else False

        return TestResult(
            framework=adapter.name,
            scenario=self.name,
            verdict=Verdict.PASS if all_pass and not errors else Verdict.FAIL,
            metrics=metrics,
            decisions_count=trail.decision_count if trail else 0,
            envelopes_count=trail.envelope_count if trail else 0,
            integrity_verified=integrity_ok,
            duration_ms=duration_ms,
            errors=errors,
            details={"raw_output": raw.get("output", "")[:500]},
        )
