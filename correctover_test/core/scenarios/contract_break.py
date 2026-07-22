"""
Contract Break Scenario — validates that CCSValidator detects
output contract violations and the system can recover.
"""

from typing import Any, Dict, List

from .base import TestScenario, FaultType, MetricSnapshot
from ..adapters.base import FrameworkAdapter


class ContractBreakScenario(TestScenario):
    name = "contract_break"
    description = "Validate contract validation detects missing required fields and triggers recovery"
    fault_type = FaultType.CONTRACT_BREAK

    def setup(self, adapter: FrameworkAdapter, agent: Any) -> Any:
        """Inject unreliable_output tool that returns broken contracts."""
        return adapter.inject_fault(agent, self.fault_type)

    def execute(self, adapter: FrameworkAdapter, agent: Any) -> Dict[str, Any]:
        """Use the unreliable tool — output should be flagged by CCSValidator."""
        result = adapter.run_task(
            agent,
            "Use unreliable_output to process query 'test_contract_validation'"
        )
        return result

    def verify(
        self,
        adapter: FrameworkAdapter,
        agent: Any,
        raw_result: Dict[str, Any],
        trail: Any,
    ) -> List[MetricSnapshot]:
        from correctover import CCSValidator

        metrics = []

        # 1. Integrity — verify AuditTrail
        integrity_ok = trail.verify_all() if trail else False
        metrics.append(MetricSnapshot(
            dimension="integrity",
            value=1.0 if integrity_ok else 0.0,
            threshold=1.0,
            passed=integrity_ok,
            detail="Trail hash verification" if integrity_ok else "Hash verification failed",
        ))

        # 2. Authorization — contract break tools should still be authorized
        # (contract validation is post-execution, not pre-execution blocking)
        decisions = trail.get_all_decisions() if trail else []
        authorized = sum(1 for d in decisions if d.authorized)
        # We expect the tool to be authorized (contract check is post-hoc)
        auth_pass = len(decisions) > 0
        metrics.append(MetricSnapshot(
            dimension="authorization",
            value=float(authorized),
            threshold=0.0,
            passed=auth_pass,
            detail=f"{authorized}/{len(decisions)} decisions authorized — "
            f"contract validation is post-execution" if decisions else "No decisions recorded",
        ))

        # 3. CCSValidator contract check on the output
        validator = CCSValidator(
            required_fields=["result", "status"],
            supported_fields=["partial", "detail", "error"],
        )
        output = raw_result.get("output", "")

        # Try to parse output as dict for validation
        import json
        try:
            output_dict = json.loads(output) if isinstance(output, str) else output
        except (json.JSONDecodeError, TypeError):
            output_dict = {"raw": output}

        validation = validator.validate(output_dict)
        contract_pass = not validation.is_valid  # Expected: contract SHOULD be broken

        metrics.append(MetricSnapshot(
            dimension="auditability",
            value=float(len(validation.errors)),
            threshold=1.0,
            passed=contract_pass,
            detail=f"CCSValidator found {len(validation.errors)} errors, "
                   f"{len(validation.warnings)} warnings: {validation.errors}"
            if validation.errors else "CCSValidator found no issues — contract was intact",
        ))

        # 4. Latency
        envelopes = trail.get_all_envelopes() if trail else []
        avg_latency = sum(e.duration_ms for e in envelopes) / max(len(envelopes), 1) if envelopes else 0.0
        latency_pass = avg_latency < 100.0 if envelopes else True
        metrics.append(MetricSnapshot(
            dimension="latency",
            value=round(avg_latency, 2),
            threshold=100.0,
            passed=latency_pass,
            detail=f"Avg {avg_latency:.2f}ms" if envelopes else "N/A",
        ))

        # 5. Coverage
        coverage_pass = (trail.envelope_count if trail else 0) > 0
        metrics.append(MetricSnapshot(
            dimension="coverage",
            value=float(trail.envelope_count if trail else 0),
            threshold=1.0,
            passed=coverage_pass,
            detail=f"{trail.envelope_count if trail else 0} tool calls tracked",
        ))

        # 6. Recovery — contract violation should be detectable and recoverable
        # Recovery = CCSValidator caught the issue + system didn't crash
        error = raw_result.get("error") or ""
        system_ok = "crash" not in error.lower() and "traceback" not in error.lower()
        recovery_pass = contract_pass and system_ok

        metrics.append(MetricSnapshot(
            dimension="recovery",
            value=1.0 if recovery_pass else 0.0,
            threshold=1.0,
            passed=recovery_pass,
            detail=f"Contract violation detected, system stable: {recovery_pass}"
            if recovery_pass else
            f"Recovery failed — contract_pass={contract_pass}, system_ok={system_ok}",
        ))

        return metrics
