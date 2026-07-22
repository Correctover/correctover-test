"""
TestScenario base class — re-exports from adapters.base for cleaner imports.
"""
from ..adapters.base import TestScenario, FaultType, Verdict, MetricSnapshot, TestResult

__all__ = ["TestScenario", "FaultType", "Verdict", "MetricSnapshot", "TestResult"]
