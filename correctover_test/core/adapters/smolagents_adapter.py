"""
Smolagents Framework Adapter.

Smolagents lacks before_tool_call hooks. For testing without an LLM,
we run guardrail checks directly against the provider by simulating
ToolCallContext entries for each tool in the agent.
"""

from typing import Any, Dict, List, Optional

from .base import FrameworkAdapter, FaultType


class SmolagentsAdapter(FrameworkAdapter):
    name = "smolagents"

    def create_agent(self, tools: List[Any], config: Optional[Dict] = None) -> Any:
        from smolagents import ToolCallingAgent

        # Use a mock model to avoid real API calls during testing
        try:
            from smolagents.models import LiteLLMModel
            model = LiteLLMModel(model_id="deepseek/deepseek-chat", api_key="sk-test")
        except Exception:
            model = None

        return ToolCallingAgent(
            tools=tools,
            model=model,
            **(config or {}),
        )

    def register_guardrail(self, agent: Any, provider: Any) -> Any:
        """
        Register guardrail context on the agent for direct-check mode.
        Smolagents has no native before_tool_call hook, so we store the
        provider on the agent for run_task to use directly.
        """
        from correctover import GuardrailContext, AuditTrail

        trail = AuditTrail()
        ctx = GuardrailContext(provider=provider, trail=trail)

        agent._correctover_trail = trail
        agent._correctover_context = ctx

        return agent

    def run_task(self, agent: Any, task: str) -> Dict[str, Any]:
        """
        Direct guardrail check — no LLM required.
        Iterates over agent tools and tests each against the guardrail provider.
        """
        import time
        from correctover import ToolCallContext

        t0 = time.time()
        error = None
        output_parts = []

        trail = getattr(agent, "_correctover_trail", None)
        ctx = getattr(agent, "_correctover_context", None)

        if ctx and ctx.provider:
            tools = getattr(agent, "tools", {})
            if tools:
                # Test each tool against the guardrail
                for tname, tool_obj in (tools.items() if isinstance(tools, dict) else [(getattr(t, "name", str(t)), t) for t in tools]):
                    tool_args = {}
                    if "rm -rf" in task or "dangerous_exec" in tname:
                        tool_args["command"] = "rm -rf /"
                    elif "TEST_API_KEY" in task or "read_env" in tname:
                        tool_args["key"] = "TEST_API_KEY"
                    else:
                        tool_args["query"] = task

                    tc = ToolCallContext(
                        tool_name=tname,
                        tool_args=tool_args,
                        agent_id=getattr(agent, "name", "smolagents-agent"),
                        metadata={"framework": "smolagents", "mode": "direct-check"},
                    )
                    try:
                        decision = ctx.authorize(tc)
                        ctx.after_tool_call(decision, {"simulated": True}, time.time())
                        if decision.authorized:
                            output_parts.append(f"Tool '{tname}' authorized")
                        else:
                            msg = f"Tool '{tname}' DENIED: {decision.claims.get('reason', 'unauthorized')}"
                            output_parts.append(msg)
                            error = msg
                    except Exception as e:
                        output_parts.append(f"[ERROR] {e}")
                        error = str(e)
            else:
                output_parts.append("No tools to test")
        else:
            output_parts.append("No guardrail context — skipping")

        output = "\n".join(output_parts) if output_parts else str(task)

        return {
            "output": output,
            "duration_ms": (time.time() - t0) * 1000,
            "error": error,
        }

    def detect_missing_guardrail(self, agent: Any) -> List[Dict]:
        findings = []

        if not hasattr(agent, "_correctover_trail"):
            findings.append({
                "severity": "CRITICAL",
                "pattern": "AS-GUARDRAIL-MISS-001",
                "agent": getattr(agent, "name", "unknown"),
                "message": "Agent has no correctover guardrail injected",
                "remediation": "Call adapter.register_guardrail(agent, provider)",
            })

        checks = getattr(agent, "final_answer_checks", None)
        if checks is None or (isinstance(checks, list) and len(checks) == 0):
            findings.append({
                "severity": "WARNING",
                "pattern": "SMOL-FINAL-CHECK-MISS-001",
                "agent": getattr(agent, "name", "unknown"),
                "message": "No final_answer_checks configured",
                "remediation": "Set agent.final_answer_checks with validation functions",
            })

        if hasattr(agent, "authorized_imports"):
            imports = getattr(agent, "authorized_imports", [])
            if "os" in imports or "subprocess" in imports:
                findings.append({
                    "severity": "HIGH",
                    "pattern": "SMOL-IMPORT-RISK-001",
                    "agent": getattr(agent, "name", "unknown"),
                    "message": "Dangerous imports allowed: os, subprocess",
                    "remediation": "Remove os/subprocess from authorized_imports",
                })

        return findings

    def inject_fault(self, agent: Any, fault_type: FaultType) -> Any:
        from smolagents import tool

        if fault_type == FaultType.COMMAND_INJECTION:

            @tool
            def dangerous_exec(command: str) -> str:
                """Execute a shell command. DANGEROUS — should be blocked by guardrail.

                Args:
                    command: Shell command to execute.
                """
                import subprocess
                return subprocess.getoutput(command)

            if agent.tools is None:
                agent.tools = {}
            agent.tools["dangerous_exec"] = dangerous_exec

        elif fault_type == FaultType.ENV_EXPOSURE:

            @tool
            def read_env(key: str) -> str:
                """Read an environment variable. Should be blocked by guardrail.

                Args:
                    key: Environment variable name to read.
                """
                import os
                return os.environ.get(key, "NOT_SET")

            if agent.tools is None:
                agent.tools = {}
            agent.tools["read_env"] = read_env

        elif fault_type == FaultType.CONTRACT_BREAK:

            @tool
            def unreliable_output(query: str) -> dict:
                """Return incomplete output missing required fields — contract break test.

                Args:
                    query: Input query to process.
                """
                return {"partial": query, "_incomplete": True}

            if agent.tools is None:
                agent.tools = {}
            agent.tools["unreliable_output"] = unreliable_output

        return agent
