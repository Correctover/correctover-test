"""
CrewAI Framework Adapter.

Hooks into CrewAI's global before_tool_call / after_tool_call decorator system
and the agent.guardrail attribute for guardrail detection.

For testing without an LLM, run_task simulates tool call guardrail checks
directly against the registered provider, bypassing actual LLM calls.
"""

from typing import Any, Dict, List, Optional

from .base import FrameworkAdapter, FaultType


class CrewAIAdapter(FrameworkAdapter):
    name = "crewai"

    def create_agent(self, tools: List[Any], config: Optional[Dict] = None) -> Any:
        from crewai import Agent

        return Agent(
            role=config.get("role", "test-agent") if config else "test-agent",
            goal=config.get("goal", "Execute tools safely with guardrail protection") if config else "Execute tools safely with guardrail protection",
            backstory=config.get("backstory", "A test agent for correctover self-healing validation") if config else "A test agent for correctover self-healing validation",
            tools=tools,
            verbose=False,
            allow_delegation=False,
        )

    def register_guardrail(self, agent: Any, provider: Any) -> Any:
        """
        Inject guardrail via CrewAI's global before_tool_call hook system.
        Wraps the provider into a callable that matches CrewAI's hook signature.
        """
        from crewai.hooks.tool_hooks import register_before_tool_call_hook
        from correctover import GuardrailContext, ToolCallContext, AuditTrail

        trail = AuditTrail()
        ctx = GuardrailContext(provider=provider, trail=trail)

        def before_hook(*, tool=None, tool_input=None, agent_role=None, agent=None, **kwargs):
            tool_name = getattr(tool, "name", str(tool))
            tool_args = tool_input if isinstance(tool_input, dict) else {}
            agent_id = agent_role or "unknown"

            tc = ToolCallContext(
                tool_name=tool_name,
                tool_args=tool_args,
                agent_id=agent_id,
                metadata={"framework": "crewai"},
            )
            decision = ctx.authorize(tc)
            if not decision.authorized:
                raise PermissionError(
                    f"Tool '{tool_name}' denied by correctover guardrail"
                )
            return tool_input

        register_before_tool_call_hook(before_hook)

        agent._correctover_trail = trail
        agent._correctover_context = ctx

        return agent

    def run_task(self, agent: Any, task: str) -> Dict[str, Any]:
        """
        Simulate a tool call against the guardrail directly — no LLM required.
        Extracts tool name from the task string and tests the guardrail provider.
        """
        import time
        from correctover import ToolCallContext

        t0 = time.time()
        error = None
        output = ""

        trail = getattr(agent, "_correctover_trail", None)
        ctx = getattr(agent, "_correctover_context", None)

        # Parse tool name from task: "Use X to do Y" -> X
        tool_name = "unknown_tool"
        task_lower = task.lower()
        for word in task.split():
            if word in ["dangerous_exec", "read_env", "unreliable_output"]:
                tool_name = word
                break
        # Fallback: find tool from agent.tools
        if tool_name == "unknown_tool" and hasattr(agent, "tools"):
            for t in agent.tools:
                tname = getattr(t, "name", str(t))
                if tname.lower() in task_lower:
                    tool_name = tname
                    break

        # Extract command arg from task if relevant
        tool_args = {}
        if "rm -rf" in task:
            tool_args["command"] = "rm -rf /"
        elif "TEST_API_KEY" in task:
            tool_args["key"] = "TEST_API_KEY"
        else:
            tool_args["query"] = task

        # Direct guardrail check
        if ctx and ctx.provider:
            tc = ToolCallContext(
                tool_name=tool_name,
                tool_args=tool_args,
                agent_id=getattr(agent, "role", "unknown"),
                metadata={"framework": "crewai", "mode": "direct-check"},
            )
            try:
                decision = ctx.authorize(tc)
                ctx.after_tool_call(decision, {"simulated": True}, time.time())
                if decision.authorized:
                    output = f"Tool '{tool_name}' was authorized"
                else:
                    error = f"Tool '{tool_name}' denied by guardrail: {decision.claims.get('reason', 'unauthorized')}"
                    output = f"[BLOCKED] {error}"
            except Exception as e:
                error = str(e)
                output = f"[ERROR] {e}"
        else:
            # Fallback: try actual agent kickoff (needs LLM)
            try:
                result = agent.kickoff(messages=task)
                output = str(result) if result else ""
            except Exception as e:
                error = str(e)
                output = ""

        return {
            "output": output,
            "duration_ms": (time.time() - t0) * 1000,
            "error": error,
        }

    def detect_missing_guardrail(self, agent: Any) -> List[Dict]:
        findings = []

        if getattr(agent, "guardrail", None) is None:
            findings.append({
                "severity": "WARNING",
                "pattern": "CREWAI-GUARDRAIL-MISS-001",
                "agent": agent.role,
                "message": f"Agent '{agent.role}' has no CrewAI guardrail set",
                "remediation": "Set agent.guardrail or inject correctover via register_guardrail()",
            })

        if not hasattr(agent, "_correctover_trail"):
            findings.append({
                "severity": "CRITICAL",
                "pattern": "AS-GUARDRAIL-MISS-001",
                "agent": agent.role,
                "message": f"Agent '{agent.role}' has no correctover guardrail injected",
                "remediation": "Call adapter.register_guardrail(agent, provider)",
            })

        from crewai.hooks.tool_hooks import get_before_tool_call_hooks
        if not get_before_tool_call_hooks():
            findings.append({
                "severity": "HIGH",
                "pattern": "CREWAI-HOOK-MISS-001",
                "agent": agent.role,
                "message": "No global before_tool_call hooks registered",
                "remediation": "Register a before_tool_call hook with correctover provider",
            })

        return findings

    def inject_fault(self, agent: Any, fault_type: FaultType) -> Any:
        from crewai.tools import tool

        if fault_type == FaultType.COMMAND_INJECTION:

            @tool("dangerous_exec")
            def dangerous_exec(command: str) -> str:
                """Execute a shell command. DANGEROUS — should be blocked by guardrail."""
                return f"executed: {command}"

            agent.tools.append(dangerous_exec)

        elif fault_type == FaultType.ENV_EXPOSURE:

            @tool("read_env")
            def read_env(key: str) -> str:
                """Read an environment variable. Should be blocked by guardrail."""
                import os
                return os.environ.get(key, "NOT_SET")

            agent.tools.append(read_env)

        elif fault_type == FaultType.CONTRACT_BREAK:

            @tool("unreliable_output")
            def unreliable_output(query: str) -> dict:
                """Return incomplete output missing required fields — contract break test."""
                return {"partial": query, "_incomplete": True}

            agent.tools.append(unreliable_output)

        return agent
