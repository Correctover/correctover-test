"""
LlamaIndex Framework Adapter.

LlamaIndex's workflow agents use event streams. For testing without an LLM,
we run guardrail checks directly against the provider by iterating tools.
"""

from typing import Any, Dict, List, Optional

from .base import FrameworkAdapter, FaultType


class LlamaIndexAdapter(FrameworkAdapter):
    name = "llamaindex"

    def create_agent(self, tools: List[Any], config: Optional[Dict] = None) -> Any:
        from llama_index.core.agent.workflow import FunctionAgent
        from llama_index.core.llms import MockLLM

        cfg = config or {}
        llm = cfg.get("llm")
        if llm is None:
            llm = MockLLM()

        return FunctionAgent(
            name=config.get("name", "test-agent") if config else "test-agent",
            description=config.get("description", "Test agent for correctover validation") if config else "Test agent for correctover validation",
            system_prompt=config.get("system_prompt", "You are a test agent. Use tools to complete tasks.") if config else "You are a test agent. Use tools to complete tasks.",
            tools=tools,
            llm=llm,
            **(config or {}),
        )

    def register_guardrail(self, agent: Any, provider: Any) -> Any:
        """
        Store guardrail context on the agent for direct-check mode.
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
            tools = getattr(agent, "tools", None)
            if tools:
                for tool_obj in tools:
                    # Get tool name from various LlamaIndex tool structures
                    tname = None
                    if hasattr(tool_obj, "metadata"):
                        meta = tool_obj.metadata
                        tname = getattr(meta, "name", None) if hasattr(meta, "name") else str(meta)
                    if tname is None:
                        fn = getattr(tool_obj, "fn", None)
                        tname = getattr(fn, "__name__", str(tool_obj)) if fn else str(tool_obj)

                    tool_args = {}
                    if "rm -rf" in task or "dangerous_exec" in str(tname):
                        tool_args["command"] = "rm -rf /"
                    elif "TEST_API_KEY" in task or "read_env" in str(tname):
                        tool_args["key"] = "TEST_API_KEY"
                    else:
                        tool_args["query"] = task

                    tc = ToolCallContext(
                        tool_name=tname,
                        tool_args=tool_args,
                        agent_id=getattr(agent, "name", "llamaindex-agent"),
                        metadata={"framework": "llamaindex", "mode": "direct-check"},
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
                "agent": agent.name,
                "message": f"Agent '{agent.name}' has no correctover guardrail injected",
                "remediation": "Call adapter.register_guardrail(agent, provider)",
            })

        tools = getattr(agent, "tools", None)
        if tools is None or (isinstance(tools, list) and len(tools) == 0):
            findings.append({
                "severity": "INFO",
                "pattern": "LLAMA-NO-TOOLS-001",
                "agent": agent.name,
                "message": "Agent has no tools configured",
                "remediation": "Add tools to the agent for guardrail testing",
            })

        return findings

    def inject_fault(self, agent: Any, fault_type: FaultType) -> Any:
        from llama_index.core.tools import FunctionTool

        if fault_type == FaultType.COMMAND_INJECTION:

            def dangerous_exec(command: str) -> str:
                return f"executed: {command}"

            tool = FunctionTool.from_defaults(
                fn=dangerous_exec,
                name="dangerous_exec",
                description="Execute a shell command (DANGEROUS)",
            )
            if agent.tools is None:
                agent.tools = []
            agent.tools.append(tool)

        elif fault_type == FaultType.ENV_EXPOSURE:

            def read_env(key: str) -> str:
                import os
                return os.environ.get(key, "NOT_SET")

            tool = FunctionTool.from_defaults(
                fn=read_env,
                name="read_env",
                description="Read an environment variable",
            )
            if agent.tools is None:
                agent.tools = []
            agent.tools.append(tool)

        elif fault_type == FaultType.CONTRACT_BREAK:

            def unreliable_output(query: str) -> dict:
                return {"partial": query, "_incomplete": True}

            tool = FunctionTool.from_defaults(
                fn=unreliable_output,
                name="unreliable_output",
                description="Returns output that may break contract validation",
            )
            if agent.tools is None:
                agent.tools = []
            agent.tools.append(tool)

        return agent
