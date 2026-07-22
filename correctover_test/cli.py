"""
correctover-test CLI — self-healing test agent entry point.

Usage:
    correctover-test --quick              # 5-second smoke test
    correctover-test --framework crewai   # Single framework
    correctover-test --all --html         # Full audit, HTML report
    correctover-test --quick --cloud      # Upload results to Correctover Cloud
"""

import json
import sys
import urllib.request
from typing import Optional

import click

from .core.engine import TestEngine
from .core.reporter import Reporter
from .core.adapters import CrewAIAdapter, SmolagentsAdapter, LlamaIndexAdapter
from .core.scenarios import MCPSelfHealScenario, EnvProtectionScenario, ContractBreakScenario


ADAPTER_REGISTRY = {
    "crewai": CrewAIAdapter,
    "smolagents": SmolagentsAdapter,
    "llamaindex": LlamaIndexAdapter,
}

SCENARIO_REGISTRY = {
    "mcp_self_heal": MCPSelfHealScenario,
    "env_protection": EnvProtectionScenario,
    "contract_break": ContractBreakScenario,
}

VERSION = "0.2.0"


@click.command()
@click.option(
    "--framework", "-f",
    default="all",
    help="Target framework: crewai, smolagents, llamaindex, or all",
)
@click.option(
    "--scenario", "-s",
    default="all",
    help="Test scenario: mcp_self_heal, env_protection, contract_break, or all",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output file path (.json / .md / .html based on extension)",
)
@click.option(
    "--quick", "-q",
    is_flag=True,
    help="5-second smoke test: env_protection on all frameworks",
)
@click.option(
    "--all", "run_all",
    is_flag=True,
    help="Full audit: all scenarios on all frameworks",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["terminal", "json", "markdown", "html"]),
    default="terminal",
    help="Output format (default: terminal)",
)
@click.option(
    "--cloud",
    default=None,
    help="Correctover Cloud endpoint URL (e.g. https://cloud.correctover.com/api/v1/audit)",
)
@click.option(
    "--no-cta",
    is_flag=True,
    help="Suppress the 'Fix this' CTA in output",
)
@click.version_option(version=VERSION, prog_name="correctover-test")
def main(
    framework: str,
    scenario: str,
    output: Optional[str],
    quick: bool,
    run_all: bool,
    output_format: str,
    cloud: Optional[str],
    no_cta: bool,
):
    """🔒 Correctover Agent Security Audit

    Tests your AI agents for guardrail gaps, command injection,
    environment variable leaks, and contract violations.

    \b
    Quick start:
      correctover-test --quick          # 5-second audit
      correctover-test --all --html     # Full report

    \b
    Correctover Cloud:
      correctover-test --quick --cloud https://cloud.correctover.com/api/v1/audit
    """

    # Resolve frameworks
    if quick:
        framework = "all"
        scenario = "env_protection"
    elif run_all:
        framework = "all"
        scenario = "all"

    if framework == "all":
        adapters = [cls() for cls in ADAPTER_REGISTRY.values()]
    else:
        fws = [f.strip() for f in framework.split(",")]
        adapters = []
        for fw in fws:
            if fw not in ADAPTER_REGISTRY:
                click.echo(
                    f"❌ Unknown framework: {fw}. Available: {list(ADAPTER_REGISTRY.keys())}",
                    err=True,
                )
                sys.exit(1)
            adapters.append(ADAPTER_REGISTRY[fw]())

    # Resolve scenarios
    if scenario == "all":
        scenarios = [cls() for cls in SCENARIO_REGISTRY.values()]
    else:
        scs = [s.strip() for s in scenario.split(",")]
        scenarios = []
        for sc in scs:
            if sc not in SCENARIO_REGISTRY:
                click.echo(
                    f"❌ Unknown scenario: {sc}. Available: {list(SCENARIO_REGISTRY.keys())}",
                    err=True,
                )
                sys.exit(1)
            scenarios.append(SCENARIO_REGISTRY[sc]())

    # Run
    click.echo(
        f"🔍 Auditing {len(adapters)} framework(s) × {len(scenarios)} scenario(s)...",
        err=True,
    )
    engine = TestEngine(adapters)
    results = engine.run_all(scenarios=scenarios)

    # Upload to cloud
    if cloud:
        try:
            payload = json.dumps({
                "source": "correctover-test",
                "version": VERSION,
                "results": [r.to_dict() for r in results],
            }).encode("utf-8")
            req = urllib.request.Request(
                cloud,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                cloud_resp = json.loads(resp.read())
                click.echo(
                    f"☁️  Uploaded to Correctover Cloud: {cloud_resp.get('dashboard_url', cloud)}",
                    err=True,
                )
        except Exception as e:
            click.echo(f"⚠️  Cloud upload failed: {e}", err=True)

    # Output
    if output:
        if output.endswith(".md"):
            content = Reporter.to_markdown(results)
        elif output.endswith(".html"):
            content = Reporter.to_html(results)
        else:
            content = Reporter.to_json(results)
        with open(output, "w") as f:
            f.write(content)
        click.echo(f"📄 Report written to {output}", err=True)
    else:
        if output_format == "json":
            click.echo(Reporter.to_json(results))
        elif output_format == "markdown":
            click.echo(Reporter.to_markdown(results))
        elif output_format == "html":
            click.echo(Reporter.to_html(results))
        else:
            Reporter.to_terminal(results, show_cta=not no_cta)

    # Exit code
    total = len(results)
    failed = sum(1 for r in results if r.verdict.value == "FAIL")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
