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
from .core.license import get_validator, LicenseExceededError
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

VERSION = "0.4.0"

# Free tier: show only first N risks, hide the rest behind paywall
FREE_RISK_PREVIEW = 2


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

    # ── License check — per-check billing ──
    # Count how many checks this run will consume
    check_count = len(adapters) * len(scenarios)

    try:
        from .core.license import LicenseValidator
        license_key = LicenseValidator.get_license_from_env()
        validator = get_validator()
        if license_key:
            validator.set_license_key(license_key)

        # Pre-check: can user afford this many checks?
        status = validator.check_license()
        is_pro = status["tier"] == "pro"

        if not is_pro:
            remaining = status["checks_remaining"]
            if remaining < check_count:
                # Not enough — show what they can run
                click.echo(
                    f"🚫 Not enough checks remaining ({remaining}/{validator.FREE_LIMIT_PER_MONTH} this month).\n"
                    f"   This run needs {check_count} checks ({len(adapters)} frameworks × {len(scenarios)} scenarios).\n\n"
                    f"   Options:\n"
                    f"   1. Upgrade to Pro for unlimited: https://correctover.com/checkout\n"
                    f"   2. Run fewer scenarios: correctover-test --framework crewai --scenario env_protection\n"
                    f"   3. Set license: export CORRECTOVER_LICENSE_KEY=<your-key>\n",
                    err=True,
                )
                sys.exit(1)

        # Record consumption
        status = validator.record_call(count=check_count)

        if not is_pro:
            click.echo(
                f"📊 Free tier: {status['checks_remaining']}/{validator.FREE_LIMIT_PER_MONTH} checks remaining "
                f"(−{check_count} this run)",
                err=True,
            )
    except LicenseExceededError as e:
        click.echo(str(e), err=True)
        sys.exit(1)

    # Run
    click.echo(
        f"🔍 Auditing {len(adapters)} framework(s) × {len(scenarios)} scenario(s) "
        f"({check_count} checks)...",
        err=True,
    )
    engine = TestEngine(adapters)
    results = engine.run_all(scenarios=scenarios)

    # Upload to cloud (Pro only)
    if cloud and is_pro:
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

    # ── Output: free tier shows limited results, Pro shows everything ──
    # Count risks (FAIL results)
    risks = [r for r in results if r.verdict.value == "FAIL"]
    passed = [r for r in results if r.verdict.value == "PASS"]

    if not is_pro and len(risks) > FREE_RISK_PREVIEW:
        # Free tier: show first N risks, hide the rest
        _print_free_output(risks, passed, check_count, status, no_cta)
    else:
        # Pro tier: full output
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


def _print_free_output(risks, passed, check_count, status, no_cta):
    """Print limited results for free tier users — show first N risks, hide rest."""
    click.echo("")
    click.echo(f"{'━'*55}")

    shown = risks[:FREE_RISK_PREVIEW]
    hidden = len(risks) - FREE_RISK_PREVIEW

    if risks:
        click.echo(f"⚠️  {len(risks)} RISK(S) FOUND:\n")
        for i, r in enumerate(shown, 1):
            severity = "🔴 HIGH" if "FAIL" in r.verdict.value else "🟡 MEDIUM"
            click.echo(f"  {i}. [{severity}] {r.framework}: {r.scenario}")
            click.echo(f"     → {r.summary[:80] if hasattr(r, 'summary') else 'Risk detected in agent configuration'}")
            click.echo(f"     🔒 Fix recommendation locked — Upgrade to Pro\n")

        if hidden > 0:
            click.echo(f"  {'─'*51}")
            click.echo(f"  🔒 {hidden} additional risk(s) detected but hidden.")
            click.echo(f"     These may include critical vulnerabilities.")
            click.echo("")
    else:
        click.echo("✅ No risks found in the checked scenarios.\n")

    if passed:
        click.echo(f"  ✅ {len(passed)} scenario(s) passed.")

    click.echo(f"{'━'*55}")

    # CTA — right in the middle of the anxiety
    if not no_cta:
        click.echo(
            f"\n{'━'*55}\n"
            f"🛡️  UPGRADE TO PRO TO UNLOCK:\n"
            f"   • All {len(risks)} risk details + fix recommendations\n"
            f"   • Auto-heal (84.1% issues resolved automatically)\n"
            f"   • Full HTML/PDF audit reports\n"
            f"   • Unlimited checks (you've used {status['checks_used']}/30 this month)\n"
            f"{'━'*55}\n"
            f"   → https://correctover.com/checkout\n"
            f"   → export CORRECTOVER_LICENSE_KEY=<your-key>\n"
            f"{'━'*55}"
        )


if __name__ == "__main__":
    main()
