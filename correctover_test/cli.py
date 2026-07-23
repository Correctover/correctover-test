"""
correctover-test CLI — freemium hook model.

Free: unlimited scanning, see all risks
Pro: fix recommendations, auto-heal, reports, history

The hook: users see ALL their problems for free.
The paywall: solutions are locked.
"""

import json
import sys
import urllib.request
from typing import Optional

import click

from .core.engine import TestEngine
from .core.reporter import Reporter
from .core.license import get_validator
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

VERSION = "0.5.0"


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
    help="Correctover Cloud endpoint URL",
)
@click.option(
    "--no-cta",
    is_flag=True,
    help="Suppress upgrade CTA",
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
      correctover-test --all            # Full audit
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
                click.echo(f"❌ Unknown framework: {fw}. Available: {list(ADAPTER_REGISTRY.keys())}", err=True)
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
                click.echo(f"❌ Unknown scenario: {sc}. Available: {list(SCENARIO_REGISTRY.keys())}", err=True)
                sys.exit(1)
            scenarios.append(SCENARIO_REGISTRY[sc]())

    # ── License check — freemium model ──
    from .core.license import LicenseValidator
    license_key = LicenseValidator.get_license_from_env()
    validator = get_validator()
    if license_key:
        validator.set_license_key(license_key)

    status = validator.check_license()
    is_pro = status["tier"] == "pro"

    # Run — always allowed (free tier can scan unlimited)
    check_count = len(adapters) * len(scenarios)
    click.echo(f"🔍 Auditing {len(adapters)} framework(s) × {len(scenarios)} scenario(s)...\n", err=True)

    engine = TestEngine(adapters)
    results = engine.run_all(scenarios=scenarios)

    # Count risks
    risks = [r for r in results if r.verdict.value == "FAIL"]
    passed = [r for r in results if r.verdict.value == "PASS"]
    risk_count = len(risks)

    # Record scan (always — this is the hook, data collection)
    validator.record_scan(risks_found=risk_count)

    # Cloud upload (Pro only)
    if cloud and is_pro:
        try:
            payload = json.dumps({
                "source": "correctover-test",
                "version": VERSION,
                "results": [r.to_dict() for r in results],
            }).encode("utf-8")
            req = urllib.request.Request(cloud, data=payload, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                click.echo(f"☁️  Uploaded to Correctover Cloud\n", err=True)
        except Exception as e:
            click.echo(f"⚠️  Cloud upload failed: {e}\n", err=True)

    # ── Output: show ALL risks (hook), lock fixes (paywall) ──
    if is_pro:
        # Pro: full output with fixes, reports, everything
        if output:
            if output.endswith(".md"):
                content = Reporter.to_markdown(results)
            elif output.endswith(".html"):
                content = Reporter.to_html(results)
            else:
                content = Reporter.to_json(results)
            with open(output, "w") as f:
                f.write(content)
            click.echo(f"📄 Report written to {output}\n", err=True)
        else:
            Reporter.to_terminal(results, show_cta=not no_cta)
    else:
        # Free: show all risks (the hook), lock fixes (the paywall)
        _print_freemium_output(risks, passed, risk_count, status, no_cta)

    sys.exit(0 if risk_count == 0 else 1)


def _print_freemium_output(risks, passed, risk_count, status, no_cta):
    """Print all risks for free, but lock fix recommendations."""

    click.echo(f"{'━'*55}")

    if risk_count > 0:
        click.echo(f"⚠️  {risk_count} RISK(S) FOUND:\n")

        for i, r in enumerate(risks, 1):
            severity = "🔴 HIGH" if "FAIL" in r.verdict.value else "🟡 MEDIUM"
            click.echo(f"  {i}. [{severity}] {r.framework}: {r.scenario}")
            if hasattr(r, 'summary'):
                click.echo(f"     → {r.summary[:80]}")

            # Show fix for first N risks (teaser), lock the rest
            if i <= status["fix_preview"]:
                if hasattr(r, 'fix') and r.fix:
                    click.echo(f"     ✅ FIX: {r.fix[:80]}\n")
                else:
                    click.echo(f"     ✅ Fix available in Pro\n")
            else:
                click.echo(f"     🔒 Fix recommendation locked — Upgrade to Pro\n")
    else:
        click.echo("✅ No risks found in this scan.")

    if passed:
        click.echo(f"\n  ✅ {len(passed)} scenario(s) passed.")

    click.echo(f"{'━'*55}")

    # ── The hook: CTA right here, at peak anxiety ──
    if not no_cta:
        if risk_count > 0:
            hidden_fixes = max(0, risk_count - status["fix_preview"])
            if hidden_fixes > 0:
                cta = status.get("fix_cta") or validator.get_fix_cta(risk_count, hidden_fixes) if 'validator' in dir() else ""
                click.echo(
                    f"\n{'━'*55}\n"
                    f"🔒 {hidden_fixes} fix recommendation(s) locked.\n"
                    f"   You have {risk_count} risk(s) but can only see {status['fix_preview']} fix(es).\n\n"
                    f"🛡️  Upgrade to Pro to unlock:\n"
                    f"   ✓ Fix recommendations for all {risk_count} risk(s)\n"
                    f"   ✓ Auto-heal (84.1% issues resolved automatically)\n"
                    f"   ✓ HTML/PDF audit reports\n"
                    f"   ✓ Scan history & tracking\n"
                    f"{'━'*55}\n"
                    f"   → https://correctover.com/checkout\n"
                    f"   → export CORRECTOVER_LICENSE_KEY=<your-key>\n"
                    f"{'━'*55}"
                )
            else:
                click.echo(
                    f"\n{'━'*55}\n"
                    f"🛡️  Stay protected with Pro:\n"
                    f"   ✓ Auto-heal when risks appear\n"
                    f"   ✓ HTML/PDF audit reports\n"
                    f"   ✓ Scan history & continuous monitoring\n"
                    f"{'━'*55}\n"
                    f"   → https://correctover.com/checkout\n"
                    f"{'━'*55}"
                )
        else:
            click.echo(
                f"\n{'━'*55}\n"
                f"✅ No risks found right now.\n\n"
                f"🛡️  Stay protected with Pro:\n"
                f"   ✓ Continuous monitoring (auto-scan on changes)\n"
                f"   ✓ Auto-heal when risks appear\n"
                f"   ✓ Compliance reports (OAuth 2.1, CCS v1.0)\n"
                f"{'━'*55}\n"
                f"   → https://correctover.com/checkout\n"
                f"{'━'*55}"
            )


if __name__ == "__main__":
    main()
