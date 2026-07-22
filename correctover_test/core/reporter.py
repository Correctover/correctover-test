"""
Reporter — renders TestResults with actionable insights and CTAs.
"""

import json
import sys
from typing import Dict, List, Optional, TextIO

from .adapters.base import TestResult


class Reporter:
    """Multi-format test report generator with security insights."""

    CTA_URL = "https://correctover.com"
    CTA_TEXT = "Fix this in 2 minutes → correctover.com"

    @staticmethod
    def to_json(results: List[TestResult], indent: int = 2) -> str:
        return json.dumps(
            {
                "summary": Reporter._summary_dict(results),
                "insights": Reporter._generate_insights(results),
                "results": [r.to_dict() for r in results],
            },
            indent=indent,
            ensure_ascii=False,
        )

    @staticmethod
    def to_markdown(results: List[TestResult]) -> str:
        lines = ["# 🔒 Correctover Agent Security Audit", ""]
        lines.append(f"> **{Reporter._summary_badge(results)}**")
        lines.append("")
        lines.extend(Reporter._summary_lines(results))
        lines.append("")

        # Security insights
        insights = Reporter._generate_insights(results)
        if insights:
            lines.append("## 🚨 Security Findings")
            lines.append("")
            for insight in insights:
                sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "WARNING": "🟡", "INFO": "🔵"}.get(
                    insight.get("severity", ""), "⚪"
                )
                lines.append(
                    f"- {sev_icon} **{insight['severity']}** — {insight['message']}"
                )
                if insight.get("remediation"):
                    lines.append(f"  - *Fix:* {insight['remediation']}")
            lines.append("")

        lines.append("## Results")
        lines.append("")
        lines.append(
            "| Framework | Scenario | Verdict | Self-Heal Rate | Decisions | Integrity | Duration (ms) |"
        )
        lines.append(
            "|-----------|----------|---------|---------------|-----------|-----------|---------------|"
        )
        for r in sorted(results, key=lambda x: (x.framework, x.scenario)):
            icon = "✅" if r.verdict.value == "PASS" else "❌"
            integrity_icon = "✅" if r.integrity_verified else "❌"
            lines.append(
                f"| {r.framework} | {r.scenario} | {icon} {r.verdict.value} | "
                f"{r.self_heal_rate:.1%} | {r.decisions_count} | {integrity_icon} | "
                f"{r.duration_ms:.1f} |"
            )

        # CTA
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append(
            f"## 🛡️ [{Reporter.CTA_TEXT}]({Reporter.CTA_URL})"
        )
        lines.append("")
        lines.append(
            "Correctover adds **4-level self-healing**, **semantic validation**, "
            "and **drift detection** to your AI agents — in 5 minutes."
        )

        return "\n".join(lines)

    @staticmethod
    def to_terminal(
        results: List[TestResult],
        file: TextIO = sys.stdout,
        show_cta: bool = True,
    ) -> None:
        """Print colored terminal output with security insights."""
        GREEN = "\033[92m"
        RED = "\033[91m"
        YELLOW = "\033[93m"
        CYAN = "\033[96m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        RESET = "\033[0m"

        # Header
        file.write(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════╗{RESET}\n")
        file.write(f"{BOLD}{CYAN}║{RESET}     {BOLD}Correctover Agent Security Audit{RESET}          {BOLD}{CYAN}║{RESET}\n")
        file.write(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════╝{RESET}\n\n")

        # Summary line
        badge = Reporter._summary_badge(results)
        file.write(f"  {badge}\n\n")

        # Insights
        insights = Reporter._generate_insights(results)
        if insights:
            file.write(f"{BOLD}🚨 Security Findings:{RESET}\n\n")
            for insight in insights:
                sev_color = {"CRITICAL": RED, "HIGH": YELLOW, "WARNING": YELLOW, "INFO": CYAN}.get(
                    insight.get("severity", ""), RESET
                )
                file.write(
                    f"  {sev_color}[{insight['severity']}]{RESET} {insight['message']}\n"
                )
                if insight.get("remediation"):
                    file.write(f"     {DIM}→ {insight['remediation']}{RESET}\n")
            file.write("\n")

        # Table
        file.write(f"{BOLD}Results:{RESET}\n")
        file.write(
            f"{'Framework':<14} {'Scenario':<18} {'Verdict':<8} {'Rate':<8} {'Decisions':<10} {'Integrity':<10} {'Duration'}\n"
        )
        file.write("-" * 90 + "\n")

        for r in sorted(results, key=lambda x: (x.framework, x.scenario)):
            color = GREEN if r.verdict.value == "PASS" else RED
            integrity_color = GREEN if r.integrity_verified else RED
            file.write(
                f"{r.framework:<14} {r.scenario:<18} "
                f"{color}{r.verdict.value:<8}{RESET} "
                f"{r.self_heal_rate:.1%}     "
                f"{r.decisions_count:<10} "
                f"{integrity_color}{'OK' if r.integrity_verified else 'FAIL'}{RESET}       "
                f"{r.duration_ms:.1f}ms\n"
            )

        # Summary bar
        total = len(results)
        passed = sum(1 for r in results if r.verdict.value == "PASS")
        color = GREEN if passed == total else (YELLOW if passed > 0 else RED)
        file.write(
            f"\n{BOLD}Total: {total}  Passed: {color}{passed}{RESET}  "
            f"Failed: {RED}{total - passed}{RESET}\n"
        )

        # CTA
        if show_cta:
            file.write(f"\n{BOLD}{CYAN}┌─────────────────────────────────────────────────┐{RESET}\n")
            file.write(f"{BOLD}{CYAN}│{RESET}  🛡️  {BOLD}{Reporter.CTA_TEXT}{RESET}          {BOLD}{CYAN}│{RESET}\n")
            file.write(f"{BOLD}{CYAN}│{RESET}  {DIM}4-level self-healing · semantic validation{RESET}  {BOLD}{CYAN}│{RESET}\n")
            file.write(f"{BOLD}{CYAN}│{RESET}  {DIM}drift detection · 9 providers · 22µs P50{RESET}  {BOLD}{CYAN}│{RESET}\n")
            file.write(f"{BOLD}{CYAN}└─────────────────────────────────────────────────┘{RESET}\n\n")

    @staticmethod
    def to_html(results: List[TestResult]) -> str:
        """Generate a self-contained HTML report."""
        insights = Reporter._generate_insights(results)
        summary = Reporter._summary_dict(results)

        def badge_class(v):
            return "pass" if v == "PASS" else "fail"

        rows = ""
        for r in sorted(results, key=lambda x: (x.framework, x.scenario)):
            rows += f"""
            <tr>
                <td>{r.framework}</td>
                <td>{r.scenario}</td>
                <td class="{badge_class(r.verdict.value)}">{'✅' if r.verdict.value == 'PASS' else '❌'} {r.verdict.value}</td>
                <td>{r.self_heal_rate:.1%}</td>
                <td>{r.decisions_count}</td>
                <td>{'✅' if r.integrity_verified else '❌'}</td>
                <td>{r.duration_ms:.1f}ms</td>
            </tr>"""

        insight_html = ""
        for ins in insights:
            sev = ins.get("severity", "INFO").lower()
            insight_html += f"""
            <div class="insight insight-{sev}">
                <span class="severity">{ins['severity']}</span>
                <span>{ins['message']}</span>
                {f'<div class="fix">{ins["remediation"]}</div>' if ins.get("remediation") else ""}
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Correctover Agent Security Audit</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #0a0e17; color: #e2e8f0; padding: 40px; max-width: 960px; margin: auto; }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .header h1 {{ font-size: 28px; color: #38bdf8; }}
        .badge {{ display: inline-block; padding: 6px 18px; border-radius: 20px;
                   font-weight: 700; font-size: 14px; margin: 10px 0; }}
        .badge-clean {{ background: #065f46; color: #6ee7b7; }}
        .badge-warn {{ background: #78350f; color: #fbbf24; }}
        .badge-danger {{ background: #7f1d1d; color: #fca5a5; }}
        .insight {{ padding: 10px 16px; margin: 6px 0; border-radius: 8px; border-left: 4px solid; }}
        .insight-critical {{ background: #7f1d1d22; border-color: #ef4444; }}
        .insight-high {{ background: #78350f22; border-color: #f59e0b; }}
        .insight-warning {{ background: #78350f11; border-color: #eab308; }}
        .severity {{ font-weight: 700; margin-right: 8px; }}
        .fix {{ margin-top: 4px; font-size: 13px; color: #94a3b8; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #1e293b; padding: 10px; text-align: left; font-size: 13px; color: #94a3b8; }}
        td {{ padding: 10px; border-bottom: 1px solid #1e293b; font-size: 14px; }}
        .pass {{ color: #4ade80; font-weight: 600; }}
        .fail {{ color: #f87171; font-weight: 600; }}
        .cta {{ text-align: center; margin-top: 30px; padding: 24px; background: linear-gradient(135deg, #1e293b, #0f172a);
                 border-radius: 12px; border: 1px solid #334155; }}
        .cta a {{ color: #38bdf8; font-size: 18px; font-weight: 700; text-decoration: none; }}
        .cta p {{ color: #94a3b8; margin-top: 6px; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Correctover Agent Security Audit</h1>
        <div class="badge {Reporter._html_badge_class(results)}">{Reporter._summary_badge(results)}</div>
    </div>

    <h2>🚨 Security Findings</h2>
    {insight_html if insight_html else '<p style="color:#4ade80;">✅ No security issues found — your agents are protected!</p>'}

    <h2>Results</h2>
    <table>
        <tr><th>Framework</th><th>Scenario</th><th>Verdict</th><th>Self-Heal Rate</th><th>Decisions</th><th>Integrity</th><th>Duration</th></tr>
        {rows}
    </table>

    <div class="cta">
        <a href="{Reporter.CTA_URL}">🛡️ {Reporter.CTA_TEXT}</a>
        <p>Add 4-level self-healing, semantic validation, and drift detection to your agents in 5 minutes.</p>
    </div>

    <p style="text-align:center; margin-top: 20px; color: #475569; font-size: 12px;">
        Generated by correctover-test v0.2.0 · Apache 2.0
    </p>
</body>
</html>"""

    # ── Insight Engine ───────────────────────────────────────────

    @staticmethod
    def _generate_insights(results: List[TestResult]) -> List[Dict]:
        """Generate actionable security insights from test results."""
        insights = []

        for r in results:
            if r.decisions_count == 0:
                insights.append({
                    "severity": "CRITICAL",
                    "message": (
                        f"{r.framework}/{r.scenario}: Zero guardrail decisions — "
                        f"your agent has NO protection against tool misuse"
                    ),
                    "remediation": f"Add correctover guardrail to your {r.framework} agent: "
                                   f"pip install correctover && see correctover.com/docs",
                })
            elif r.verdict.value == "FAIL":
                for m in r.metrics:
                    if not m.passed:
                        insights.append({
                            "severity": "HIGH",
                            "message": (
                                f"{r.framework}/{r.scenario}: {m.dimension} check FAILED — "
                                f"{m.detail}"
                            ),
                            "remediation": (
                                f"Configure {m.dimension} validation in your "
                                f"correctover GuardrailProvider"
                            ),
                        })

            # Framework-specific warnings
            if r.framework == "crewai" and r.decisions_count == 0:
                insights.append({
                    "severity": "WARNING",
                    "message": (
                        "CrewAI agents detected without guardrail hooks. "
                        "Tool calls execute without authorization checks."
                    ),
                    "remediation": (
                        "Use correctover.make_guardrail_hook() with CrewAI's "
                        "register_before_tool_call_hook()"
                    ),
                })
            elif r.framework == "smolagents" and r.decisions_count == 0:
                insights.append({
                    "severity": "WARNING",
                    "message": (
                        "Smolagents has NO native before_tool_call hook. "
                        "All tool calls bypass security checks."
                    ),
                    "remediation": (
                        "Wrap agent.run() with correctover GuardrailContext "
                        "for pre-execution validation"
                    ),
                })

        # Deduplicate by message
        seen = set()
        unique = []
        for ins in insights:
            if ins["message"] not in seen:
                seen.add(ins["message"])
                unique.append(ins)
        return unique

    # ── Summary Helpers ──────────────────────────────────────────

    @staticmethod
    def _summary_dict(results: List[TestResult]) -> dict:
        total = len(results)
        passed = sum(1 for r in results if r.verdict.value == "PASS")
        avg_rate = sum(r.self_heal_rate for r in results) / max(total, 1)
        frameworks = sorted(set(r.framework for r in results))
        return {
            "total_tests": total,
            "passed": passed,
            "failed": total - passed,
            "pass_rate": round(passed / max(total, 1), 4),
            "avg_self_heal_rate": round(avg_rate, 4),
            "frameworks_tested": frameworks,
        }

    @staticmethod
    def _summary_lines(results: List[TestResult]) -> List[str]:
        s = Reporter._summary_dict(results)
        return [
            f"- **Total tests**: {s['total_tests']}",
            f"- **Passed**: {s['passed']}",
            f"- **Failed**: {s['failed']}",
            f"- **Pass rate**: {s['pass_rate']:.1%}",
            f"- **Avg self-heal rate**: {s['avg_self_heal_rate']:.1%}",
            f"- **Frameworks tested**: {', '.join(s['frameworks_tested'])}",
        ]

    @staticmethod
    def _summary_terminal(results: List[TestResult]) -> str:
        s = Reporter._summary_dict(results)
        GREEN = "\033[92m"
        RED = "\033[91m"
        RESET = "\033[0m"
        return (
            f"  Total: {s['total_tests']}  "
            f"Passed: {GREEN}{s['passed']}{RESET}  "
            f"Failed: {RED}{s['failed']}{RESET}  "
            f"Pass Rate: {s['pass_rate']:.1%}  "
            f"Avg Self-Heal: {s['avg_self_heal_rate']:.1%}\n"
        )

    @staticmethod
    def _summary_badge(results: List[TestResult]) -> str:
        total = len(results)
        passed = sum(1 for r in results if r.verdict.value == "PASS")
        if passed == total:
            return f"✅ All {total} tests passed — your agents are protected"
        elif passed == 0:
            return f"🚨 ALL {total} tests FAILED — your agents are UNPROTECTED"
        else:
            return f"⚠️ {passed}/{total} passed — {total - passed} security gaps found"

    @staticmethod
    def _html_badge_class(results: List[TestResult]) -> str:
        total = len(results)
        passed = sum(1 for r in results if r.verdict.value == "PASS")
        if passed == total:
            return "badge-clean"
        elif passed == 0:
            return "badge-danger"
        return "badge-warn"
