"""Rich CLI entry point for the RIG Web Security Scanner.

Usage:
    rig scan example.com
    rig scan example.com -m recon -m web -v
    rig scan example.com -o reports/my_report -f html
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

import click

from src import __version__

# ---------------------------------------------------------------------------
# Rich imports (lazy — CLI will fail gracefully if rich is missing)
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
        TaskID,
    )
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover
    RICH_AVAILABLE = False
    Console = object  # type: ignore[assignment]
    Progress = object  # type: ignore[assignment]
    Panel = object  # type: ignore[assignment]
    Table = object  # type: ignore[assignment]
    Text = object  # type: ignore[assignment]

from src.config import load_config
from src.core.report import Report
from src.core.scanner import Scanner

# ---------------------------------------------------------------------------
# Severity colors for Rich output
# ---------------------------------------------------------------------------
SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "white",
    "error": "bold red",
    "success": "green",
    "warning": "yellow",
}


def _severity_tag(severity: str) -> str:
    """Return a coloured severity label."""
    sev = severity.lower()
    style = SEVERITY_STYLES.get(sev, "white")
    return f"[{style}]{sev.upper():^10}[/{style}]"


# ---------------------------------------------------------------------------
# Click CLI
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(version=__version__, prog_name="RIG Scanner")
def cli() -> None:
    """Resistance Infrastructure Gabon — Web Security Scanner

    A modular security scanner for web applications and infrastructure.
    """
    pass


@cli.command()
@click.argument("target")
@click.option(
    "--modules", "-m",
    multiple=True,
    default=["all"],
    help="Modules to run: recon, web, vuln, all",
)
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to YAML configuration file (e.g. config/rig.yml)",
)
@click.option(
    "--output", "-o",
    default="reports/report",
    show_default=True,
    help="Output file path (without extension)",
)
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["html", "json", "pdf"]),
    default="json",
    show_default=True,
    help="Output report format",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output with real-time findings",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="Suppress all output except final report path",
)
def scan(
    target: str,
    modules: tuple[str, ...],
    config: str | None,
    output: str,
    fmt: str,
    verbose: bool,
    quiet: bool,
) -> None:
    """Run security scan against TARGET (URL or domain).

    \b
    Examples:
        rig scan example.com
        rig scan example.com -m recon -m web -v
        rig scan example.com -o reports/scan -f html -q
    """
    # ── Console ────────────────────────────────────────────────
    console = Console() if RICH_AVAILABLE else None

    if not quiet and console:
        console.print(
            Panel(
                f"[bold cyan]RIG Scanner[/bold cyan] v{__version__}\n"
                f"[white]Target:[/white] [bold]{target}[/bold]\n"
                f"[white]Modules:[/white] {', '.join(modules)}\n"
                f"[white]Date:[/white] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                title="[bold]🔍 Security Scan[/bold]",
                border_style="cyan",
            )
        )
    elif not quiet:
        click.echo(f"[*] Scanning: {target} (modules: {', '.join(modules)})")

    # ── Build Scanner ──────────────────────────────────────────
    module_list = list(modules)
    # Load YAML config if provided (or auto-search defaults)
    cfg = load_config(config)
    scanner = Scanner(target, modules=module_list, config=cfg)

    # ── Run with Progress ──────────────────────────────────────
    if not quiet and console and RICH_AVAILABLE:
        results = _run_with_progress(console, scanner, module_list, verbose)
    else:
        if verbose and not quiet:
            click.echo("[*] Verbose mode enabled")
        results = scanner.run()

    # ── Generate Report ────────────────────────────────────────
    scan_duration = results.get("scan_duration", 0.0)

    try:
        report = Report(results, scan_duration=scan_duration)
        saved_path = report.save(output, fmt=fmt)  # type: ignore[arg-type]
    except Exception as exc:
        if not quiet:
            click.echo(f"[!] Report generation failed: {exc}", err=True)
        saved_path = None

    # ── Results Summary ────────────────────────────────────────
    if not quiet:
        _display_summary(console, results, scan_duration)

    if not quiet and saved_path:
        report_msg = f"[+] Report saved: {saved_path}"
        if console and RICH_AVAILABLE:
            console.print(Panel(report_msg, border_style="green"))
        else:
            click.echo(report_msg)

    # In quiet mode, just print the report path
    if quiet and saved_path:
        click.echo(saved_path)


# ---------------------------------------------------------------------------
# Progress display
# ---------------------------------------------------------------------------


def _run_with_progress(
    console: Any,
    scanner: Scanner,
    module_list: list[str],
    verbose: bool,
) -> dict[str, Any]:
    """Run the scanner with Rich progress bars.

    Args:
        console: Rich Console instance.
        scanner: Scanner instance.
        module_list: List of module names to run.
        verbose: Whether to display real-time findings.

    Returns:
        Scan results dict.
    """
    if "all" in module_list:
        module_list = ["recon", "web", "vuln"]

    modules_to_run = [m for m in ("recon", "web", "vuln") if m in module_list]

    progress = Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )

    results: dict[str, Any] = {"target": scanner.target, "modules": {}}
    tasks: dict[str, TaskID] = {}
    module_results: dict[str, dict[str, Any]] = {}
    findings_log: list[str] = []

    with progress:
        # Create a task for each module with unknown total -> set later
        for mod_name in modules_to_run:
            # Estimate: count sub-modules for each module
            sub_count = {
                "recon": 4,  # dns, whois, subdomains, portscan
                "web": 4,    # headers, ssl, crawler, fingerprint
                "vuln": 5,   # sqli, xss, csrf, sensitive_files, open_redirect
            }
            total = sub_count.get(mod_name, 4)
            task_id = progress.add_task(
                f"[cyan]{mod_name:12s}[/cyan]",
                total=total,
            )
            tasks[mod_name] = task_id

        # Run modules
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(modules_to_run),
        ) as executor:
            future_map = {
                executor.submit(scanner._run_single_module, mod_name): mod_name
                for mod_name in modules_to_run
            }

            for future in concurrent.futures.as_completed(future_map):
                mod_name = future_map[future]
                try:
                    mod_result = future.result()
                    module_results[mod_name] = mod_result
                    results["modules"][mod_name] = mod_result
                    # Mark as complete
                    task = tasks[mod_name]
                    total = progress.tasks[task].total
                    progress.update(task, completed=total, refresh=True)

                    # Log findings in verbose mode
                    if verbose:
                        findings = _extract_findings(mod_result, mod_name)
                        findings_log.extend(findings)
                except Exception as exc:
                    module_results[mod_name] = {"status": "error", "error": str(exc)}
                    results["modules"][mod_name] = module_results[mod_name]
                    task = tasks[mod_name]
                    progress.update(task, completed=progress.tasks[task].total, refresh=True)
                    if verbose:
                        findings_log.append(f"[red]Error in {mod_name}: {exc}[/red]")

    # Display real-time findings in verbose mode
    if verbose and findings_log:
        console.print("\n[bold underline]Findings Log:[/bold underline]")
        for entry in findings_log:
            console.print(f"  {entry}")

    return results


def _extract_findings(module_result: dict[str, Any], module_name: str) -> list[str]:
    """Extract readable findings from a module result."""
    lines: list[str] = []
    for sub_name, sub_data in module_result.items():
        if not isinstance(sub_data, dict):
            continue
        findings = sub_data.get("data", {}).get("findings", [])
        if isinstance(findings, list):
            for f in findings:
                sev = f.get("severity", "info").lower()
                desc = f.get("type", f.get("name", "unknown"))
                param = f.get("param", "")
                extra = f" [dim](param: {param})[/dim]" if param else ""
                tag = _severity_tag(sev)
                lines.append(f"  [{module_name}.{sub_name}] {tag} {desc}{extra}")
    return lines


# ---------------------------------------------------------------------------
# Summary display
# ---------------------------------------------------------------------------


def _display_summary(
    console: Any,
    results: dict[str, Any],
    scan_duration: float,
) -> None:
    """Display the scan results summary table."""
    modules = results.get("modules", {})
    target = results.get("target", "unknown")

    if not modules:
        return

    if console and RICH_AVAILABLE:
        _display_rich_summary(console, modules, target, scan_duration)
    else:
        _display_plain_summary(modules, target, scan_duration)


def _display_rich_summary(
    console: Any,
    modules: dict[str, Any],
    target: str,
    scan_duration: float,
) -> None:
    """Display summary using Rich Table and Tree."""
    # ── Module summary table ──────────────────────────────────
    table = Table(
        title=f"Scan Results — {target}",
        title_style="bold cyan",
        border_style="cyan",
        header_style="bold white",
    )
    table.add_column("Module", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Findings", justify="right")
    table.add_column("Duration", justify="right")

    total_findings = 0
    total_duration = 0.0

    for mod_name in ("recon", "web", "vuln"):
        mod_data = modules.get(mod_name)
        if mod_data is None:
            continue

        status, findings_count, duration = _summarize_module(mod_data, mod_name)

        status_str = _status_display(status)
        if status == "error":
            status_str = f"[bold red]✗ Error[/bold red]"
        elif findings_count > 0:
            status_str = f"[green]✔ Done[/green]"
        else:
            status_str = f"[green]✔ Done[/green]"

        dur_str = f"{duration:.1f}s" if duration else "—"
        table.add_row(mod_name.capitalize(), status_str, str(findings_count), dur_str)

        total_findings += findings_count
        total_duration += duration

    # Add total row
    table.add_row(
        "[bold]Total[/bold]",
        "",
        f"[bold]{total_findings}[/bold]",
        f"[bold]{total_duration:.1f}s[/bold]",
        style="bold",
    )

    console.print()
    console.print(table)

    # ── Severity breakdown ────────────────────────────────────
    severity_counts = _count_severities(modules)
    if severity_counts:
        sev_table = Table(title="Severity Breakdown", border_style="dim")
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="right")

        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(sev, 0)
            if count > 0:
                style = SEVERITY_STYLES.get(sev, "white")
                sev_table.add_row(f"[{style}]{sev.capitalize()}[/{style}]", str(count))

        console.print()
        console.print(sev_table)

    # ── Findings tree per module (if any) ─────────────────────
    has_findings = any(
        _extract_findings_count(mod) > 0
        for mod in modules.values()
        if isinstance(mod, dict)
    )

    if has_findings:
        tree = Tree(f"[bold]Findings Overview[/bold]")
        for mod_name in ("recon", "web", "vuln"):
            mod_data = modules.get(mod_name)
            if not isinstance(mod_data, dict):
                continue
            branch = Tree(f"[cyan]{mod_name.capitalize()}[/cyan]")
            count = _add_findings_to_tree(branch, mod_data)
            if count > 0:
                tree.add(branch)

        console.print()
        console.print(tree)

    console.print(
        f"\n[dim]Total scan duration:[/dim] [bold]{scan_duration:.1f}s[/bold]"
    )


def _display_plain_summary(
    modules: dict[str, Any],
    target: str,
    scan_duration: float,
) -> None:
    """Display plain text summary (fallback when Rich is unavailable)."""
    click.echo(f"\n{'=' * 50}")
    click.echo(f"Scan Results — {target}")
    click.echo(f"{'=' * 50}")

    total_findings = 0

    for mod_name in ("recon", "web", "vuln"):
        mod_data = modules.get(mod_name)
        if mod_data is None:
            continue

        status, findings_count, duration = _summarize_module(mod_data, mod_name)
        status_symbol = "✓" if status != "error" else "✗"
        dur_str = f"{duration:.1f}s" if duration else "—"
        click.echo(f"  {status_symbol} {mod_name.capitalize():12s} | "
                    f"Findings: {findings_count:3d} | Duration: {dur_str}")
        total_findings += findings_count

    click.echo(f"{'-' * 50}")
    click.echo(f"  Total findings: {total_findings}  |  Duration: {scan_duration:.1f}s")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _summarize_module(mod_data: dict[str, Any], mod_name: str) -> tuple[str, int, float]:
    """Summarize a module's status, finding count, and estimated duration.

    Returns:
        Tuple of (status, findings_count, duration_seconds).
    """
    status = "success"
    findings_count = 0
    duration = 0.0

    for sub_name, sub_data in mod_data.items():
        if not isinstance(sub_data, dict):
            continue

        # Check sub-module status
        sub_status = sub_data.get("status", "success")
        if sub_status == "error":
            status = "error"

        # Count findings
        data = sub_data.get("data", {})
        if isinstance(data, dict):
            findings = data.get("findings", [])
            if isinstance(findings, list):
                findings_count += len(findings)
            # Also check for vulnerabilities
            vulns = data.get("vulnerabilities", [])
            if isinstance(vulns, list):
                findings_count += len(vulns)

    return status, findings_count, duration


def _extract_findings_count(mod_data: dict[str, Any]) -> int:
    """Count total findings across all sub-modules."""
    total = 0
    for sub_data in mod_data.values():
        if not isinstance(sub_data, dict):
            continue
        data = sub_data.get("data", {})
        if isinstance(data, dict):
            for key in ("findings", "vulnerabilities"):
                items = data.get(key, [])
                if isinstance(items, list):
                    total += len(items)
    return total


def _count_severities(modules: dict[str, Any]) -> dict[str, int]:
    """Count findings by severity across all modules."""
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for mod_data in modules.values():
        if not isinstance(mod_data, dict):
            continue
        for sub_data in mod_data.values():
            if not isinstance(sub_data, dict):
                continue
            data = sub_data.get("data", {})
            if not isinstance(data, dict):
                continue
            for key in ("findings", "vulnerabilities"):
                items = data.get(key, [])
                if not isinstance(items, list):
                    continue
                for item in items:
                    sev = (item.get("severity") or "info").lower()
                    if sev in counts:
                        counts[sev] += 1
                    else:
                        counts["info"] += 1
    return counts


def _status_display(status: str) -> str:
    """Return a Rich-formatted status string."""
    mapping = {
        "success": "[green]✔ Done[/green]",
        "error": "[bold red]✗ Error[/bold red]",
        "partial": "[yellow]~ Partial[/yellow]",
    }
    return mapping.get(status, f"[white]{status}[/white]")


def _add_findings_to_tree(branch: Any, mod_data: dict[str, Any]) -> int:
    """Recursively add findings to a Rich Tree branch.

    Returns:
        Number of findings added.
    """
    count = 0
    for sub_name, sub_data in mod_data.items():
        if not isinstance(sub_data, dict):
            continue
        data = sub_data.get("data", {})
        if not isinstance(data, dict):
            continue
        for key in ("findings", "vulnerabilities"):
            items = data.get(key, [])
            if not isinstance(items, list) or not items:
                continue
            sub_branch = branch.add(f"[dim]{sub_name}[/dim]")
            for item in items:
                sev = (item.get("severity") or "info").lower()
                style = SEVERITY_STYLES.get(sev, "white")
                desc = item.get("type", item.get("name", "finding"))
                param = item.get("param", "")
                label = f"[{style}]●[/{style}] {desc}"
                if param:
                    label += f" [dim]({param})[/dim]"
                sub_branch.add(label)
                count += 1
    return count


if __name__ == "__main__":
    cli()
