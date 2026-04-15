"""
NightWatch CLI — Main command-line interface.

Usage:
    nightwatch project create <name> --target <domain>
    nightwatch scan <project> --target <domain> [--subdomains] [--ports] [--cve]
    nightwatch monitor <project> --interval <hours>
    nightwatch report <project> [--format json|html|markdown]
    nightwatch list
    nightwatch status <project>
"""

import asyncio
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

from .core.engine import NightWatchEngine
from .core.config import Config, get_config
from .modules.report_generator import ReportGenerator
from .db.session import Database
from .utils.logging_utils import get_logger

log = get_logger("cli")
console = Console()


@click.group(invoke_without_command=True)
@click.version_option(version="1.0.0", prog_name="NightWatch")
@click.pass_context
def main(ctx):
    """NightWatch — AI-Powered Attack Surface Monitoring Framework."""
    if ctx.invoked_subcommand is None:
        console.print(Panel.fit(
            "[bold cyan]NightWatch[/bold cyan] v1.0.0\n"
            "[dim]AI-Powered Attack Surface Monitoring Framework[/dim]\n\n"
            "[bold]Quick Start:[/bold]\n"
            "  nightwatch project create myproject --target example.com\n"
            "  nightwatch scan myproject --target example.com\n"
            "  nightwatch report myproject --format html\n\n"
            "[bold]Commands:[/bold]\n"
            "  [cyan]project[/cyan]     Create and manage security research projects\n"
            "  [cyan]scan[/cyan]        Run reconnaissance scans\n"
            "  [cyan]monitor[/cyan]     Set up continuous monitoring\n"
            "  [cyan]report[/cyan]      Generate security reports\n"
            "  [cyan]list[/cyan]         List all projects\n"
            "  [cyan]status[/cyan]       Show project status and summary\n"
            "\n[dim]Use --help with any command for more options.[/dim]",
            border_style="cyan",
            title="NightWatch"
        ))


# ─── Project Management ────────────────────────────────────────────────────

@main.command("project")
@click.argument("action", type=click.Choice(["create", "list", "delete"]))
@click.option("--name", "-n", help="Project name")
@click.option("--target", "-t", help="Target domain (e.g. example.com)")
@click.option("--description", "-d", default="", help="Project description")
@click.option("--scope", "-s", multiple=True, help="In-scope domains or patterns")
def project(action, name, target, description, scope):
    """Create and manage security research projects."""
    if action == "create":
        if not name or not target:
            console.print("[red]Error:[/red] --name and --target are required")
            sys.exit(1)

        engine = NightWatchEngine()
        loop = asyncio.get_event_loop()
        try:
            pid = loop.run_until_complete(
                engine.create_project(name, target, description, list(scope))
            )
            console.print(f"[green]Created project '{name}' (ID: {pid})[/green]")
        except Exception as e:
            console.print(f"[red]Error creating project:[/red] {e}")
            sys.exit(1)

    elif action == "list":
        engine = NightWatchEngine()
        loop = asyncio.get_event_loop()
        try:
            projects = loop.run_until_complete(engine.list_projects())
            if not projects:
                console.print("[dim]No projects found.[/dim]")
                return

            table = Table(title="NightWatch Projects", style="cyan")
            table.add_column("ID", style="bold")
            table.add_column("Name")
            table.add_column("Target Domain")
            table.add_column("Status")
            table.add_column("Created")

            for p in projects:
                status = "[green]Active[/green]" if p.is_active else "[red]Inactive[/red]"
                created = p.created_at.strftime("%Y-%m-%d") if p.created_at else "—"
                table.add_row(str(p.id), p.name, p.target_domain, status, created)

            console.print(table)
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)


# ─── Scanning ───────────────────────────────────────────────────────────────

@main.command("scan")
@click.argument("project", required=False)
@click.option("--target", "-t", help="Target domain to scan")
@click.option("--project-name", "-n", help="Project name (alternative to positional arg)")
@click.option("--subdomains", is_flag=True, default=True, help="Enumerate subdomains (default: enabled)")
@click.option("--http", is_flag=True, default=True, help="Probe HTTP/HTTPS services (default: enabled)")
@click.option("--ports", is_flag=True, help="Scan for open ports")
@click.option("--cve", is_flag=True, default=True, help="Check for known CVEs (default: enabled)")
@click.option("--scan-type", type=click.Choice(["quick", "common", "full"]), default="common", help="Port scan type")
@click.option("--output", "-o", help="Output file for JSON results")
def scan(project, target, project_name, subdomains, http, ports, cve, scan_type, output):
    """Run reconnaissance scans on a target."""
    project_name = project_name or project
    if not project_name:
        console.print("[red]Error:[/red] Project name required (positional or --name)")
        sys.exit(1)
    if not target:
        console.print("[red]Error:[/red] --target required")
        sys.exit(1)

    engine = NightWatchEngine()
    loop = asyncio.get_event_loop()

    # Find or create project
    proj = loop.run_until_complete(engine.get_project(project_name))
    if not proj:
        console.print(f"[yellow]Project '{project_name}' not found. Creating...[/yellow]")
        pid = loop.run_until_complete(
            engine.create_project(project_name, target)
        )
    else:
        pid = proj.id

    # Run scan
    console.print(f"[cyan]Starting scan for '{target}' in project '{project_name}'...[/cyan]\n")

    options = {
        "wordlist": None,
        "cve_check": cve,
        "scan_type": scan_type,
        "ports": ports,
    }

    try:
        results = loop.run_until_complete(
            engine.run_full_scan(pid, [target], options)
        )

        # Print results
        console.print(f"\n[bold green]Scan complete![/bold green]")
        console.print(f"  Subdomains found:   {results['subdomains_found']}")
        console.print(f"  Hosts probed:      {results['hosts_probed']}")
        console.print(f"  Open ports found:  {results['open_ports_found']}")
        console.print(f"  Vulnerabilities:    {results['vulnerabilities_found']}")
        console.print(f"  Duration:          {results['scan_time_seconds']}s")

        # Save JSON output
        if output:
            with open(output, "w") as f:
                json.dump(results, f, indent=2)
            console.print(f"\n[green]Results saved to {output}[/green]")

        # Show summary table
        engine.print_summary(pid)

    except Exception as e:
        console.print(f"[red]Scan error:[/red] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


# ─── Monitoring ─────────────────────────────────────────────────────────────

@main.command("monitor")
@click.argument("project")
@click.option("--interval", "-i", type=int, default=24, help="Check interval in hours (default: 24)")
@click.option("--target", "-t", help="Add a specific target to monitor")
@click.option("--target-type", type=click.Choice(["domain", "ip", "url"]), default="domain", help="Type of target")
def monitor(project, interval, target, target_type):
    """Set up continuous monitoring for a project."""
    engine = NightWatchEngine()
    loop = asyncio.get_event_loop()

    proj = loop.run_until_complete(engine.get_project(project))
    if not proj:
        console.print(f"[red]Error:[/red] Project '{project}' not found")
        sys.exit(1)

    console.print(f"[cyan]Running monitoring check for '{project}'...[/cyan]\n")

    try:
        changes = loop.run_until_complete(engine.run_monitor_check(proj.id))

        if not changes:
            console.print("[dim]No changes detected.[/dim]")
        else:
            table = Table(title="Detected Changes", style="yellow")
            table.add_column("Severity")
            table.add_column("Type")
            table.add_column("Description")

            for change in changes:
                sev = change.get("severity", "info")
                sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}.get(sev, "dim")
                table.add_row(
                    f"[{sev_color}]{sev.upper()}[/{sev_color}]",
                    f"[cyan]{change.get('type', '')}[/cyan]",
                    change.get("description", "")
                )

            console.print(table)
            console.print(f"\n[yellow]{len(changes)} changes detected[/yellow]")

    except Exception as e:
        console.print(f"[red]Monitor error:[/red] {e}")
        sys.exit(1)


# ─── Reporting ──────────────────────────────────────────────────────────────

@main.command("report")
@click.argument("project")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "html", "markdown", "all"]), default="all", help="Report format")
@click.option("--output-dir", "-o", help="Output directory")
def report(project, fmt, output_dir):
    """Generate security reports for a project."""
    engine = NightWatchEngine()
    loop = asyncio.get_event_loop()

    proj = loop.run_until_complete(engine.get_project(project))
    if not proj:
        console.print(f"[red]Error:[/red] Project '{project}' not found")
        sys.exit(1)

    console.print(f"[cyan]Generating report for '{project}'...[/cyan]\n")

    # Gather data
    summary = loop.run_until_complete(engine.get_summary(proj.id))

    async def _gather_data():
        async with engine.db.session() as session:
            from sqlalchemy import select
            from .db.database import Subdomain, HostScan, Vulnerability, ChangeLog

            subs = (await session.execute(select(Subdomain).where(Subdomain.project_id == proj.id))).scalars().all()
            hosts = (await session.execute(select(HostScan).where(HostScan.project_id == proj.id))).scalars().all()
            vulns = (await session.execute(select(Vulnerability).where(Vulnerability.project_id == proj.id))).scalars().all()
            changes = (await session.execute(select(ChangeLog).where(ChangeLog.project_id == proj.id))).scalars().all()

            return {
                "project": proj,
                "summary": summary,
                "subdomains": subs,
                "hosts": hosts,
                "vulnerabilities": vulns,
                "changes": changes,
            }

    data = loop.run_until_complete(_gather_data())

    # Generate reports
    formats = ["json", "html", "markdown"] if fmt == "all" else [fmt]
    generator = ReportGenerator()
    outputs = loop.run_until_complete(
        generator.generate_report(data, output_dir or str(Path.home() / "NightWatch" / "reports"), formats)
    )

    for fmt_name, path in outputs.items():
        console.print(f"  [{'green' if Path(path).exists() else 'red'}] {fmt_name.upper()}: {path}")


# ─── Status ─────────────────────────────────────────────────────────────────

@main.command("status")
@click.argument("project")
def status(project):
    """Show project status and summary."""
    engine = NightWatchEngine()
    loop = asyncio.get_event_loop()

    proj = loop.run_until_complete(engine.get_project(project))
    if not proj:
        console.print(f"[red]Error:[/red] Project '{project}' not found")
        sys.exit(1)

    engine.print_summary(proj.id)


# ─── List ───────────────────────────────────────────────────────────────────

@main.command("list")
def list_projects():
    """List all projects (alias for 'project list')."""
    engine = NightWatchEngine()
    loop = asyncio.get_event_loop()
    projects = loop.run_until_complete(engine.list_projects())

    if not projects:
        console.print("[dim]No projects found.[/dim]")
        return

    table = Table(title="NightWatch Projects", style="cyan")
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Created")

    for p in projects:
        status_str = "[green]Active[/green]" if p.is_active else "[red]Inactive[/red]"
        created = p.created_at.strftime("%Y-%m-%d") if p.created_at else "—"
        table.add_row(str(p.id), p.name, p.target_domain, status_str, created)

    console.print(table)


if __name__ == "__main__":
    main()
