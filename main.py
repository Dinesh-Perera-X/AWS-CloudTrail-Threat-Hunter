import argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.cloudtrail_parser import CloudTrailParser
from analyzers.security_analyzer import SecurityAnalyzer

console = Console()

def display_banner():
    banner = (
        "[bold cyan]AWS-CloudTrail-Threat-Hunter 🛡️☁️[/bold cyan]\n"
        "[dim]Day 2: Heuristic Security Analyzers Active[/dim]"
    )
    console.print(Panel.fit(banner, border_style="cyan"))

def main():
    parser = argparse.ArgumentParser(description="AWS CloudTrail Log Threat Hunter.")
    parser.add_argument("--logs", help="Path to CloudTrail JSON logs", default="data/cloudtrail_logs.json")
    args = parser.parse_args()

    display_banner()

    logs = CloudTrailParser.load_logs(args.logs)
    analyzed_logs = SecurityAnalyzer.analyze_events(logs)

    table = Table(title="[bold green]🚨 Security Threat Analysis Dashboard[/bold green]", border_style="green")
    table.add_column("Event ID", justify="center", style="dim")
    table.add_column("Event Name", style="yellow")
    table.add_column("User", style="magenta")
    table.add_column("Threat Level", justify="center")
    table.add_column("Detected Behavior", style="bold")

    for log in analyzed_logs:
        level = log["threat_level"]
        level_str = "[bold red]CRITICAL[/bold red]" if level == "CRITICAL" else "[bold yellow]HIGH[/bold yellow]" if level == "HIGH" else "[green]NORMAL[/green]"
        behavior_str = f"[red]{log['detected_behavior']}[/red]" if level in ["HIGH", "CRITICAL"] else f"[dim]{log['detected_behavior']}[/dim]"

        table.add_row(
            log["event_id"],
            log["event_name"],
            log["user_name"],
            level_str,
            behavior_str
        )

    console.print(table)
    console.print(f"\n[bold green]✔ Day 2 Complete:[/bold green] Successfully analyzed [bold cyan]{len(analyzed_logs)}[/bold cyan] CloudTrail records for threats.")

if __name__ == "__main__":
    main()
