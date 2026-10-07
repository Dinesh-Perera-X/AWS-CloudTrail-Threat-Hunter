import argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.cloudtrail_parser import CloudTrailParser

console = Console()

def display_banner():
    banner = (
        "[bold cyan]AWS-CloudTrail-Threat-Hunter 🛡️☁️[/bold cyan]\n"
        "[dim]Day 1: Ingestion & Schema Normalization Parser[/dim]"
    )
    console.print(Panel.fit(banner, border_style="cyan"))

def main():
    parser = argparse.ArgumentParser(description="AWS CloudTrail Log Threat Hunter.")
    parser.add_argument("--logs", help="Path to CloudTrail JSON logs", default="data/cloudtrail_logs.json")
    args = parser.parse_args()

    display_banner()

    logs = CloudTrailParser.load_logs(args.logs)

    table = Table(title="[bold green]📋 Parsed CloudTrail Events Feed[/bold green]", border_style="green")
    table.add_column("Event ID", justify="center", style="dim")
    table.add_column("Time", style="cyan")
    table.add_column("Event Name", style="yellow")
    table.add_column("User", style="magenta")
    table.add_column("Source IP", justify="center")

    for log in logs:
        table.add_row(
            log["event_id"],
            log["event_time"],
            log["event_name"],
            log["user_name"],
            log["source_ip"]
        )

    console.print(table)
    console.print(f"\n[bold green]✔ Day 1 Complete:[/bold green] Successfully parsed [bold cyan]{len(logs)}[/bold cyan] CloudTrail records.")

if __name__ == "__main__":
    main()
