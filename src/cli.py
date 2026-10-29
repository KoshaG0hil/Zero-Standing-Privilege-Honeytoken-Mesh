"""CLI operator utility for Zero-Standing-Privilege Dynamic Access & Honeytoken Defense Mesh."""

import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .broker.ephemeral_sts_broker import EphemeralSTSBroker
from .core.config import HoneytokenType, JITSessionRequest
from .honeytokens.honeytoken_generator import HoneytokenManager
from .remediators.session_revocation_engine import HoneytokenRevocationEngine
from .reporters.forensic_manifest import ForensicManifestGenerator

console = Console()

BANNER = r"""[bold cyan]
  _____ ____  _____    __  __                          __        __
 /__  // __ \/ ___/   / / / /___  ____  ___  __  __   / /_____  / /_____  ____
   / // /_/ /\__ \   / /_/ / __ \/ __ \/ _ \/ / / /  / __/ __ \/ //_/ _ \/ __ \
  / // ____/___/ /  / __  / /_/ / / / /  __/ /_/ /  / /_/ /_/ / ,< /  __/ / / /
 /_//_/    /____/  /_/ /_/\____/_/ /_/\___/\__, /   \__/\____/_/|_|\___/_/ /_/
                                          /____/
[/bold cyan]
[dim]Zero-Standing-Privilege (ZSP) Dynamic Access & Honeytoken Defense Mesh on AWS[/dim]
"""


def cmd_simulate(args):
    """Executes full end-to-end ZSP lifecycle and honeytoken attacker tripwire simulation."""
    console.print(BANNER)
    console.print(
        Panel(
            "[bold yellow]Executing Zero-Standing-Privilege & Honeytoken Containment Simulation[/bold yellow]\n"
            "[dim]Phases: Ephemeral STS Elevation -> Honeytoken Tripwire -> Instant Attacker Neutralization[/dim]\n"
            "[dim]Standards: MITRE ATT&CK T1078 (Valid Accounts) | AWS Security Best Practices[/dim]",
            title="[ZSP Mesh Simulation]",
            border_style="cyan",
        )
    )

    broker = EphemeralSTSBroker(dry_run=True)
    honey_mgr = HoneytokenManager()
    remediator = HoneytokenRevocationEngine(broker=broker)
    reporter = ForensicManifestGenerator()

    # Step 1: Request Ephemeral Privileged Access (ZSP)
    console.print("\n[bold cyan][Phase 1] Just-In-Time (JIT) Privileged Elevation Request[/bold cyan]")
    req = JITSessionRequest(
        user_arn="arn:aws:identitystore:::user/kosha-gohil",
        target_role_arn="arn:aws:iam::123456789012:role/ProductionDatabaseAdmin",
        duration_minutes=15,
        justification="Emergency production database migration maintenance window.",
        ticket_id="CHG-4091",
        mfa_authenticated=True,
    )
    token = broker.request_access(req)
    console.print(f" [+] JIT Privileged Session Issued: [bold green]{token.session_id}[/bold green]")
    console.print(f" [+] Target Privileged Role:        [white]{token.target_role_arn}[/white]")
    console.print(f" [+] Temporary Assumed Key:         [yellow]{token.access_key_id}[/yellow]")
    console.print(f" [+] Session TTL:                   [cyan]{token.ttl_seconds // 60} minutes (Ephemeral)[/cyan]")

    # Step 2: Plant Decoy Honeytokens in Environment
    console.print("\n[bold cyan][Phase 2] Deploying Canary Honeytokens into Environment[/bold cyan]")
    honey = honey_mgr.deploy_honeytoken(
        honey_type=HoneytokenType.IAM_ACCESS_KEY,
        deployed_location="git-repo:fintech-core/.env.production.local",
    )
    console.print(f" [+] Canary Honeytoken ID:          [bold yellow]{honey.token_id}[/bold yellow]")
    console.print(f" [+] Decoy Canary Key:              [yellow]{honey.decoy_access_key_id}[/yellow]")
    console.print(f" [+] Planted Decoy Location:        [white]{honey.deployed_location}[/white]")

    # Step 3: Attacker Interacts with Honeytoken
    console.print("\n[bold red][Phase 3] Threat Actor Tripwire Triggered via AWS CloudTrail[/bold red]")
    simulated_cloudtrail_event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "accessKeyId": honey.decoy_access_key_id,
            "arn": honey.canary_principal_arn,
        },
        "eventTime": "2026-10-29T14:24:00Z",
        "eventName": "GetCallerIdentity",
        "sourceIPAddress": "198.51.100.44",
        "userAgent": "aws-cli/2.15.15 Python/3.11.6 Linux/5.15.0",
    }
    alert = honey_mgr.evaluate_cloudtrail_event(simulated_cloudtrail_event)
    console.print(f" [!] Tripwire Breach Alert ID:       [bold red]{alert.event_id}[/bold red]")
    console.print(f" [!] Offending IP Address:          [red]{alert.source_ip}[/red]")
    console.print(f" [!] Adversarial API Call:          [yellow]{alert.event_name}[/yellow]")

    # Step 4: Sub-Second Automated Containment
    console.print("\n[bold green][Phase 4] Automated Incident Response & Session Revocation[/bold green]")
    action = remediator.remediate_breach(alert, target_role_arn=token.target_role_arn)

    table = Table(title="[Incident Response Containment Matrix]", show_header=True, header_style="bold green")
    table.add_column("Action ID", style="cyan", width=18)
    table.add_column("Offending Principal / IP", style="red", width=36)
    table.add_column("Sessions Dropped", style="yellow", width=18)
    table.add_column("Inline Deny Attached", style="green", width=22)
    table.add_column("Latency", style="bold green", width=14)

    table.add_row(
        action.action_id,
        f"{alert.caller_arn}\n({alert.source_ip})",
        str(action.sessions_terminated),
        "Yes (EmergencyDenyAll)",
        f"{action.containment_duration_ms} ms",
    )
    console.print(table)

    # Step 5: Tamper-Evident Forensic Incident Manifest
    manifest = reporter.generate([alert], [action])
    out_file = reporter.save_report(manifest)

    avg_ms = manifest["metrics"]["average_containment_latency_ms"]
    console.print(
        Panel(
            f"[bold green]Containment Status:[/bold green]     SUCCESS (Neutralized)\n"
            f"[bold white]Sessions Revoked:[/bold white]       {manifest['metrics']['total_sessions_terminated']}\n"
            f"[bold yellow]Latency:[/bold yellow]                {avg_ms} ms\n"
            f"[bold cyan]Forensic Report ID:[/bold cyan]     {manifest['report_id']}\n"
            f"[bold cyan]Cryptographic SHA-256:[/bold cyan]  {manifest['sha256_checksum']}\n"
            f"[bold dim]Forensic Saved:[/bold dim]         {out_file}",
            title="[SecOps Incident Attribution Posture]",
            border_style="green",
        )
    )


def main():
    parser = argparse.ArgumentParser(description="Zero-Standing-Privilege Honeytoken Defense Mesh CLI")
    subparsers = parser.add_subparsers(dest="command")

    sim_parser = subparsers.add_parser("simulate", help="Runs complete ZSP and honeytoken tripwire simulation")
    sim_parser.set_defaults(func=cmd_simulate)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
