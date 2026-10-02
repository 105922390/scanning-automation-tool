"""ReconPilot command-line entry point.

For now: select/list engagements and print the active scope summary. Stage
execution and the API/GUI are wired in later build steps; this establishes the
``--engagement`` selector that everything downstream keys off.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .engagement import DEFAULT_DIR, list_engagements, load_engagement
from .errors import ReconPilotError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconpilot",
        description="Authorization-first bug-bounty recon orchestration (local-only).")
    p.add_argument("-e", "--engagement", metavar="NAME",
                   help="active engagement: loads engagements/<NAME>.yaml")
    p.add_argument("--engagements-dir", default=DEFAULT_DIR, metavar="DIR",
                   help=f"where scope files live (default: {DEFAULT_DIR}/)")
    p.add_argument("--list", action="store_true",
                   help="list available engagements and exit")
    p.add_argument("--safe-mode", action="store_true",
                   help="force extra-conservative rates/concurrency (halves them)")
    p.add_argument("--run-passive", action="store_true",
                   help="run the passive_recon stage (subfinder/amass) for the active engagement")
    p.add_argument("--dry-run", action="store_true",
                   help="with --run-passive: show the plan (seeds + commands), don't execute")
    p.add_argument("--only", metavar="TOOL[,TOOL]",
                   help="with --run-passive: run only these passive tools "
                        "(e.g. --only subfinder); must be allowlisted passive tools")
    p.add_argument("--tools", default="tools.yaml", metavar="FILE",
                   help="tool registry file (default: tools.yaml)")
    p.add_argument("--out", metavar="DIR",
                   help="run-artifact dir (default: engagements/<slug>/runs/passive_recon/)")
    return p


def _print_summary(scope, force_safe_mode: bool) -> None:
    eng = scope.engagement
    eff = scope.limits.effective(force_safe_mode=force_safe_mode)
    print(f"Active engagement : {eng.name}")
    print(f"  program         : {eng.program_url}  [{eng.platform}]")
    print(f"  authorized by   : {eng.authorized_by} on {eng.authorized_date}")
    print(f"  in-scope        : {len(scope.in_scope_domains)} domains, "
          f"{len(scope.in_scope_cidrs)} CIDRs")
    labels = (len(scope.out_of_scope_host_label_contains)
              + len(scope.out_of_scope_host_label_equals))
    label_note = f", {labels} label rules" if labels else ""
    print(f"  out-of-scope    : {len(scope.out_of_scope_domains)} domains, "
          f"{len(scope.out_of_scope_cidrs)} CIDRs{label_note}")
    print(f"  effective limits: {eff.max_rps_per_host} rps/host, "
          f"concurrency {eff.max_global_concurrency}"
          f"{'  (safe_mode)' if eff.safe_mode else ''}")
    print(f"  allowed tools   : {len(scope.allowed_tools)}")
    http = scope.http
    if http.user_agent or http.require_user_agent or http.no_third_party_oob \
            or http.drop_on_redirect_to:
        ua = "set" if http.user_agent_is_valid() else "MISSING/placeholder"
        if http.require_user_agent and not http.user_agent_is_valid():
            ua += " — active tools WILL BE REFUSED"
        print(f"  http policy     : UA {ua}"
              f"{' (required)' if http.require_user_agent else ''}; "
              f"third-party OOB {'disabled' if http.no_third_party_oob else 'allowed'}; "
              f"drop-on-redirect {len(http.drop_on_redirect_to)}")


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def _run_passive(scope, args) -> int:
    # Imported here so `--list` / plain selection don't pull in the heavier deps.
    from .audit_log import AuditLog
    from .config import load_tools
    from .runner import GuardedRunner
    from .stages import PassiveReconStage
    from .store import Store

    registry = load_tools(args.tools)
    slug = _slug(scope.engagement.name)
    eng_base = Path(args.engagements_dir) / slug
    out = Path(args.out) if args.out else eng_base / "runs" / "passive_recon"
    audit = AuditLog(eng_base / "audit.jsonl", engagement=scope.engagement.name)
    store = Store.open_for_engagement(scope.engagement.name, base_dir=args.engagements_dir)
    runner = GuardedRunner(scope, registry, audit, force_safe_mode=args.safe_mode)
    only = args.only.split(",") if args.only else None
    try:
        stage = PassiveReconStage(scope, registry, store, audit, runner, out, only=only)
    except ValueError as e:
        store.close()
        print(f"error: {e}", file=sys.stderr)
        return 2

    print(f"\nRunning passive_recon ({', '.join(stage.tools)}) on "
          f"{len(stage.enumeration_roots())} roots"
          f"{' [DRY RUN]' if args.dry_run else ''} ...\n")
    result = stage.run(dry_run=args.dry_run)
    print(result.summary_text())
    if not args.dry_run:
        print(f"\nAudit log: {audit.path}\nDatabase : {store.path}")
    store.close()
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.list:
            names = list_engagements(args.engagements_dir)
            if names:
                print("Available engagements:")
                for n in names:
                    print(f"  - {n}")
            else:
                print(f"No engagements found in {args.engagements_dir}/.")
            return 0

        if not args.engagement:
            print("error: --engagement NAME is required (or use --list)", file=sys.stderr)
            return 2

        scope = load_engagement(args.engagement, args.engagements_dir)
        _print_summary(scope, args.safe_mode)
        if args.run_passive:
            return _run_passive(scope, args)
        return 0
    except ReconPilotError as e:
        # Fail-closed: a bad/missing/malformed engagement is an error, not a
        # fallback to some default scope.
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
