"""CLI entry point for check-hashes."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from check_hashes.core import (
    NtdsEntry,
    build_admin_list,
    find_admin_shared_hashes,
    find_bsp_pairs,
    find_common_pairs,
    group_by_hash,
    parse_ntds,
)

BANNER = r"""
       __              __      __               __
  ____/ /_  ___  _____/ /__   / /_  ____ ______/ /_  ___  _____
 / __/ __ \/ _ \/ ___/ //_/  / __ \/ __ `/ ___/ __ \/ _ \/ ___/
/ /_/ / / /  __/ /__/ ,<    / / / / /_/ (__  ) / / /  __(__  )
\__/_/ /_/\___/\___/_/|_|  /_/ /_/\__,_/____/_/ /_/\___/____/
"""


def _discover_ntds_files(root: Path) -> list[tuple[str, Path]]:
    """Find .ntds files under root directory.

    Looks for <root>/<domain>/*.ntds
    Returns list of (domain_name, ntds_path) tuples.
    """
    results = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        ntds_files = list(entry.glob("*.ntds"))
        # Exclude .ntds.out and .ntds.cleartext
        ntds_files = [f for f in ntds_files if f.suffix == ".ntds"]
        if ntds_files:
            results.append((entry.name, ntds_files[0]))
    return results


def _run_single(
    entries: list[NtdsEntry],
    args: argparse.Namespace,
    label: str = "",
) -> None:
    """Run hash check on a single set of entries."""
    # Pre-filter entries based on CLI flags
    if not args.include_disabled:
        entries = [e for e in entries if not e.is_disabled]
    if not args.include_computers:
        entries = [e for e in entries if not e.is_computer]

    has_admin_filter = any([args.prefix, args.suffix, args.regex, args.file, args.ldap])
    admin_file = Path(args.file) if args.file else None
    ldap_dir = Path(args.ldap) if args.ldap else None

    if args.common:
        if has_admin_filter:
            admin_accounts = build_admin_list(
                entries,
                prefix=args.prefix,
                suffix=args.suffix,
                regex=args.regex,
                admin_file=admin_file,
                ldap_dir=ldap_dir,
            )
            pairs = find_bsp_pairs(entries, admin_accounts)
        else:
            pairs = find_common_pairs(entries)
        for admin, non_admin in pairs:
            print(f"{admin},{non_admin}")
    elif has_admin_filter:
        admin_accounts = build_admin_list(
            entries,
            prefix=args.prefix,
            suffix=args.suffix,
            regex=args.regex,
            admin_file=admin_file,
            ldap_dir=ldap_dir,
        )
        results = find_admin_shared_hashes(entries, admin_accounts)
        for admins, non_admins in results:
            for acct in admins + non_admins:
                print(acct)
            print()
    else:
        groups = group_by_hash(entries)
        for nt_hash, accounts in sorted(groups.items(), key=lambda x: len(x[1])):
            for acct in sorted(accounts):
                print(acct)
            print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check user hashes against each other to find users that share passwords"
    )
    parser.add_argument("target", help="Pwdump file or root directory containing <domain>/*.ntds")
    parser.add_argument("--prefix", "--pre", help="Filter admin accounts by username prefix")
    parser.add_argument("--suffix", "--post", help="Filter admin accounts by username suffix")
    parser.add_argument("--regex", help="Regex filter for admin accounts")
    parser.add_argument("--file", help="File containing a list of admin usernames")
    parser.add_argument(
        "--ldap",
        nargs="?",
        const=".",
        default=None,
        help="Path to ldapdomaindump output folder (default: cwd if flag given without argument)",
    )
    parser.add_argument(
        "--common", action="store_true", help="Only show pairs where usernames are variants of each other"
    )
    parser.add_argument("--cross-domain", action="store_true", help="Also check for shared hashes across all domains")
    parser.add_argument(
        "--include-disabled", action="store_true", help="Include disabled accounts (excluded by default)"
    )
    parser.add_argument(
        "--include-computers", action="store_true", help="Include machine/computer accounts (excluded by default)"
    )

    args = parser.parse_args()
    print(BANNER, file=sys.stderr)

    target = Path(args.target)
    if not target.exists():
        print(f"Error: not found: {target}", file=sys.stderr)
        sys.exit(1)

    if target.is_file():
        # Single file mode
        entries = parse_ntds(target)
        if not entries:
            print("No valid entries found in pwdump file", file=sys.stderr)
            sys.exit(1)
        _run_single(entries, args)
    else:
        # Directory mode — discover domains
        domains = _discover_ntds_files(target)
        if not domains:
            print(f"No .ntds files found under {target}/*/", file=sys.stderr)
            sys.exit(1)

        all_entries: list[NtdsEntry] = []
        for domain_name, ntds_path in domains:
            entries = parse_ntds(ntds_path)
            if not entries:
                print(f"[!] {domain_name}: no valid entries in {ntds_path}", file=sys.stderr)
                continue
            print(f"[*] {domain_name} ({len(entries)} entries)")
            _run_single(entries, args)
            all_entries.extend(entries)

        if args.cross_domain and len(domains) > 1:
            print(f"\n[*] Cross-domain check ({len(all_entries)} total entries)")
            _run_single(all_entries, args)


if __name__ == "__main__":
    main()
