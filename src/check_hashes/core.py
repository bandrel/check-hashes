"""Core hash-checking logic.

Standalone module — no external dependencies beyond the standard library.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

BLANK_LM = "aad3b435b51404eeaad3b435b51404ee"
BLANK_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"

_STATUS_RE = re.compile(r"\(status=(\w+)\)")
_HASH_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)


@dataclass(frozen=True)
class NtdsEntry:
    full_account: str  # DOMAIN\user
    rid: str
    lm_hash: str
    nt_hash: str
    status: str  # "Enabled" or "Disabled"

    @property
    def username(self) -> str:
        return self.full_account.split("\\")[1] if "\\" in self.full_account else self.full_account

    @property
    def is_enabled(self) -> bool:
        return self.status == "Enabled"

    @property
    def is_disabled(self) -> bool:
        return self.status == "Disabled"

    @property
    def has_blank_nt(self) -> bool:
        return self.nt_hash == BLANK_NT

    @property
    def is_computer(self) -> bool:
        return self.username.endswith("$")


def _read_text(path: Path) -> str:
    """Read a text file, trying UTF-8 first then falling back to latin-1."""
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def parse_ntds(path: Path) -> list[NtdsEntry]:
    """Parse a pwdump/secretsdump .ntds file into NtdsEntry objects.

    Deduplicates by account name (case-insensitive), keeping the first
    occurrence of each account.
    """
    seen: set[str] = set()
    entries = []
    text = _read_text(path)
    for line in text.strip().split("\n"):
        if not line.strip():
            continue
        m = _STATUS_RE.search(line)
        status = m.group(1) if m else "Enabled"
        core = line.split(" (status=")[0] if " (status=" in line else line
        parts = core.split(":")
        if len(parts) < 4:
            continue
        if not _HASH_RE.match(parts[2]) or not _HASH_RE.match(parts[3]):
            continue
        key = parts[0].lower()
        if key in seen:
            continue
        seen.add(key)
        entries.append(
            NtdsEntry(
                full_account=parts[0],
                rid=parts[1],
                lm_hash=parts[2].lower(),
                nt_hash=parts[3].lower(),
                status=status,
            )
        )
    return entries


def _extract_username(full_account: str) -> str:
    return full_account.split("\\")[1] if "\\" in full_account else full_account


_SEPARATORS = {"-", "_", "."}
_MAX_AFFIX_NO_SEP = 2  # e.g. jsmith -> jsmitha, ajsmith
_MAX_AFFIX_WITH_SEP = 6  # e.g. jsmith -> jsmith-admin, adm-jsmith


def is_username_variant(name_a: str, name_b: str) -> bool:
    """Check if two usernames look like variants of the same person.

    The base username must be the longer portion.  The added prefix/suffix
    is allowed up to 2 chars without a separator, or up to 6 chars if it
    starts with a separator (-, _, .).
    """
    a = name_a.lower()
    b = name_b.lower()
    if a == b:
        return False
    short, long = (a, b) if len(a) <= len(b) else (b, a)
    if len(short) < 3:
        return False
    diff = len(long) - len(short)
    if diff < 1:
        return False
    # Check suffix: long starts with short, affix is what follows
    if long.startswith(short):
        affix = long[len(short) :]
        if affix[0] in _SEPARATORS:
            return len(affix) <= _MAX_AFFIX_WITH_SEP
        # No separator — reject if affix is digits continuing a numeric ending
        if affix[0].isdigit() and short[-1].isdigit():
            return False
        return len(affix) <= _MAX_AFFIX_NO_SEP
    # Check prefix: long ends with short, affix is what precedes
    if long.endswith(short):
        affix = long[: len(long) - len(short)]
        if affix[-1] in _SEPARATORS:
            return len(affix) <= _MAX_AFFIX_WITH_SEP
        # No separator — reject if affix is digits continuing a numeric start
        if affix[-1].isdigit() and short[0].isdigit():
            return False
        return len(affix) <= _MAX_AFFIX_NO_SEP
    return False


def group_by_hash(
    entries: list[NtdsEntry],
    skip_disabled: bool = True,
    skip_blank: bool = True,
    skip_computers: bool = True,
) -> dict[str, list[str]]:
    """Group accounts by NT hash.

    Returns a dict mapping NT hash -> list of full_account strings.
    Only includes hashes shared by 2+ accounts.
    """
    nt_to_accounts: dict[str, dict[str, str]] = {}
    for e in entries:
        if skip_disabled and e.is_disabled:
            continue
        if skip_blank and e.has_blank_nt:
            continue
        if skip_computers and e.is_computer:
            continue
        bucket = nt_to_accounts.setdefault(e.nt_hash, {})
        key = e.full_account.lower()
        if key not in bucket:
            bucket[key] = e.full_account
    return {h: sorted(accts.values(), key=str.lower) for h, accts in nt_to_accounts.items() if len(accts) > 1}


def find_admin_shared_hashes(
    entries: list[NtdsEntry],
    admin_accounts: list[str],
) -> list[tuple[list[str], list[str]]]:
    """Find hash groups where at least one admin shares a hash with non-admins.

    admin_accounts can be full accounts (DOMAIN\\user) or just usernames.
    Returns list of (admins_with_hash, non_admins_with_hash) tuples.
    """
    admin_set = {a.lower() for a in admin_accounts}
    groups = group_by_hash(entries)
    results = []
    for nt_hash, accounts in sorted(groups.items(), key=lambda x: len(x[1])):
        admins = []
        non_admins = []
        for acct in accounts:
            if acct.lower() in admin_set or _extract_username(acct).lower() in admin_set:
                admins.append(acct)
            else:
                non_admins.append(acct)
        if admins and non_admins:
            results.append((sorted(admins), sorted(non_admins)))
    return results


def find_common_pairs(
    entries: list[NtdsEntry],
) -> list[tuple[str, str]]:
    """Find all account pairs that share a hash and have variant usernames.

    No admin filter — returns every (account_a, account_b) pair where the
    accounts share an NT hash and one username is a prefix/suffix of the other.
    """
    groups = group_by_hash(entries)
    pairs = []
    for nt_hash, accounts in groups.items():
        for i, acct_a in enumerate(accounts):
            name_a = _extract_username(acct_a)
            for acct_b in accounts[i + 1 :]:
                name_b = _extract_username(acct_b)
                if is_username_variant(name_a, name_b):
                    pairs.append((acct_a, acct_b))
    return sorted(pairs)


def find_bsp_pairs(
    entries: list[NtdsEntry],
    admin_accounts: list[str],
) -> list[tuple[str, str]]:
    """Find Broken Separation of Privilege pairs.

    admin_accounts can be full accounts (DOMAIN\\user) or just usernames.
    Returns (admin, non_admin) tuples where the accounts share a hash
    and the usernames are variants of each other.
    """
    admin_set = {a.lower() for a in admin_accounts}
    groups = group_by_hash(entries)
    pairs = []
    for nt_hash, accounts in groups.items():
        admins = [a for a in accounts if a.lower() in admin_set or _extract_username(a).lower() in admin_set]
        non_admins = [
            a for a in accounts if a.lower() not in admin_set and _extract_username(a).lower() not in admin_set
        ]
        if admins and non_admins:
            for admin in admins:
                admin_name = _extract_username(admin)
                for non_admin in non_admins:
                    non_admin_name = _extract_username(non_admin)
                    if is_username_variant(admin_name, non_admin_name):
                        pairs.append((admin, non_admin))
    return sorted(pairs)


def _cn_from_dn(dn: str) -> str:
    """Extract the first CN value from a distinguished name."""
    for part in dn.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:]
    return ""


_PRIVILEGED_GROUPS = {
    "domain admins",
    "enterprise admins",
    "administrators",
    "schema admins",
}


def _get_attr(attrs: dict, key: str, default: str = "") -> str:
    """Extract a single-valued attribute from ldapdomaindump JSON."""
    val = attrs.get(key, default)
    if isinstance(val, list):
        return val[0] if val else default
    return val


def _get_attr_list(attrs: dict, key: str) -> list[str]:
    """Extract a multi-valued attribute from ldapdomaindump JSON."""
    val = attrs.get(key, [])
    if isinstance(val, str):
        return [val]
    return val


def parse_ldap_admins(ldap_dir: Path) -> list[str]:
    """Parse ldapdomaindump output to find privileged usernames.

    Reads domain_groups.json to identify privileged groups (standard names
    plus any group with "admin" in CN or description) and resolves nested
    group membership transitively.  Maps member DNs to sAMAccountNames
    via domain_users.json.

    Falls back to checking memberOf on user objects when domain_groups.json
    is absent.

    Returns sorted, deduplicated list of sAMAccountName values.
    """
    groups_file = ldap_dir / "domain_groups.json"
    users_file = ldap_dir / "domain_users.json"

    if not users_file.exists():
        return []

    users_data = json.loads(_read_text(users_file))

    # Build DN -> sAMAccountName mapping from users
    dn_to_sam: dict[str, str] = {}
    for u in users_data:
        attrs = u.get("attributes", {})
        dn = _get_attr(attrs, "distinguishedName")
        sam = _get_attr(attrs, "sAMAccountName")
        if dn and sam:
            dn_to_sam[dn.lower()] = sam

    admins: set[str] = set()

    if groups_file.exists():
        groups_data = json.loads(_read_text(groups_file))

        # Index groups: DN -> members, and identify privileged groups
        group_dns: set[str] = set()
        group_members: dict[str, list[str]] = {}
        privileged_dns: set[str] = set()

        for g in groups_data:
            attrs = g.get("attributes", {})
            dn = _get_attr(attrs, "distinguishedName")
            if not dn:
                continue
            dn_lower = dn.lower()
            group_dns.add(dn_lower)

            members = _get_attr_list(attrs, "member")
            group_members[dn_lower] = [m.lower() for m in members]

            cn = _get_attr(attrs, "cn")
            description = _get_attr(attrs, "description")

            if cn.lower() in _PRIVILEGED_GROUPS or "admin" in cn.lower() or "admin" in description.lower():
                privileged_dns.add(dn_lower)

        # Resolve nested groups — BFS downward from privileged groups
        queue = list(privileged_dns)
        visited: set[str] = set()
        while queue:
            current = queue.pop()
            if current in visited:
                continue
            visited.add(current)
            for member_dn in group_members.get(current, []):
                if member_dn in group_dns and member_dn not in privileged_dns:
                    privileged_dns.add(member_dn)
                    queue.append(member_dn)

        # Collect non-group members of all privileged groups
        for priv_dn in privileged_dns:
            for member_dn in group_members.get(priv_dn, []):
                if member_dn not in group_dns:
                    sam = dn_to_sam.get(member_dn)
                    if sam:
                        admins.add(sam)

        # Also check user memberOf for robustness
        for u in users_data:
            attrs = u.get("attributes", {})
            member_of = _get_attr_list(attrs, "memberOf")
            for group_dn in member_of:
                if group_dn.lower() in privileged_dns:
                    sam = _get_attr(attrs, "sAMAccountName")
                    if sam:
                        admins.add(sam)
                    break
    else:
        # Fallback: no groups file — check memberOf against known names
        for u in users_data:
            attrs = u.get("attributes", {})
            member_of = _get_attr_list(attrs, "memberOf")
            for group_dn in member_of:
                cn = _cn_from_dn(group_dn).lower()
                if cn in _PRIVILEGED_GROUPS or "admin" in cn:
                    sam = _get_attr(attrs, "sAMAccountName")
                    if sam:
                        admins.add(sam)
                    break

    return sorted(admins)


def build_admin_list(
    entries: list[NtdsEntry],
    prefix: str | None = None,
    suffix: str | None = None,
    regex: str | None = None,
    admin_file: Path | None = None,
    ldap_dir: Path | None = None,
) -> list[str]:
    """Build list of admin accounts from filters.

    Matches full_account (DOMAIN\\user) against the given filters.
    """
    admin_accounts: list[str] = []

    if admin_file and admin_file.exists():
        file_names = [line.strip() for line in admin_file.read_text().strip().split("\n") if line.strip()]
        pattern = re.compile(
            r"^((.*\\)?(" + "|".join(re.escape(n) for n in file_names) + r"))$",
            re.IGNORECASE,
        )
        for e in entries:
            if pattern.match(e.full_account):
                admin_accounts.append(e.full_account)

    if prefix:
        pat = re.compile(r"^((.*\\)?" + re.escape(prefix) + r".+)$", re.IGNORECASE)
        for e in entries:
            if pat.match(e.full_account):
                admin_accounts.append(e.full_account)

    if suffix:
        pat = re.compile(r"^(.+" + re.escape(suffix) + r")$", re.IGNORECASE)
        for e in entries:
            if pat.match(e.full_account):
                admin_accounts.append(e.full_account)

    if regex:
        pat = re.compile(r"^(" + regex.strip("'") + r")$", re.IGNORECASE)
        for e in entries:
            if pat.match(e.full_account):
                admin_accounts.append(e.full_account)

    if ldap_dir:
        ldap_names = parse_ldap_admins(ldap_dir)
        if ldap_names:
            pattern = re.compile(
                r"^((.*\\)?(" + "|".join(re.escape(n) for n in ldap_names) + r"))$",
                re.IGNORECASE,
            )
            for e in entries:
                if pattern.match(e.full_account):
                    admin_accounts.append(e.full_account)

    return sorted(set(admin_accounts))
