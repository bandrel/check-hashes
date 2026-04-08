#!/usr/bin/env python3
"""Generate realistic test data for check-hashes testing.

Creates multi-domain test data with NTDS pwdump files and ldapdomaindump
JSON output, covering shared hashes, BSP scenarios, nested groups, and
cross-domain password reuse.

Adapted from password-audit/generate_test_data.py.
"""

import json
import os
import random
import string
import struct

BLANK_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"
BLANK_LM = "aad3b435b51404eeaad3b435b51404ee"

# Per-domain name pools — each domain draws from a different dystopian universe

# 1984 / George Orwell
OCEANIA_FIRST = [
    "winston",
    "julia",
    "emmanuel",
    "tom",
    "katherine",
    "martin",
    "tillotson",
    "ampleforth",
    "comrade",
    "eric",
    "clement",
    "rosemary",
    "gordon",
    "hilda",
    "dorothy",
    "flory",
    "elizabeth",
    "george",
    "benjamin",
    "clover",
    "boxer",
    "mollie",
    "muriel",
    "squealer",
    "snowball",
    "pilkington",
    "frederick",
]
OCEANIA_LAST = [
    "smith",
    "goldstein",
    "obrien",
    "parsons",
    "charrington",
    "syme",
    "withers",
    "ogilvy",
    "rutherford",
    "aaronson",
    "jones",
    "bumstead",
    "wilsher",
    "blair",
    "comstock",
    "bowling",
    "hare",
    "lackersteen",
    "veraswami",
    "orwell",
    "napoleon",
    "whymper",
    "minimus",
    "foxwood",
    "pinchfield",
    "manor",
]

# Brave New World / Aldous Huxley
WORLDSTATE_FIRST = [
    "bernard",
    "lenina",
    "helmholtz",
    "mustapha",
    "john",
    "fanny",
    "henry",
    "thomas",
    "linda",
    "darwin",
    "benito",
    "morgana",
    "polly",
    "joanna",
    "clara",
    "george",
    "herbert",
    "aldous",
    "arch",
    "primo",
    "popé",
    "sigmund",
    "herbert",
    "sarojini",
    "reuben",
    "mordecai",
    "miss",
]
WORLDSTATE_LAST = [
    "marx",
    "crowne",
    "watson",
    "mond",
    "savage",
    "foster",
    "bonaparte",
    "engels",
    "trotsky",
    "bakunin",
    "lenin",
    "hoover",
    "rothschild",
    "diesel",
    "bradlaugh",
    "mellon",
    "morgana",
    "kipling",
    "shaw",
    "wells",
    "huxley",
    "pfitzner",
    "kawaguchi",
    "katsura",
    "keate",
]

# The Handmaid's Tale / Margaret Atwood
GILEAD_FIRST = [
    "june",
    "fred",
    "serena",
    "nick",
    "moira",
    "emily",
    "lydia",
    "janine",
    "luke",
    "alma",
    "rita",
    "cora",
    "glen",
    "warren",
    "naomi",
    "eleanor",
    "agnes",
    "daisy",
    "nicole",
    "lillie",
    "brianna",
    "becka",
    "aunt",
    "mark",
    "ruth",
    "dolores",
    "victoria",
    "adrianna",
    "beth",
    "iris",
]
GILEAD_LAST = [
    "osborne",
    "waterford",
    "blaine",
    "bankole",
    "mayday",
    "warren",
    "putnam",
    "lawrence",
    "pryce",
    "winslow",
    "staunton",
    "wheeler",
    "mackenzie",
    "tuello",
    "castillo",
    "montei",
    "limpkin",
    "judd",
    "calhoun",
    "delaney",
    "keys",
    "baker",
    "fuller",
    "flores",
    "gordon",
]


# ---------------------------------------------------------------------------
# MD4 / NTLM hashing (pure Python, from password-audit)
# ---------------------------------------------------------------------------


def _md4(data: bytes) -> bytes:
    """Pure Python MD4 - RFC 1320."""

    def _f(x, y, z):
        return (x & y) | (~x & z)

    def _g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def _h(x, y, z):
        return x ^ y ^ z

    def _left_rotate(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    msg = bytearray(data)
    orig_len = len(msg)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len * 8)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for i in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[i : i + 64]))
        aa, bb, cc, dd = a, b, c, d

        for k, s in [
            (0, 3),
            (1, 7),
            (2, 11),
            (3, 19),
            (4, 3),
            (5, 7),
            (6, 11),
            (7, 19),
            (8, 3),
            (9, 7),
            (10, 11),
            (11, 19),
            (12, 3),
            (13, 7),
            (14, 11),
            (15, 19),
        ]:
            a = _left_rotate((a + _f(b, c, d) + x[k]) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        for k, s in [
            (0, 3),
            (4, 5),
            (8, 9),
            (12, 13),
            (1, 3),
            (5, 5),
            (9, 9),
            (13, 13),
            (2, 3),
            (6, 5),
            (10, 9),
            (14, 13),
            (3, 3),
            (7, 5),
            (11, 9),
            (15, 13),
        ]:
            a = _left_rotate((a + _g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        for k, s in [
            (0, 3),
            (8, 9),
            (4, 11),
            (12, 15),
            (2, 3),
            (10, 9),
            (6, 11),
            (14, 15),
            (1, 3),
            (9, 9),
            (5, 11),
            (13, 15),
            (3, 3),
            (11, 9),
            (7, 11),
            (15, 15),
        ]:
            a = _left_rotate((a + _h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d)


def ntlm_hash(password: str) -> str:
    return _md4(password.encode("utf-16-le")).hex()


def unique_hash() -> str:
    return ntlm_hash("".join(random.choices(string.ascii_letters + string.digits, k=16)))


def generate_username(first_names: list[str], last_names: list[str]) -> str:
    first = random.choice(first_names)
    last = random.choice(last_names)
    style = random.choice(["fl", "f.l", "first.last"])
    if style == "fl":
        return f"{first[0]}{last}"
    elif style == "f.l":
        return f"{first[0]}.{last}"
    else:
        return f"{first}.{last}"


# ---------------------------------------------------------------------------
# Domain generation
# ---------------------------------------------------------------------------


def generate_domain(domain: str, config: dict) -> dict:
    """Generate a full domain dataset. Returns dict with all generated data."""
    # Generate unique usernames
    seen: set[str] = set()
    regular_users: list[str] = []

    # Reserve named accounts
    da_accounts = config.get("da_accounts", [])
    ea_accounts = config.get("ea_accounts", [])
    svc_accounts = config.get("svc_accounts", [])
    bsp_pairs = config.get("bsp_pairs", [])  # list of (admin_name, regular_name) tuples

    for name in da_accounts + ea_accounts + svc_accounts:
        seen.add(name)
    for admin_name, reg_name in bsp_pairs:
        seen.add(admin_name)
        seen.add(reg_name)

    first_names = config.get("first_names", OCEANIA_FIRST)
    last_names = config.get("last_names", OCEANIA_LAST)

    user_count = config.get("user_count", 50)
    while len(regular_users) + len(seen) < user_count:
        uname = generate_username(first_names, last_names)
        if uname not in seen:
            seen.add(uname)
            regular_users.append(uname)

    # Assign hashes
    shared_hash = ntlm_hash("Summer2025")
    bsp_hash = ntlm_hash("SharedAdmin1!")
    cross_domain_hash = config.get("cross_domain_hash")

    account_hashes: dict[str, str] = {}

    # BSP pairs share the same hash
    for admin_name, reg_name in bsp_pairs:
        account_hashes[admin_name] = bsp_hash
        account_hashes[reg_name] = bsp_hash

    # Some regular users share a password
    shared_users = config.get("shared_password_users", [])
    for u in shared_users:
        account_hashes[u] = shared_hash

    # Cross-domain hash users
    for u in config.get("cross_domain_users", []):
        if cross_domain_hash:
            account_hashes[u] = cross_domain_hash

    # Extra named accounts (e.g. nested group members that must exist in NTDS)
    extra_accounts = config.get("extra_accounts", [])
    # Give nested group members a shared hash so they're visible in output
    nested_hash = ntlm_hash("NestedGroupPassword!")
    for acct in extra_accounts:
        if acct not in seen:
            seen.add(acct)
        if acct not in account_hashes:
            account_hashes[acct] = nested_hash

    # DA/EA/svc get unique hashes unless in BSP pairs or cross-domain
    for acct in da_accounts + ea_accounts + svc_accounts:
        if acct not in account_hashes:
            account_hashes[acct] = unique_hash()

    # Regular users get unique hashes unless already assigned
    for acct in regular_users:
        if acct not in account_hashes:
            account_hashes[acct] = unique_hash()

    # Disabled accounts
    disabled = set(config.get("disabled_accounts", []))

    # Build all accounts list (ordered)
    all_accounts = da_accounts + ea_accounts + svc_accounts
    for admin_name, reg_name in bsp_pairs:
        if admin_name not in all_accounts:
            all_accounts.append(admin_name)
        if reg_name not in all_accounts:
            all_accounts.append(reg_name)
    for u in shared_users:
        if u not in all_accounts:
            all_accounts.append(u)
    for u in config.get("cross_domain_users", []):
        if u not in all_accounts:
            all_accounts.append(u)
    for u in extra_accounts:
        if u not in all_accounts:
            all_accounts.append(u)
    for u in regular_users:
        if u not in all_accounts:
            all_accounts.append(u)

    # Add blank hash account if configured
    blank_accounts = config.get("blank_accounts", [])
    for acct in blank_accounts:
        if acct not in all_accounts:
            all_accounts.append(acct)
        account_hashes[acct] = BLANK_NT

    # Computer accounts
    computer_count = config.get("computer_count", 10)
    computers = [f"WS{i:03d}$" for i in range(computer_count)]

    # --- Generate NTDS pwdump lines ---
    ntds_lines = []
    rid = 1000
    for acct in all_accounts:
        rid += 1
        nt = account_hashes.get(acct, unique_hash())
        status = "Disabled" if acct in disabled else "Enabled"
        ntds_lines.append(f"{domain}\\{acct}:{rid}:{BLANK_LM}:{nt}::: (status={status})")

    for comp in computers:
        rid += 1
        ntds_lines.append(f"{domain}\\{comp}:{rid}:{BLANK_LM}:{unique_hash()}::: (status=Enabled)")

    # --- Generate ldapdomaindump JSON ---
    # Nested groups config
    nested_groups = config.get("nested_groups", [])  # list of {name, description, members, parent}

    groups_json = []
    group_membership: dict[str, list[str]] = {}  # group DN -> member DNs

    # Domain Admins (da_accounts + any extra_da_members for cross-domain scenarios)
    extra_da = config.get("extra_da_members", [])
    da_dn = f"CN=Domain Admins,CN=Users,DC={domain},DC=local"
    da_members = [f"CN={a},CN=Users,DC={domain},DC=local" for a in da_accounts + extra_da]
    groups_json.append(
        {
            "attributes": {
                "cn": "Domain Admins",
                "distinguishedName": da_dn,
                "description": "Designated administrators of the domain",
                "member": da_members,
            }
        }
    )
    group_membership[da_dn] = da_members

    # Enterprise Admins
    ea_dn = f"CN=Enterprise Admins,CN=Users,DC={domain},DC=local"
    ea_members = [f"CN={a},CN=Users,DC={domain},DC=local" for a in ea_accounts]
    groups_json.append(
        {
            "attributes": {
                "cn": "Enterprise Admins",
                "distinguishedName": ea_dn,
                "description": "Designated administrators of the enterprise",
                "member": ea_members,
            }
        }
    )
    group_membership[ea_dn] = ea_members

    # Server Admins (dynamic — has "admin" in name)
    svc_admin_accounts = [a for a, _ in bsp_pairs]
    sa_dn = f"CN=Server Admins,CN=Users,DC={domain},DC=local"
    sa_members = [f"CN={a},CN=Users,DC={domain},DC=local" for a in svc_admin_accounts]
    groups_json.append(
        {
            "attributes": {
                "cn": "Server Admins",
                "distinguishedName": sa_dn,
                "description": "Server administration group",
                "member": sa_members,
            }
        }
    )
    group_membership[sa_dn] = sa_members

    # Nested groups
    for ng in nested_groups:
        ng_dn = f"CN={ng['name']},CN=Users,DC={domain},DC=local"
        ng_members = [f"CN={m},CN=Users,DC={domain},DC=local" for m in ng["members"]]
        groups_json.append(
            {
                "attributes": {
                    "cn": ng["name"],
                    "distinguishedName": ng_dn,
                    "description": ng.get("description", ""),
                    "member": ng_members,
                }
            }
        )
        # Add nested group as member of parent
        if ng.get("parent"):
            parent_dn = f"CN={ng['parent']},CN=Users,DC={domain},DC=local"
            for g in groups_json:
                if g["attributes"]["distinguishedName"] == parent_dn:
                    g["attributes"]["member"].append(ng_dn)
                    break

    # Non-admin groups
    for gname in ["Domain Users", "IT Staff", "Service Accounts"]:
        g_dn = f"CN={gname},CN=Users,DC={domain},DC=local"
        groups_json.append(
            {
                "attributes": {
                    "cn": gname,
                    "distinguishedName": g_dn,
                    "description": f"{gname} group",
                    "member": [],
                }
            }
        )

    # Build user memberOf from group membership
    user_member_of: dict[str, list[str]] = {}
    for g in groups_json:
        g_dn = g["attributes"]["distinguishedName"]
        for member_dn in g["attributes"]["member"]:
            user_member_of.setdefault(member_dn, []).append(g_dn)

    # Users JSON
    users_json = []
    for acct in all_accounts:
        user_dn = f"CN={acct},CN=Users,DC={domain},DC=local"
        users_json.append(
            {
                "attributes": {
                    "sAMAccountName": acct,
                    "distinguishedName": user_dn,
                    "memberOf": user_member_of.get(user_dn, []),
                }
            }
        )

    return {
        "ntds": "\n".join(ntds_lines) + "\n",
        "domain_users_json": users_json,
        "domain_groups_json": groups_json,
        "stats": {
            "users": len(all_accounts),
            "computers": computer_count,
            "da": len(da_accounts),
            "ea": len(ea_accounts),
            "bsp_pairs": len(bsp_pairs),
        },
    }


def write_domain(base_dir: str, domain: str, data: dict) -> None:
    """Write domain data to the directory convention."""
    domain_dir = os.path.join(base_dir, domain)
    os.makedirs(domain_dir, exist_ok=True)

    # NTDS file — directly under domain dir
    with open(os.path.join(domain_dir, f"{domain}.ntds"), "w") as f:
        f.write(data["ntds"])

    # ldapdomaindump JSON — directly under domain dir
    with open(os.path.join(domain_dir, "domain_users.json"), "w") as f:
        json.dump(data["domain_users_json"], f, indent=2)

    with open(os.path.join(domain_dir, "domain_groups.json"), "w") as f:
        json.dump(data["domain_groups_json"], f, indent=2)

    s = data["stats"]
    print(
        f"  [{domain}] {s['users']} users, {s['computers']} computers, "
        f"{s['da']} DA, {s['ea']} EA, {s['bsp_pairs']} BSP pairs"
    )


def main():
    random.seed(42)
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")
    os.makedirs(base_dir, exist_ok=True)

    print("Generating dystopian test data for check-hashes...\n")

    # Shared hash for cross-domain testing (same password used across domains)
    cross_domain_hash = ntlm_hash("BigBrotherIsWatching!")

    # --- OCEANIA: 1984 / George Orwell ---
    # Main domain exercising all features: shared hashes, BSP, nested groups,
    # deep nesting, description-based admin detection, cross-domain admin overlap
    oceania = generate_domain(
        "OCEANIA",
        {
            "first_names": OCEANIA_FIRST,
            "last_names": OCEANIA_LAST,
            "user_count": 80,
            "computer_count": 15,
            "da_accounts": ["obrien", "charrington", "inner.party1"],
            "ea_accounts": ["bigbrother", "thought.police1"],
            "svc_accounts": ["svc_telescreen", "svc_speakwrite", "svc_memoryhole"],
            "bsp_pairs": [
                ("wsmith-admin", "wsmith"),  # suffix variant BSP
                ("admin-goldstein", "goldstein"),  # prefix variant BSP
                ("parsons.da", "parsons"),  # suffix variant BSP
            ],
            "shared_password_users": ["syme", "ampleforth", "tillotson"],
            "blank_accounts": ["blank.prole1", "blank.prole2"],
            "disabled_accounts": ["blank.prole2", "syme"],  # Syme was vaporized
            # winston.smith is also a DA — tests cross-domain admin/non-admin mix
            "extra_da_members": ["winston.smith"],
            "cross_domain_users": ["winston.smith", "julia.obrien"],
            "cross_domain_hash": cross_domain_hash,
            "nested_groups": [
                # Level 1: Thought Police Ops is a member of Domain Admins
                {
                    "name": "Thought Police Ops",
                    "description": "Inner party operations division",
                    "members": ["thinkpol.agent1", "thinkpol.agent2"],
                    "parent": "Domain Admins",
                },
                # Level 2: deep nesting — Room 101 Staff nested inside Thought Police Ops
                {
                    "name": "Room 101 Staff",
                    "description": "Interrogation specialists",
                    "members": ["room101.operator1"],
                    "parent": "Thought Police Ops",
                },
                # Description-only admin group: "admin" in description but NOT in name
                {
                    "name": "Minitrue Ops",
                    "description": "Ministry of Truth admin operations team",
                    "members": ["minitrue.editor1"],
                    "parent": None,
                },
            ],
            # Extra named accounts that are members of nested groups
            # (these must exist in NTDS and users JSON for resolution to work)
            "extra_accounts": [
                "thinkpol.agent1",
                "thinkpol.agent2",
                "room101.operator1",
                "minitrue.editor1",
            ],
        },
    )
    write_domain(base_dir, "OCEANIA", oceania)

    # --- WORLDSTATE: Brave New World / Aldous Huxley ---
    # Second domain for cross-domain testing; helmholtz.watson is a DA here,
    # so cross-domain check catches admin-in-one-domain / non-admin-in-another
    worldstate = generate_domain(
        "WORLDSTATE",
        {
            "first_names": WORLDSTATE_FIRST,
            "last_names": WORLDSTATE_LAST,
            "user_count": 40,
            "computer_count": 5,
            "da_accounts": ["mustapha.mond", "controller.west", "helmholtz.watson"],
            "ea_accounts": ["world.controller1"],
            "svc_accounts": ["svc_soma", "svc_bokanovsky"],
            "bsp_pairs": [
                ("bmarx-admin", "bmarx"),
            ],
            "shared_password_users": [],
            "cross_domain_users": ["helmholtz.watson"],
            "cross_domain_hash": cross_domain_hash,
            "nested_groups": [],
        },
    )
    write_domain(base_dir, "WORLDSTATE", worldstate)

    # --- GILEAD: The Handmaid's Tale / Margaret Atwood ---
    # Minimal domain
    gilead = generate_domain(
        "GILEAD",
        {
            "first_names": GILEAD_FIRST,
            "last_names": GILEAD_LAST,
            "user_count": 5,
            "computer_count": 2,
            "da_accounts": ["commander.waterford"],
            "ea_accounts": [],
            "svc_accounts": [],
            "bsp_pairs": [],
            "shared_password_users": [],
            "nested_groups": [],
        },
    )
    write_domain(base_dir, "GILEAD", gilead)

    print(f"\nTest data generated in {base_dir}/")
    print("\nExample usage:")
    print(f"  check-hashes {base_dir}/OCEANIA/OCEANIA.ntds")
    print(f"  check-hashes {base_dir}/OCEANIA/OCEANIA.ntds --ldap {base_dir}/OCEANIA")
    print(f"  check-hashes {base_dir}/OCEANIA/OCEANIA.ntds --ldap {base_dir}/OCEANIA --common")
    print(f"  check-hashes {base_dir} --suffix=-admin --cross-domain")


if __name__ == "__main__":
    main()
