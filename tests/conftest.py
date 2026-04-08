"""Shared test fixtures for check_hashes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Sample hashes for tests
HASH_A = "a" * 32
HASH_B = "b" * 32
HASH_C = "c" * 32
BLANK_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"
BLANK_LM = "aad3b435b51404eeaad3b435b51404ee"


def make_pwdump_line(
    account: str,
    rid: str = "1001",
    lm: str = BLANK_LM,
    nt: str = HASH_A,
    status: str | None = None,
) -> str:
    line = f"{account}:{rid}:{lm}:{nt}:::"
    if status:
        line += f" (status={status})"
    return line


@pytest.fixture()
def ntds_file(tmp_path: Path) -> Path:
    """Create a basic pwdump file with several accounts sharing hashes."""
    lines = [
        make_pwdump_line("CORP\\jsmith", "1001", nt=HASH_A),
        make_pwdump_line("CORP\\jsmith-admin", "1002", nt=HASH_A),
        make_pwdump_line("CORP\\bjones", "1003", nt=HASH_B),
        make_pwdump_line("CORP\\admin-bjones", "1004", nt=HASH_B),
        make_pwdump_line("CORP\\svc_backup", "1005", nt=HASH_C),
        make_pwdump_line("CORP\\disabled_user", "1006", nt=HASH_A, status="Disabled"),
        make_pwdump_line("CORP\\blank_user", "1007", nt=BLANK_NT),
        make_pwdump_line("CORP\\WS001$", "1008", nt=HASH_A),
        make_pwdump_line("CORP\\SRV001$", "1009", nt=HASH_B),
    ]
    f = tmp_path / "test.ntds"
    f.write_text("\n".join(lines))
    return f


@pytest.fixture()
def ldap_dir(tmp_path: Path) -> Path:
    """Create a basic ldapdomaindump output directory."""
    users = [
        {
            "attributes": {
                "sAMAccountName": "jsmith-admin",
                "distinguishedName": "CN=John Smith Admin,CN=Users,DC=corp,DC=local",
                "memberOf": ["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
            }
        },
        {
            "attributes": {
                "sAMAccountName": "jsmith",
                "distinguishedName": "CN=John Smith,CN=Users,DC=corp,DC=local",
                "memberOf": [],
            }
        },
        {
            "attributes": {
                "sAMAccountName": "bjones",
                "distinguishedName": "CN=Bob Jones,CN=Users,DC=corp,DC=local",
                "memberOf": ["CN=IT Staff,CN=Users,DC=corp,DC=local"],
            }
        },
        {
            "attributes": {
                "sAMAccountName": "admin-bjones",
                "distinguishedName": "CN=Bob Jones Admin,CN=Users,DC=corp,DC=local",
                "memberOf": ["CN=Server Admins,CN=Users,DC=corp,DC=local"],
            }
        },
        {
            "attributes": {
                "sAMAccountName": "svc_backup",
                "distinguishedName": "CN=Backup Service,CN=Users,DC=corp,DC=local",
                "memberOf": [],
            }
        },
    ]
    groups = [
        {
            "attributes": {
                "cn": "Domain Admins",
                "distinguishedName": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
                "description": "Designated administrators of the domain",
                "member": [
                    "CN=John Smith Admin,CN=Users,DC=corp,DC=local",
                ],
            }
        },
        {
            "attributes": {
                "cn": "Server Admins",
                "distinguishedName": "CN=Server Admins,CN=Users,DC=corp,DC=local",
                "description": "Server administration group",
                "member": [
                    "CN=Bob Jones Admin,CN=Users,DC=corp,DC=local",
                ],
            }
        },
        {
            "attributes": {
                "cn": "IT Staff",
                "distinguishedName": "CN=IT Staff,CN=Users,DC=corp,DC=local",
                "description": "General IT staff",
                "member": [
                    "CN=Bob Jones,CN=Users,DC=corp,DC=local",
                ],
            }
        },
    ]

    (tmp_path / "domain_users.json").write_text(json.dumps(users))
    (tmp_path / "domain_groups.json").write_text(json.dumps(groups))
    return tmp_path
