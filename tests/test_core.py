"""Tests for check_hashes.core."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import BLANK_LM, BLANK_NT, HASH_A, make_pwdump_line

from check_hashes.core import (
    NtdsEntry,
    build_admin_list,
    find_admin_shared_hashes,
    find_bsp_pairs,
    find_common_pairs,
    group_by_hash,
    is_username_variant,
    parse_ldap_admins,
    parse_ntds,
)

# ---------------------------------------------------------------------------
# parse_ntds
# ---------------------------------------------------------------------------


class TestParseNtds:
    def test_basic_parse(self, ntds_file: Path):
        entries = parse_ntds(ntds_file)
        accounts = [e.full_account for e in entries]
        assert "CORP\\jsmith" in accounts
        assert "CORP\\jsmith-admin" in accounts

    def test_status_parsing(self, ntds_file: Path):
        entries = parse_ntds(ntds_file)
        disabled = [e for e in entries if e.full_account == "CORP\\disabled_user"]
        assert len(disabled) == 1
        assert disabled[0].is_disabled

    def test_deduplication(self, tmp_path: Path):
        lines = [
            make_pwdump_line("CORP\\jsmith", "1001", nt=HASH_A),
            make_pwdump_line("CORP\\JSMITH", "1001", nt=HASH_A),  # dup
            make_pwdump_line("corp\\jsmith", "1001", nt=HASH_A),  # dup
        ]
        f = tmp_path / "dup.ntds"
        f.write_text("\n".join(lines))
        entries = parse_ntds(f)
        assert len(entries) == 1

    def test_skips_invalid_lines(self, tmp_path: Path):
        lines = [
            "not a valid line",
            "also:bad",
            make_pwdump_line("CORP\\valid", "1001", nt=HASH_A),
            "CORP\\badhash:1001:notahash:notahash:::",
        ]
        f = tmp_path / "mixed.ntds"
        f.write_text("\n".join(lines))
        entries = parse_ntds(f)
        assert len(entries) == 1
        assert entries[0].full_account == "CORP\\valid"

    def test_latin1_encoding(self, tmp_path: Path):
        line = make_pwdump_line("CORP\\caf\u00e9user", "1001", nt=HASH_A)
        f = tmp_path / "latin1.ntds"
        f.write_bytes(line.encode("latin-1"))
        entries = parse_ntds(f)
        assert len(entries) == 1


# ---------------------------------------------------------------------------
# NtdsEntry properties
# ---------------------------------------------------------------------------


class TestNtdsEntry:
    def test_username_extraction(self):
        e = NtdsEntry("CORP\\jsmith", "1001", BLANK_LM, HASH_A, "Enabled")
        assert e.username == "jsmith"

    def test_username_no_domain(self):
        e = NtdsEntry("jsmith", "1001", BLANK_LM, HASH_A, "Enabled")
        assert e.username == "jsmith"

    def test_is_computer(self):
        e = NtdsEntry("CORP\\SERVER01$", "1001", BLANK_LM, HASH_A, "Enabled")
        assert e.is_computer

    def test_blank_nt(self):
        e = NtdsEntry("CORP\\user", "1001", BLANK_LM, BLANK_NT, "Enabled")
        assert e.has_blank_nt


# ---------------------------------------------------------------------------
# group_by_hash
# ---------------------------------------------------------------------------


class TestGroupByHash:
    def test_groups_shared_hashes(self, ntds_file: Path):
        entries = parse_ntds(ntds_file)
        groups = group_by_hash(entries)
        # HASH_A is shared by jsmith and jsmith-admin (disabled + computers skipped)
        assert HASH_A in groups
        assert len(groups[HASH_A]) == 2

    def test_skips_disabled(self, ntds_file: Path):
        entries = parse_ntds(ntds_file)
        groups = group_by_hash(entries, skip_disabled=True)
        all_accounts = [a for accts in groups.values() for a in accts]
        assert "CORP\\disabled_user" not in all_accounts

    def test_includes_disabled_when_asked(self, ntds_file: Path):
        entries = parse_ntds(ntds_file)
        groups = group_by_hash(entries, skip_disabled=False)
        hash_a_accounts = groups.get(HASH_A, [])
        assert "CORP\\disabled_user" in hash_a_accounts

    def test_skips_blank_hashes(self, ntds_file: Path):
        entries = parse_ntds(ntds_file)
        groups = group_by_hash(entries)
        assert BLANK_NT not in groups

    def test_skips_computers(self, ntds_file: Path):
        entries = parse_ntds(ntds_file)
        groups = group_by_hash(entries, skip_computers=True)
        all_accounts = [a for accts in groups.values() for a in accts]
        assert "CORP\\WS001$" not in all_accounts
        assert "CORP\\SRV001$" not in all_accounts

    def test_includes_computers_when_asked(self, ntds_file: Path):
        entries = parse_ntds(ntds_file)
        groups = group_by_hash(entries, skip_computers=False)
        hash_a_accounts = groups.get(HASH_A, [])
        assert "CORP\\WS001$" in hash_a_accounts

    def test_excludes_singletons(self, ntds_file: Path):
        entries = parse_ntds(ntds_file)
        groups = group_by_hash(entries)
        for accts in groups.values():
            assert len(accts) >= 2


# ---------------------------------------------------------------------------
# is_username_variant
# ---------------------------------------------------------------------------


class TestIsUsernameVariant:
    @pytest.mark.parametrize(
        "a, b",
        [
            ("jsmith", "jsmith-admin"),
            ("jsmith", "jsmith_admin"),
            ("jsmith", "jsmith.admin"),
            ("bjones", "admin-bjones"),
            ("bjones", "admin_bjones"),
            ("bjones", "admin.bjones"),
        ],
    )
    def test_separator_variants(self, a: str, b: str):
        assert is_username_variant(a, b)

    @pytest.mark.parametrize(
        "a, b",
        [
            ("jsmith", "jsmitha"),  # 1 char suffix, no sep
            ("jsmith", "ajsmith"),  # 1 char prefix, no sep
            ("jsmith", "jsmithda"),  # 2 char suffix, no sep
        ],
    )
    def test_short_affix_no_separator(self, a: str, b: str):
        assert is_username_variant(a, b)

    def test_too_long_without_separator(self):
        assert not is_username_variant("jsmith", "jsmithadm")  # 3 chars, no sep

    def test_same_name_is_not_variant(self):
        assert not is_username_variant("jsmith", "jsmith")

    def test_short_names_rejected(self):
        assert not is_username_variant("ab", "ab-admin")

    def test_digit_continuation_rejected(self):
        # jsmith1 -> jsmith12 should not match (digit continues number)
        assert not is_username_variant("jsmith1", "jsmith12")

    def test_symmetric(self):
        assert is_username_variant("jsmith-admin", "jsmith")
        assert is_username_variant("admin-jsmith", "jsmith")


# ---------------------------------------------------------------------------
# build_admin_list
# ---------------------------------------------------------------------------


class TestBuildAdminList:
    def _entries(self, ntds_file: Path) -> list[NtdsEntry]:
        return parse_ntds(ntds_file)

    def test_prefix_filter(self, ntds_file: Path):
        entries = self._entries(ntds_file)
        admins = build_admin_list(entries, prefix="admin-")
        assert "CORP\\admin-bjones" in admins
        assert "CORP\\jsmith" not in admins

    def test_suffix_filter(self, ntds_file: Path):
        entries = self._entries(ntds_file)
        admins = build_admin_list(entries, suffix="-admin")
        assert "CORP\\jsmith-admin" in admins
        assert "CORP\\bjones" not in admins

    def test_regex_filter(self, ntds_file: Path):
        entries = self._entries(ntds_file)
        admins = build_admin_list(entries, regex=".*admin.*")
        assert "CORP\\jsmith-admin" in admins
        assert "CORP\\admin-bjones" in admins

    def test_file_filter(self, ntds_file: Path, tmp_path: Path):
        entries = self._entries(ntds_file)
        admin_file = tmp_path / "admins.txt"
        admin_file.write_text("jsmith-admin\nadmin-bjones\n")
        admins = build_admin_list(entries, admin_file=admin_file)
        assert "CORP\\jsmith-admin" in admins
        assert "CORP\\admin-bjones" in admins
        assert "CORP\\jsmith" not in admins

    def test_ldap_filter(self, ntds_file: Path, ldap_dir: Path):
        entries = self._entries(ntds_file)
        admins = build_admin_list(entries, ldap_dir=ldap_dir)
        # jsmith-admin is in Domain Admins, admin-bjones is in Server Admins ("admin" in name)
        assert "CORP\\jsmith-admin" in admins
        assert "CORP\\admin-bjones" in admins
        assert "CORP\\jsmith" not in admins
        assert "CORP\\bjones" not in admins

    def test_combined_filters(self, ntds_file: Path):
        entries = self._entries(ntds_file)
        admins = build_admin_list(entries, prefix="admin-", suffix="-admin")
        assert "CORP\\jsmith-admin" in admins
        assert "CORP\\admin-bjones" in admins


# ---------------------------------------------------------------------------
# find_admin_shared_hashes
# ---------------------------------------------------------------------------


class TestFindAdminSharedHashes:
    def test_finds_admin_non_admin_groups(self, ntds_file: Path):
        entries = parse_ntds(ntds_file)
        admin_accounts = ["CORP\\jsmith-admin"]
        results = find_admin_shared_hashes(entries, admin_accounts)
        assert len(results) == 1
        admins, non_admins = results[0]
        assert "CORP\\jsmith-admin" in admins
        assert "CORP\\jsmith" in non_admins

    def test_excludes_admin_only_groups(self, ntds_file: Path):
        entries = parse_ntds(ntds_file)
        # Mark both hash-A users as admin
        admin_accounts = ["CORP\\jsmith-admin", "CORP\\jsmith"]
        results = find_admin_shared_hashes(entries, admin_accounts)
        # No group has both admin and non-admin for HASH_A
        for admins, non_admins in results:
            assert non_admins  # every result must have non-admins


# ---------------------------------------------------------------------------
# find_common_pairs
# ---------------------------------------------------------------------------


class TestFindCommonPairs:
    def test_finds_variant_pairs(self, ntds_file: Path):
        entries = parse_ntds(ntds_file)
        pairs = find_common_pairs(entries)
        pair_set = {tuple(sorted(p)) for p in pairs}
        assert tuple(sorted(("CORP\\jsmith", "CORP\\jsmith-admin"))) in pair_set
        assert tuple(sorted(("CORP\\bjones", "CORP\\admin-bjones"))) in pair_set


# ---------------------------------------------------------------------------
# find_bsp_pairs
# ---------------------------------------------------------------------------


class TestFindBspPairs:
    def test_finds_bsp(self, ntds_file: Path):
        entries = parse_ntds(ntds_file)
        admins = ["CORP\\jsmith-admin", "CORP\\admin-bjones"]
        pairs = find_bsp_pairs(entries, admins)
        admin_names = [p[0] for p in pairs]
        assert "CORP\\jsmith-admin" in admin_names
        assert "CORP\\admin-bjones" in admin_names


# ---------------------------------------------------------------------------
# parse_ldap_admins
# ---------------------------------------------------------------------------


class TestParseLdapAdmins:
    def test_standard_group(self, ldap_dir: Path):
        admins = parse_ldap_admins(ldap_dir)
        assert "jsmith-admin" in admins

    def test_admin_keyword_in_group_name(self, ldap_dir: Path):
        # "Server Admins" contains "admin"
        admins = parse_ldap_admins(ldap_dir)
        assert "admin-bjones" in admins

    def test_non_admin_excluded(self, ldap_dir: Path):
        admins = parse_ldap_admins(ldap_dir)
        assert "bjones" not in admins
        assert "svc_backup" not in admins

    def test_admin_keyword_in_description(self, tmp_path: Path):
        users = [
            {
                "attributes": {
                    "sAMAccountName": "opsguy",
                    "distinguishedName": "CN=Ops Guy,CN=Users,DC=corp,DC=local",
                    "memberOf": ["CN=Ops Team,CN=Users,DC=corp,DC=local"],
                }
            },
        ]
        groups = [
            {
                "attributes": {
                    "cn": "Ops Team",
                    "distinguishedName": "CN=Ops Team,CN=Users,DC=corp,DC=local",
                    "description": "Operations team with admin privileges",
                    "member": ["CN=Ops Guy,CN=Users,DC=corp,DC=local"],
                }
            },
        ]
        (tmp_path / "domain_users.json").write_text(json.dumps(users))
        (tmp_path / "domain_groups.json").write_text(json.dumps(groups))

        admins = parse_ldap_admins(tmp_path)
        assert "opsguy" in admins

    def test_nested_groups(self, tmp_path: Path):
        users = [
            {
                "attributes": {
                    "sAMAccountName": "nested_admin",
                    "distinguishedName": "CN=Nested Admin,CN=Users,DC=corp,DC=local",
                    "memberOf": ["CN=Tier2 Group,CN=Users,DC=corp,DC=local"],
                }
            },
        ]
        groups = [
            {
                "attributes": {
                    "cn": "Domain Admins",
                    "distinguishedName": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
                    "description": "Designated administrators of the domain",
                    "member": ["CN=Tier1 Group,CN=Users,DC=corp,DC=local"],
                }
            },
            {
                "attributes": {
                    "cn": "Tier1 Group",
                    "distinguishedName": "CN=Tier1 Group,CN=Users,DC=corp,DC=local",
                    "description": "First tier",
                    "member": ["CN=Tier2 Group,CN=Users,DC=corp,DC=local"],
                }
            },
            {
                "attributes": {
                    "cn": "Tier2 Group",
                    "distinguishedName": "CN=Tier2 Group,CN=Users,DC=corp,DC=local",
                    "description": "Second tier",
                    "member": ["CN=Nested Admin,CN=Users,DC=corp,DC=local"],
                }
            },
        ]
        (tmp_path / "domain_users.json").write_text(json.dumps(users))
        (tmp_path / "domain_groups.json").write_text(json.dumps(groups))

        admins = parse_ldap_admins(tmp_path)
        assert "nested_admin" in admins

    def test_fallback_no_groups_file(self, tmp_path: Path):
        users = [
            {
                "attributes": {
                    "sAMAccountName": "da_user",
                    "distinguishedName": "CN=DA User,CN=Users,DC=corp,DC=local",
                    "memberOf": ["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
                }
            },
            {
                "attributes": {
                    "sAMAccountName": "normal",
                    "distinguishedName": "CN=Normal,CN=Users,DC=corp,DC=local",
                    "memberOf": ["CN=Users,CN=Users,DC=corp,DC=local"],
                }
            },
        ]
        (tmp_path / "domain_users.json").write_text(json.dumps(users))
        # No domain_groups.json

        admins = parse_ldap_admins(tmp_path)
        assert "da_user" in admins
        assert "normal" not in admins

    def test_missing_users_file(self, tmp_path: Path):
        admins = parse_ldap_admins(tmp_path)
        assert admins == []

    def test_list_valued_attributes(self, tmp_path: Path):
        """ldapdomaindump may store single-valued attrs as lists."""
        users = [
            {
                "attributes": {
                    "sAMAccountName": ["listuser"],
                    "distinguishedName": ["CN=List User,CN=Users,DC=corp,DC=local"],
                    "memberOf": ["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
                }
            },
        ]
        groups = [
            {
                "attributes": {
                    "cn": ["Domain Admins"],
                    "distinguishedName": ["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
                    "description": ["Designated administrators"],
                    "member": ["CN=List User,CN=Users,DC=corp,DC=local"],
                }
            },
        ]
        (tmp_path / "domain_users.json").write_text(json.dumps(users))
        (tmp_path / "domain_groups.json").write_text(json.dumps(groups))

        admins = parse_ldap_admins(tmp_path)
        assert "listuser" in admins

    def test_all_standard_groups(self, tmp_path: Path):
        """All four standard privileged groups are recognized."""
        standard = [
            "Domain Admins",
            "Enterprise Admins",
            "Administrators",
            "Schema Admins",
        ]
        users = []
        groups = []
        for i, group_name in enumerate(standard):
            sam = f"user{i}"
            user_dn = f"CN=User {i},CN=Users,DC=corp,DC=local"
            group_dn = f"CN={group_name},CN=Users,DC=corp,DC=local"
            users.append(
                {
                    "attributes": {
                        "sAMAccountName": sam,
                        "distinguishedName": user_dn,
                        "memberOf": [group_dn],
                    }
                }
            )
            groups.append(
                {
                    "attributes": {
                        "cn": group_name,
                        "distinguishedName": group_dn,
                        "description": "",
                        "member": [user_dn],
                    }
                }
            )
        (tmp_path / "domain_users.json").write_text(json.dumps(users))
        (tmp_path / "domain_groups.json").write_text(json.dumps(groups))

        admins = parse_ldap_admins(tmp_path)
        assert sorted(admins) == ["user0", "user1", "user2", "user3"]
