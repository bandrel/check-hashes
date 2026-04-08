# check-hashes

Check pwdump/secretsdump NTDS hashes for shared passwords, broken separation of privilege (BSP), and admin/non-admin hash overlap.

## Install

```bash
# From GitHub
uv tool install git+https://github.com/bandrel/check-hashes

# From a local clone
uv tool install .
```

Requires Python 3.10+. Zero runtime dependencies.

## Usage

```
check-hashes <target> [options]
```

`target` is either a single pwdump file or a root directory containing `<domain>/*.ntds` subdirectories.

### Modes

**Show all shared hashes** (default — no flags):

```bash
check-hashes dump.ntds
```

Groups accounts that share the same NT hash and prints each group.

**Admin vs non-admin overlap** (any admin filter):

```bash
check-hashes dump.ntds --suffix -admin
check-hashes dump.ntds --prefix admin-
check-hashes dump.ntds --regex ".*adm.*"
check-hashes dump.ntds --file admin_list.txt
check-hashes dump.ntds --ldap /path/to/ldapdump
```

Identifies admin accounts using the given filter(s), then shows groups where at least one admin shares a hash with a non-admin.

**Broken Separation of Privilege pairs** (`--common` + admin filter):

```bash
check-hashes dump.ntds --suffix -admin --common
```

Outputs CSV pairs where an admin and non-admin share a hash AND their usernames are variants of each other (e.g. `jsmith` / `jsmith-admin`). Useful for identifying users who set the same password on their regular and privileged accounts.

**Username variant pairs** (`--common` alone):

```bash
check-hashes dump.ntds --common
```

Same as above but without an admin filter — finds all account pairs with shared hashes and variant usernames.

### Admin Filters

Filters can be combined. Each adds to the admin account list.

| Flag | Description |
|------|-------------|
| `--prefix STR` | Username starts with STR (e.g. `admin-`, `a-`) |
| `--suffix STR` | Username ends with STR (e.g. `-admin`, `.da`) |
| `--regex PATTERN` | Full account matches regex |
| `--file PATH` | Text file with one admin username per line |
| `--ldap [PATH]` | ldapdomaindump output folder (defaults to cwd if no path given) |

### LDAP Admin Discovery

The `--ldap` flag parses [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) output (`domain_users.json` and `domain_groups.json`) to automatically identify privileged accounts:

- **Standard groups**: Domain Admins, Enterprise Admins, Administrators, Schema Admins
- **Dynamic discovery**: any group with "admin" in its name or description
- **Nested groups**: resolves transitive group membership (e.g. user in Group A, Group A is a member of Domain Admins)

Falls back to checking `memberOf` on user objects if `domain_groups.json` is absent.

```bash
# Use ldapdomaindump output in current directory
check-hashes dump.ntds --ldap

# Point at a specific folder
check-hashes dump.ntds --ldap /path/to/ldapdump

# Combine with --common for BSP pairs
check-hashes dump.ntds --ldap /path/to/ldapdump --common
```

### Filtering

Disabled accounts and machine/computer accounts (ending in `$`) are **excluded by default** when status information is available in the pwdump file (e.g. `(status=Disabled)` from secretsdump).

```bash
check-hashes dump.ntds --include-disabled     # include disabled accounts
check-hashes dump.ntds --include-computers    # include machine accounts
```

### Multi-Domain / Directory Mode

When `target` is a directory, check-hashes discovers domains automatically using the convention:

```
target/
  domain1/dump.ntds
  domain2/dump.ntds
```

Each domain is checked independently. Add `--cross-domain` to also check for shared hashes across all domains combined — finding cases where users in different domains share the same password.

```bash
check-hashes /path/to/engagement --suffix -admin --cross-domain
```

## Output

- Results go to **stdout** (pipeable)
- Status messages and the banner go to **stderr**

In `--common` / BSP mode, output is CSV (`admin,non_admin`). Otherwise, accounts are printed in groups separated by blank lines.

## Test Data

Generate dystopian-themed sample data covering all features (shared hashes, BSP pairs, nested LDAP groups, cross-domain overlap, disabled accounts, computer accounts):

```bash
uv run python generate_test_data.py
```

Creates three domains under `testdata/`:
- **OCEANIA** (1984) — full-featured: BSP pairs, nested groups, deep nesting, description-based admin detection
- **WORLDSTATE** (Brave New World) — cross-domain hash sharing with OCEANIA
- **GILEAD** (The Handmaid's Tale) — minimal domain

## Development

```bash
uv sync                          # install deps
uv run pytest                    # run tests
uv run ruff check src/ tests/    # lint
git config core.hooksPath .githooks  # enable pre-commit (ruff) and pre-push (pytest) hooks
```
