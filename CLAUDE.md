# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

check-hashes is a standalone CLI tool for analyzing pwdump/secretsdump NTDS files to find shared passwords, admin/non-admin hash overlap, and broken separation of privilege (BSP). Zero external dependencies — standard library only.

## Commands

```bash
# Install dependencies
uv sync

# Run the CLI
uv run check-hashes <target> [options]

# Run tests
uv run pytest
uv run pytest tests/test_file.py::test_name   # single test

# Lint & format
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/

# Build
uv build

# Set up git hooks (ruff on commit, pytest on push)
git config core.hooksPath .githooks
```

## Architecture

All code lives in `src/check_hashes/` using the src layout with hatchling as the build backend.

- **core.py** — All hash-checking logic. `NtdsEntry` dataclass represents a parsed pwdump line. Key functions: `parse_ntds()` reads files, `group_by_hash()` clusters accounts by NT hash, `is_username_variant()` detects naming patterns (e.g. jsmith / jsmith-admin), `parse_ldap_admins()` extracts privileged users from ldapdomaindump output (with nested group resolution). Higher-level functions (`find_admin_shared_hashes`, `find_bsp_pairs`, `find_common_pairs`) compose these primitives.
- **__main__.py** — CLI layer. Two modes: single-file and directory discovery (`<domain>/*.ntds` convention). Delegates all logic to core.py. Output goes to stdout (results) vs stderr (banners, status, errors) so results can be piped.

The separation is intentional: core.py has no I/O side effects beyond reading the input file, making it importable as a library.
