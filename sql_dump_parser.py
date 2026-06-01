#!/usr/bin/env python3
"""
dumploot.py - MariaDB/MySQL dump analyzer & loot hunter

Parses a SQL dump (from mysqldump / mariadb-dump), prints a clean structural
overview, and hunts for interesting data: credentials, usernames, passwords,
hashes, versions, API keys/tokens, emails, etc.

Pure stdlib. Works on any dump file you already have on disk.

Examples:
    ./dumploot.py dump.sql --overview
    ./dumploot.py dump.sql --all
    ./dumploot.py dump.sql --passwords --hashes
    ./dumploot.py dump.sql --keys --emails --no-color
    ./dumploot.py dump.sql --creds -o findings.txt
"""

import argparse
import re
import sys
import os
from collections import defaultdict


# ----------------------------------------------------------------------------- 
# Coloring
# -----------------------------------------------------------------------------
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"; GREY = "\033[90m"

    @classmethod
    def disable(cls):
        for k in list(vars(cls)):
            if k.isupper():
                setattr(cls, k, "")


def hdr(text):
    return f"{C.BOLD}{C.CYAN}== {text} =={C.RESET}"


# ----------------------------------------------------------------------------- 
# Patterns
# -----------------------------------------------------------------------------
# Column-name hints (matched against parsed CREATE TABLE columns)
COL_HINTS = {
    "password": re.compile(r"(pass(word|wd|_hash)?|pwd|secret|credential)", re.I),
    "username": re.compile(r"(user(name|_name)?|login|email|account|uname)", re.I),
    "token":    re.compile(r"(token|api[_-]?key|apikey|secret[_-]?key|access[_-]?key|auth)", re.I),
    "email":    re.compile(r"(email|e_mail|mail)", re.I),
}

# Hash signatures: (label, compiled regex anchored to a standalone value)
HASH_SIGS = [
    ("bcrypt",          re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("argon2",          re.compile(r"^\$argon2(id|i|d)\$")),
    ("sha512crypt",     re.compile(r"^\$6\$")),
    ("sha256crypt",     re.compile(r"^\$5\$")),
    ("md5crypt",        re.compile(r"^\$1\$")),
    ("phpass",          re.compile(r"^\$[PH]\$[./A-Za-z0-9]{30,}$")),
    ("MySQL5 (SHA1x2)", re.compile(r"^\*[A-F0-9]{40}$")),
    ("MySQL<4.1",       re.compile(r"^[0-9a-f]{16}$")),
    ("SHA-512",         re.compile(r"^[0-9a-fA-F]{128}$")),
    ("SHA-256",         re.compile(r"^[0-9a-fA-F]{64}$")),
    ("SHA-1 / NTLM",    re.compile(r"^[0-9a-fA-F]{40}$")),
    ("MD5 / NTLM",      re.compile(r"^[0-9a-fA-F]{32}$")),
]

# Secret / key / token signatures found anywhere in values
SECRET_SIGS = [
    ("AWS Access Key ID",  re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("AWS Secret (likely)",re.compile(r"\b[A-Za-z0-9/+=]{40}\b")),
    ("GitHub token",       re.compile(r"\bgh[opsur]_[A-Za-z0-9]{36,}\b")),
    ("Google API key",     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token",        re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("Stripe key",         re.compile(r"\b[sr]k_(live|test)_[A-Za-z0-9]{16,}\b")),
    ("JWT",                re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("Private key block",  re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Generic secret kv",  re.compile(r"\b(api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9/+=_\-]{8,}", re.I)),
]

EMAIL_RE   = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
VERSION_RE = re.compile(
    r"(?:(?:mariadb|mysql|percona|server\s*version|version)\D{0,8})?"
    r"\b(\d{1,2}\.\d{1,2}\.\d{1,3}(?:-[A-Za-z0-9.\-]+)?)\b", re.I)

# Dump-header version line, e.g. "-- Server version 8.0.36" or comment markers
DUMP_VERSION_RE = re.compile(r"(?:server version|mariadb|mysql|dump completed|/\*!\d{5})\s*([\d.]+)?", re.I)


# ----------------------------------------------------------------------------- 
# Parsing
# -----------------------------------------------------------------------------
class Dump:
    def __init__(self, path):
        self.path = path
        # table -> list of column names (in order)
        self.columns = {}
        # table -> approx row count (number of value-tuples in INSERTs)
        self.row_counts = defaultdict(int)
        self.databases = []
        self.header_versions = set()
        self._raw_lines = 0

    def parse(self):
        create_buf = []
        in_create = False
        create_table = None

        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                self._raw_lines += 1
                stripped = line.strip()

                # versions / metadata in comments
                if stripped.startswith("--") or stripped.startswith("/*"):
                    for m in DUMP_VERSION_RE.finditer(stripped):
                        if m.group(1):
                            self.header_versions.add(m.group(1))
                    continue

                # CREATE DATABASE / USE
                mdb = re.search(r"CREATE DATABASE.*?`([^`]+)`", stripped, re.I) \
                      or re.match(r"USE\s+`?([^`;\s]+)`?", stripped, re.I)
                if mdb and mdb.group(1) not in self.databases:
                    self.databases.append(mdb.group(1))

                # CREATE TABLE block
                if not in_create:
                    mct = re.match(r"CREATE TABLE.*?`([^`]+)`", stripped, re.I)
                    if mct:
                        in_create = True
                        create_table = mct.group(1)
                        create_buf = [line]
                        if stripped.endswith(";"):
                            in_create = False
                            self._finish_create(create_table, create_buf)
                        continue
                else:
                    create_buf.append(line)
                    if stripped.startswith(")") or stripped.endswith(";"):
                        in_create = False
                        self._finish_create(create_table, create_buf)
                    continue

                # INSERT row counting
                mins = re.match(r"INSERT INTO\s+`?([^`\s(]+)`?", stripped, re.I)
                if mins:
                    tbl = mins.group(1)
                    # count top-level "),(" tuple separators + 1
                    self.row_counts[tbl] += stripped.count("),(") + 1

    def _finish_create(self, table, buf):
        cols = []
        for raw in buf:
            mcol = re.match(r"\s*`([^`]+)`\s+", raw)
            if mcol:
                cols.append(mcol.group(1))
        self.columns[table] = cols


# ----------------------------------------------------------------------------- 
# Value extraction from INSERTs
# -----------------------------------------------------------------------------
def iter_insert_rows(path):
    """Yield (table, [values]) tuples. Naive but robust SQL value splitter."""
    buf = ""
    table = None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.strip()
            if buf:
                buf += " " + s
            else:
                m = re.match(r"INSERT INTO\s+`?([^`\s(]+)`?.*?VALUES", s, re.I)
                if m:
                    table = m.group(1)
                    buf = s
            if buf and buf.rstrip().endswith(";"):
                for row in _split_value_tuples(buf):
                    yield table, row
                buf = ""
                table = None


def _split_value_tuples(stmt):
    """Extract each (...) tuple from a VALUES clause and split its fields."""
    vidx = stmt.upper().find("VALUES")
    if vidx == -1:
        return
    body = stmt[vidx + 6:]
    rows = []
    depth = 0
    cur = ""
    in_str = False
    esc = False
    for ch in body:
        if in_str:
            cur += ch
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == "'":
                in_str = False
            continue
        if ch == "'":
            in_str = True
            cur += ch
        elif ch == "(":
            depth += 1
            if depth == 1:
                cur = ""
            else:
                cur += ch
        elif ch == ")":
            depth -= 1
            if depth == 0:
                rows.append(cur)
                cur = ""
            else:
                cur += ch
        elif depth >= 1:
            cur += ch
    out = []
    for r in rows:
        out.append(_split_fields(r))
    return out


def _split_fields(tuple_body):
    fields = []
    cur = ""
    in_str = False
    esc = False
    for ch in tuple_body:
        if in_str:
            if esc:
                cur += ch; esc = False
            elif ch == "\\":
                cur += ch; esc = True
            elif ch == "'":
                in_str = False
            else:
                cur += ch
            continue
        if ch == "'":
            in_str = True
        elif ch == ",":
            fields.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip() != "" or fields:
        fields.append(cur.strip())
    return [f for f in fields]


def classify_hash(value):
    for label, rx in HASH_SIGS:
        if rx.match(value):
            return label
    return None


# ----------------------------------------------------------------------------- 
# Reporting
# -----------------------------------------------------------------------------
class Reporter:
    def __init__(self, out):
        self.out = out

    def line(self, text=""):
        self.out.write(text + "\n")


def overview(dump, rep):
    rep.line(hdr("DUMP OVERVIEW"))
    rep.line(f"{C.DIM}file:{C.RESET} {dump.path}  "
             f"({os.path.getsize(dump.path):,} bytes, {dump._raw_lines:,} lines)")
    if dump.header_versions:
        rep.line(f"{C.YELLOW}server/dump versions:{C.RESET} "
                 + ", ".join(sorted(dump.header_versions)))
    if dump.databases:
        rep.line(f"{C.BLUE}databases:{C.RESET} " + ", ".join(dump.databases))
    rep.line()
    rep.line(f"{C.BOLD}{'TABLE':<32}{'ROWS':>10}  COLUMNS{C.RESET}")
    rep.line(f"{C.GREY}{'-'*70}{C.RESET}")
    for tbl in sorted(dump.columns):
        cols = dump.columns[tbl]
        rows = dump.row_counts.get(tbl, 0)
        # flag interesting columns
        flagged = []
        for c in cols:
            for kind, rx in COL_HINTS.items():
                if rx.search(c):
                    flagged.append(c)
                    break
        colstr = ", ".join(cols[:8]) + (" ..." if len(cols) > 8 else "")
        rep.line(f"{tbl:<32}{rows:>10}  {C.GREY}{colstr}{C.RESET}")
        if flagged:
            rep.line(f"{'':<32}{'':>10}  {C.YELLOW}* sensitive cols: "
                     f"{', '.join(flagged)}{C.RESET}")
    rep.line()


def hunt(dump, rep, want):
    """want: set of categories among
       creds users passwords hashes versions keys emails"""
    # Precompute, per table, indices of interesting columns
    interesting = {}  # table -> {colname: kind}
    for tbl, cols in dump.columns.items():
        marks = {}
        for c in cols:
            for kind, rx in COL_HINTS.items():
                if rx.search(c):
                    marks[c] = kind
        if marks:
            interesting[tbl] = marks

    found = defaultdict(list)  # category -> list of finding strings
    seen_versions = set(dump.header_versions)

    for table, values in iter_insert_rows(dump.path):
        cols = dump.columns.get(table, [])
        # Map values to columns where possible
        pairs = list(zip(cols, values)) if cols and len(cols) >= len(values) \
                else [(f"col{i}", v) for i, v in enumerate(values)]

        for col, val in pairs:
            v = val.strip()
            if v in ("", "NULL"):
                continue
            low_col = col.lower()

            # --- password columns / hashes ---
            if want & {"passwords", "creds", "hashes"}:
                is_pwcol = COL_HINTS["password"].search(low_col)
                htype = classify_hash(v)
                if (want & {"passwords", "creds"}) and is_pwcol:
                    tag = f"[{htype}]" if htype else "[plaintext?]"
                    found["passwords"].append(
                        f"{C.GREEN}{table}.{col}{C.RESET} {C.RED}{tag}{C.RESET} {v}")
                if (want & {"hashes"}) and htype:
                    found["hashes"].append(
                        f"{C.MAGENTA}{htype}{C.RESET}  ({table}.{col})  {v}")

            # --- usernames ---
            if want & {"users", "creds"} and COL_HINTS["username"].search(low_col):
                found["users"].append(f"{C.GREEN}{table}.{col}{C.RESET}  {v}")

            # --- emails ---
            if want & {"emails", "creds"}:
                for m in EMAIL_RE.findall(v):
                    found["emails"].append(f"{m}  {C.GREY}({table}.{col}){C.RESET}")

            # --- keys / tokens / secrets ---
            if want & {"keys", "creds"}:
                for label, rx in SECRET_SIGS:
                    if rx.search(v):
                        found["keys"].append(
                            f"{C.RED}{label}{C.RESET}  ({table}.{col})  "
                            f"{v[:80]}{'...' if len(v) > 80 else ''}")
                        break

            # --- versions ---
            if want & {"versions"}:
                if re.search(r"(version|build|release)", low_col) or \
                   re.search(r"\b\d+\.\d+\.\d+\b", v):
                    for m in VERSION_RE.findall(v):
                        if m and m not in seen_versions:
                            seen_versions.add(m)
                            found["versions"].append(
                                f"{m}  {C.GREY}({table}.{col} = {v[:40]}){C.RESET}")

    # de-dup while preserving order
    def dedup(seq):
        seen = set(); out = []
        for x in seq:
            if x not in seen:
                seen.add(x); out.append(x)
        return out

    titles = {
        "passwords": "PASSWORDS / PASSWORD COLUMNS",
        "hashes":    "HASHES (classified)",
        "users":     "USERNAMES / LOGINS",
        "emails":    "EMAIL ADDRESSES",
        "keys":      "KEYS / TOKENS / SECRETS",
        "versions":  "VERSIONS",
    }
    order = ["versions", "users", "passwords", "hashes", "keys", "emails"]

    if want & {"versions"} and seen_versions and not found["versions"]:
        # surface header versions even if no inline ones
        for v in sorted(seen_versions):
            found["versions"].append(f"{v}  {C.GREY}(dump header){C.RESET}")

    any_found = False
    for cat in order:
        if cat == "passwords" and not (want & {"passwords", "creds"}):
            continue
        if cat == "hashes" and not (want & {"hashes"}):
            continue
        if cat == "users" and not (want & {"users", "creds"}):
            continue
        if cat == "emails" and not (want & {"emails", "creds"}):
            continue
        if cat == "keys" and not (want & {"keys", "creds"}):
            continue
        if cat == "versions" and not (want & {"versions"}):
            continue
        items = dedup(found.get(cat, []))
        if not items:
            continue
        any_found = True
        rep.line(hdr(f"{titles[cat]}  ({len(items)})"))
        for it in items:
            rep.line(f"  {it}")
        rep.line()

    if not any_found:
        rep.line(f"{C.DIM}No matches for the selected categories.{C.RESET}")


# ----------------------------------------------------------------------------- 
# CLI
# -----------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(
        description="Analyze a MariaDB/MySQL dump and hunt for loot.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("dumpfile", help="path to the .sql dump")
    p.add_argument("--overview", action="store_true",
                   help="print schema/table/column overview (default if no hunt switches)")
    p.add_argument("--creds", action="store_true",
                   help="hunt usernames + passwords + emails + keys together")
    p.add_argument("--users", action="store_true", help="find username/login columns")
    p.add_argument("--passwords", action="store_true", help="find password columns + values")
    p.add_argument("--hashes", action="store_true", help="detect & classify hash formats")
    p.add_argument("--keys", action="store_true", help="find API keys/tokens/secrets/private keys")
    p.add_argument("--versions", action="store_true", help="find software/server versions")
    p.add_argument("--emails", action="store_true", help="find email addresses")
    p.add_argument("--all", action="store_true", help="overview + every hunt category")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("-o", "--output", help="write report to file instead of stdout")
    args = p.parse_args()

    if args.no_color or args.output:
        C.disable()

    if not os.path.isfile(args.dumpfile):
        sys.exit(f"error: no such file: {args.dumpfile}")

    want = set()
    if args.all:
        want = {"users", "passwords", "hashes", "keys", "versions", "emails"}
    else:
        if args.creds:     want |= {"creds"}
        if args.users:     want |= {"users"}
        if args.passwords: want |= {"passwords"}
        if args.hashes:    want |= {"hashes"}
        if args.keys:      want |= {"keys"}
        if args.versions:  want |= {"versions"}
        if args.emails:    want |= {"emails"}

    show_overview = args.overview or args.all or not want

    dump = Dump(args.dumpfile)
    dump.parse()

    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    try:
        rep = Reporter(out)
        if show_overview:
            overview(dump, rep)
        if want:
            hunt(dump, rep, want)
    finally:
        if args.output:
            out.close()
            print(f"report written to {args.output}")


if __name__ == "__main__":
    main()