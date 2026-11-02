"""Structural SQL statement classification.

The external-review finding this module closes (VIOLATION_LEDGER `SQL-LEX-01`):

    With `tool_manifest={"run_query": ["data.read"]}`, `GovernanceKernel.authorize`
    returned PERMIT for

        DROP/**/TABLE customers
        TRUNCATE customers
        UPDATE accounts SET balance=0
        EXECUTE IMMEDIATE 'DR'||'OP TABLE customers'

    while `DROP TABLE customers` and `DELETE FROM customers` escalated. SQL
    payloads were classified by one regular expression over the flattened
    argument text, so a comment between two keywords, a statement verb the
    pattern did not list, or a statement assembled at run time all read as
    ordinary data access.

This module TOKENISES the text the way a database lexer does and classifies
each statement by its type. Comments are removed rather than matched around,
string literals and quoted identifiers are opaque rather than searched, case and
whitespace stop mattering, and every statement in a multi-statement payload is
classified, the strictest one deciding.

Where SQL dialects disagree on how to read the same bytes (backslash escapes in
string literals, nested block comments, `#` comments, `--` without a following
space, MySQL `/*! ... */` executable comments, PostgreSQL dollar quoting, T-SQL
and SQLite bracket identifiers, Oracle `q'[...]'` quoting), the text is read
under EVERY dialect and the capabilities are unioned. A payload cannot hide a
statement by choosing the reading under which it looks like a comment.

Two modes:

  strict   the value is known to be SQL (an `sql`/`statement` argument, or the
           query argument of a database tool). Anything that does not lex in
           any dialect, any statement type outside the known read/transaction
           set, and any dynamic statement (EXEC, EXECUTE IMMEDIATE, CALL, DO,
           PREPARE, sp_executesql) FAILS CLOSED to `statement.unclassified`,
           which the capability policy escalates.

  sniff    any other string argument. It is classified only where a statement
           has an unambiguous SQL shape (`UPDATE <name> SET`, `TRUNCATE
           [TABLE] <name>`, `DELETE FROM`, ...), so prose that happens to begin
           "Update the notes" is not escalated. Unreadable text is left to the
           lexical floor in `capabilities`.

This is DEFENCE IN DEPTH, not the guarantee. A statement's effect is decided by
the database, not by its text: a `SELECT` can call a user-defined function that
writes, a view can be replaced, and a dialect this module does not model can
read the bytes differently again. The guarantee for a read-only tool is a
read-only database role on the resource side (see DEPLOYMENT.md, "Resource-side
enforcement").

Deterministic: no clock, no RNG, no I/O. No third-party parser: a dependency
here would be a second attack surface and a lint-gate entry.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable

# Capability names. Kept as literals rather than imported from `capabilities`
# to avoid an import cycle; `capabilities` asserts they are in its vocabulary.
CAP_DATA_READ = "data.read"
CAP_DATA_WRITE = "data.write"
CAP_DATA_DESTRUCTIVE = "data.destructive"
CAP_IAM_PRIVILEGED = "iam.privileged"
CAP_CREDENTIAL_CHANGE = "credential.change"
CAP_SECURITY_CONTROL = "security_control.modify"
CAP_PERSISTENCE = "persistence.establish"
CAP_CODE_EXEC = "code.execute"
CAP_INFRA_DESTRUCTIVE = "infra.destructive"
CAP_UNCLASSIFIED = "statement.unclassified"
CAP_LOG_TAMPER = "log.tamper"

# Longest text read in strict mode. Longer SQL is not classified, it is
# escalated: a bounded lexer that silently stopped would be a partial reading.
MAX_SQL_CHARS = 1_000_000

# Statement classes (for reporting; capabilities are what policy reads).
READ = "read"
TRANSACTION = "transaction"
WRITE = "write"
DESTRUCTIVE = "destructive"
PRIVILEGE = "privilege"
DYNAMIC = "dynamic"
UNCLASSIFIED = "unclassified"

_ZERO_WIDTH = dict.fromkeys([0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD], None)


# ─────────────────────────────────────────────────────────────
# Dialects
# ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Dialect:
    name: str
    backslash_escapes: bool = False     # '\'' ends nothing; MySQL default
    nested_comments: bool = False       # /* /* */ */ (PostgreSQL, T-SQL)
    hash_comments: bool = False         # '# ...' to end of line (MySQL)
    dash_needs_space: bool = False      # MySQL: '--' is a comment only before whitespace
    exec_comments: bool = False         # MySQL: /*! ... */ and /*!50001 ... */ are CODE
    double_quote_string: bool = False   # MySQL: "..." is a string with escapes
    backtick_ident: bool = False        # MySQL, SQLite
    bracket_ident: bool = False         # T-SQL, SQLite
    dollar_quotes: bool = False         # PostgreSQL $tag$...$tag$
    e_strings: bool = False             # PostgreSQL E'...' with backslash escapes
    q_quotes: bool = False              # Oracle q'[...]'


DIALECTS: tuple[Dialect, ...] = (
    Dialect("postgresql", nested_comments=True, dollar_quotes=True, e_strings=True),
    Dialect("mysql", backslash_escapes=True, hash_comments=True,
            dash_needs_space=True, exec_comments=True, double_quote_string=True,
            backtick_ident=True),
    Dialect("sqlite", backtick_ident=True, bracket_ident=True),
    Dialect("tsql", nested_comments=True, bracket_ident=True),
    Dialect("oracle", q_quotes=True),
)


# ─────────────────────────────────────────────────────────────
# Lexer
# ─────────────────────────────────────────────────────────────

WORD, STRING, IDENT, NUMBER, VAR, PUNCT, SEMI = (
    "word", "string", "ident", "number", "var", "punct", "semi")


@dataclass(frozen=True)
class Token:
    kind: str
    value: str

    @property
    def upper(self) -> str:
        return self.value.upper() if self.kind == WORD else ""


@dataclass
class Lexed:
    tokens: list = field(default_factory=list)
    complete: bool = True
    error: str = ""


def _is_word_start(c: str) -> bool:
    return c.isalpha() or c == "_"


def _is_word_char(c: str) -> bool:
    return c.isalnum() or c in "_$"


def _read_quoted(text: str, i: int, close: str, backslash: bool) -> int:
    """Index just past the closing quote of a literal opened at text[i-1];
    -1 when unterminated. A doubled closing quote is an escaped quote."""
    n = len(text)
    while i < n:
        c = text[i]
        if backslash and c == "\\":
            i += 2
            continue
        if c == close:
            if i + 1 < n and text[i + 1] == close:
                i += 2
                continue
            return i + 1
        i += 1
    return -1


_Q_PAIRS = {"[": "]", "(": ")", "{": "}", "<": ">"}


def lex(text: str, d: Dialect) -> Lexed:
    """Tokenise `text` under dialect `d`.

    Lenient: on an unterminated literal or comment it stops, keeps every token
    read so far, and reports `complete=False`. Tokens before the error are kept
    because a server that executes statements one at a time (MySQL
    multi-statements) runs them before it reaches the error.
    """
    out = Lexed()
    toks = out.tokens
    n = len(text)
    i = 0
    exec_comment_depth = 0

    def fail(msg: str) -> Lexed:
        out.complete = False
        out.error = f"{d.name}: {msg}"
        return out

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if c.isspace() or (ord(c) < 32):
            i += 1
            continue

        # ── comments ──
        if c == "-" and nxt == "-":
            after = text[i + 2] if i + 2 < n else ""
            if not d.dash_needs_space or after == "" or after.isspace() or ord(after) < 32:
                j = text.find("\n", i)
                i = n if j < 0 else j + 1
                continue
        if c == "#" and d.hash_comments:
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if c == "/" and nxt == "*":
            if d.exec_comments and i + 2 < n and text[i + 2] == "!":
                # MySQL executable comment: its body is code.
                i += 3
                while i < n and text[i].isdigit():
                    i += 1
                exec_comment_depth += 1
                continue
            depth = 1
            j = i + 2
            while j < n and depth:
                if d.nested_comments and text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            if depth:
                return fail("unterminated block comment")
            i = j
            continue
        if c == "*" and nxt == "/" and exec_comment_depth:
            exec_comment_depth -= 1
            i += 2
            continue

        # ── literals and quoted identifiers ──
        if c == "'":
            j = _read_quoted(text, i + 1, "'", d.backslash_escapes)
            if j < 0:
                return fail("unterminated string literal")
            toks.append(Token(STRING, text[i:j]))
            i = j
            continue
        if c == '"':
            if d.double_quote_string:
                j = _read_quoted(text, i + 1, '"', d.backslash_escapes)
                kind = STRING
            else:
                j = _read_quoted(text, i + 1, '"', False)
                kind = IDENT
            if j < 0:
                return fail("unterminated double-quoted token")
            toks.append(Token(kind, text[i:j]))
            i = j
            continue
        if c == "`" and d.backtick_ident:
            j = _read_quoted(text, i + 1, "`", False)
            if j < 0:
                return fail("unterminated backtick identifier")
            toks.append(Token(IDENT, text[i:j]))
            i = j
            continue
        if c == "[" and d.bracket_ident:
            j = _read_quoted(text, i + 1, "]", False)
            if j < 0:
                return fail("unterminated bracket identifier")
            toks.append(Token(IDENT, text[i:j]))
            i = j
            continue
        if c == "$" and d.dollar_quotes:
            j = i + 1
            while j < n and (_is_word_char(text[j]) and text[j] != "$"):
                j += 1
            tag_ok = j < n and text[j] == "$" and (j == i + 1 or _is_word_start(text[i + 1]))
            if tag_ok:
                tag = text[i:j + 1]
                end = text.find(tag, j + 1)
                if end < 0:
                    return fail("unterminated dollar-quoted string")
                toks.append(Token(STRING, text[i:end + len(tag)]))
                i = end + len(tag)
                continue
            if nxt.isdigit():                         # $1 positional parameter
                j = i + 1
                while j < n and text[j].isdigit():
                    j += 1
                toks.append(Token(VAR, text[i:j]))
                i = j
                continue

        # ── words (and prefixed literals E'..', N'..', q'[..]') ──
        if _is_word_start(c):
            j = i + 1
            while j < n and _is_word_char(text[j]):
                j += 1
            word = text[i:j]
            if j < n and text[j] == "'":
                low = word.lower()
                if d.q_quotes and low in ("q", "nq") and j + 1 < n:
                    opener = text[j + 1]
                    closer = _Q_PAIRS.get(opener, opener)
                    end = text.find(closer + "'", j + 2)
                    if end < 0:
                        return fail("unterminated q-quoted string")
                    toks.append(Token(STRING, text[i:end + 2]))
                    i = end + 2
                    continue
                if low in ("e", "x", "b", "n", "u", "_utf8", "_utf8mb4", "_latin1", "_binary"):
                    backslash = d.backslash_escapes or (d.e_strings and low == "e")
                    k = _read_quoted(text, j + 1, "'", backslash)
                    if k < 0:
                        return fail("unterminated prefixed string literal")
                    toks.append(Token(STRING, text[i:k]))
                    i = k
                    continue
            toks.append(Token(WORD, word))
            i = j
            continue

        if c.isdigit():
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] in "._"):
                j += 1
            toks.append(Token(NUMBER, text[i:j]))
            i = j
            continue

        if c in "@:?" :
            j = i + 1
            while j < n and (_is_word_char(text[j]) or text[j] == "@"):
                j += 1
            toks.append(Token(VAR, text[i:j]))
            i = j
            continue

        if c == ";":
            toks.append(Token(SEMI, ";"))
            i += 1
            continue

        toks.append(Token(PUNCT, c))
        i += 1

    if exec_comment_depth:
        return fail("unterminated executable comment")
    return out


def split_statements(tokens: Iterable[Token]) -> list[list[Token]]:
    stmts: list[list[Token]] = [[]]
    for t in tokens:
        if t.kind == SEMI:
            stmts.append([])
        else:
            stmts[-1].append(t)
    return [s for s in stmts if s]


# ─────────────────────────────────────────────────────────────
# Statement classification
# ─────────────────────────────────────────────────────────────

_READ_LEAD = frozenset({"SELECT", "WITH", "VALUES", "TABLE", "SHOW", "DESCRIBE",
                        "DESC", "EXPLAIN"})
_TXN_LEAD = frozenset({"BEGIN", "START", "COMMIT", "ROLLBACK", "END", "SAVEPOINT",
                       "RELEASE", "ABORT"})
_DESTRUCTIVE_KW = frozenset({"DROP", "TRUNCATE", "DELETE"})
_WRITE_KW = frozenset({"INSERT", "UPDATE", "MERGE", "REPLACE", "UPSERT", "COPY",
                       "LOAD", "IMPORT", "RENAME", "COMMENT", "CREATE", "ALTER"})
_PRIV_KW = frozenset({"GRANT", "REVOKE", "DENY"})
_DYNAMIC_KW = frozenset({"EXEC", "EXECUTE", "CALL", "DO", "PREPARE"})

# Keywords that open a data-changing statement wherever they appear: the
# leading word of a CTE body, a T-SQL batch with no semicolons, a PL/SQL block.
_EMBEDDED_KW = frozenset({"DROP", "TRUNCATE", "DELETE", "INSERT", "UPDATE", "MERGE",
                          "REPLACE", "UPSERT", "GRANT", "REVOKE", "ALTER", "CREATE",
                          "EXEC", "EXECUTE", "CALL", "PREPARE"})
# These three are also ordinary scalar functions: REPLACE(s, a, b), MySQL
# INSERT(s, pos, len, new) and TRUNCATE(x, d). Followed by '(' they are calls.
_ALSO_FUNCTIONS = frozenset({"REPLACE", "INSERT", "TRUNCATE"})
# `FOR UPDATE`, `FOR NO KEY UPDATE`, `ON UPDATE CASCADE`, `ON DELETE SET NULL`
# are clauses, not statements.
_CLAUSE_PREFIX = frozenset({"FOR", "KEY", "ON"})

_IAM_OBJECTS = frozenset({"USER", "ROLE", "LOGIN", "GROUP"})
_PERSIST_OBJECTS = frozenset({"TRIGGER", "EVENT", "RULE", "JOB", "TASK",
                              "SUBSCRIPTION", "PUBLICATION"})
_CODE_OBJECTS = frozenset({"FUNCTION", "PROCEDURE", "PROC", "EXTENSION", "LANGUAGE",
                           "SERVER", "PACKAGE", "ASSEMBLY", "LIBRARY"})
_SYSTEM_OBJECTS = frozenset({"SYSTEM", "INSTANCE", "CONFIGURATION"})
_CREATE_MODIFIERS = frozenset({"OR", "REPLACE", "TEMP", "TEMPORARY", "UNIQUE",
                               "GLOBAL", "LOCAL", "UNLOGGED", "MATERIALIZED",
                               "DEFINER", "ALGORITHM", "SQL", "SECURITY",
                               "CONSTRAINT", "RECURSIVE", "IF", "NOT", "EXISTS",
                               "TRUSTED", "PROCEDURAL", "EDITIONABLE",
                               "NONEDITIONABLE", "FORCE", "NO", "AGGREGATE"})

# Functions whose effect is outside the database or is itself dynamic SQL.
# A list, so it is incomplete by construction; see the module docstring.
_FUNCTION_CAPS: dict[str, tuple[str, ...]] = {
    **dict.fromkeys(("XP_CMDSHELL", "SP_OACREATE", "SP_OAMETHOD",
                     "SP_EXECUTE_EXTERNAL_SCRIPT", "SYS_EXEC", "SYS_EVAL",
                     "PG_EXECUTE_SERVER_PROGRAM", "DBMS_JAVA", "UTL_HTTP",
                     "UTL_TCP", "HTTPURITYPE", "UTL_SMTP"),
                    (CAP_CODE_EXEC,)),
    **dict.fromkeys(("PG_READ_FILE", "PG_READ_BINARY_FILE", "PG_LS_DIR",
                     "PG_STAT_FILE", "LOAD_FILE", "LO_IMPORT", "LO_EXPORT",
                     "PG_FILE_WRITE", "UTL_FILE", "BULK"),
                    (CAP_CODE_EXEC,)),
    **dict.fromkeys(("SP_EXECUTESQL", "SP_SQLEXEC", "DBMS_SQL", "DBLINK",
                     "DBLINK_EXEC", "OPENROWSET", "OPENQUERY", "OPENDATASOURCE",
                     "QUERY_TO_XML"),
                    (CAP_CODE_EXEC, CAP_UNCLASSIFIED)),
    **dict.fromkeys(("DBMS_SCHEDULER", "DBMS_JOB", "SP_ADD_JOB", "SP_ADD_JOBSTEP"),
                    (CAP_PERSISTENCE, CAP_CODE_EXEC)),
    **dict.fromkeys(("PG_TERMINATE_BACKEND", "PG_CANCEL_BACKEND"),
                    (CAP_INFRA_DESTRUCTIVE,)),
    **dict.fromkeys(("SET_CONFIG", "PG_RELOAD_CONF", "SP_CONFIGURE"),
                    (CAP_SECURITY_CONTROL,)),
}


@dataclass(frozen=True)
class StatementClass:
    kind: str
    caps: frozenset
    lead: str = ""
    text: str = ""


def _words(stmt: list[Token]) -> list[str]:
    return [t.upper for t in stmt if t.kind == WORD]


def _object_after(stmt: list[Token], i: int) -> str:
    """The object keyword of CREATE/ALTER/DROP at index i, skipping modifiers
    such as `OR REPLACE`, `TEMPORARY`, `IF NOT EXISTS`, `DEFINER=...`."""
    j = i + 1
    while j < len(stmt):
        t = stmt[j]
        if t.kind == WORD and t.upper not in _CREATE_MODIFIERS:
            return t.upper
        if t.kind not in (WORD, PUNCT, VAR, STRING, IDENT, NUMBER):
            return ""
        j += 1
    return ""


# Identifier word-parts that name audit evidence. A destructive statement whose
# TARGET carries one of these destroys or rewrites audit evidence, which the
# shipped policy denies outright (log.tamper). Matched on whole word-parts of
# the target identifiers, not substrings, so `catalog`, `login` and
# `order_history` stay ordinary data (independent review remediation: before
# this, `DROP TABLE audit_log` through a SQL tool classified only as
# data.destructive, which is APPROVAL, so a valid approval executed it).
_EVIDENCE_PARTS = frozenset({"AUDIT", "AUDITS", "AUDITLOG", "AUDITLOGS", "LOG", "LOGS",
                             "EVENTLOG", "EVENTLOGS", "TRAIL", "TRAILS", "FORENSIC",
                             "FORENSICS", "EVIDENCE"})
_IDENT_SPLIT = re.compile(r"[^A-Za-z0-9]+")


def _targets_evidence(stmt: list[Token], i: int) -> bool:
    """Whether the statement at i names an audit-evidence relation before its
    first WHERE / SET clause."""
    for t in stmt[i + 1:]:
        if t.kind == WORD and t.upper in ("WHERE", "SET", "USING", "RETURNING"):
            return False
        if t.kind in (WORD, IDENT):
            if _EVIDENCE_PARTS & {p.upper() for p in _IDENT_SPLIT.split(t.value) if p}:
                return True
    return False


def _keyword_caps(stmt: list[Token], i: int, kw: str) -> tuple[str, frozenset]:
    """Class and capabilities of the statement opened by keyword `kw` at i."""
    words = _words(stmt[i:])
    if kw in ("DROP", "TRUNCATE", "DELETE"):
        obj = _object_after(stmt, i) if kw == "DROP" else ""
        caps = {CAP_DATA_DESTRUCTIVE}
        if obj in _IAM_OBJECTS:
            caps.add(CAP_IAM_PRIVILEGED)
        if obj in _PERSIST_OBJECTS:
            caps.add(CAP_SECURITY_CONTROL)
        if _targets_evidence(stmt, i):
            caps.add(CAP_LOG_TAMPER)
        return DESTRUCTIVE, frozenset(caps)
    if kw == "UPDATE":
        # An UPDATE with no WHERE clause rewrites every row: destructive.
        if "WHERE" in words:
            caps = {CAP_DATA_WRITE}
            klass = WRITE
        else:
            caps = {CAP_DATA_DESTRUCTIVE, CAP_DATA_WRITE}
            klass = DESTRUCTIVE
        if _targets_evidence(stmt, i):
            # Rewriting audit evidence, scoped or not, is tampering with it.
            caps.add(CAP_LOG_TAMPER)
        return klass, frozenset(caps)
    if kw in _PRIV_KW:
        return PRIVILEGE, frozenset({CAP_IAM_PRIVILEGED})
    if kw in _DYNAMIC_KW:
        return DYNAMIC, frozenset({CAP_CODE_EXEC, CAP_UNCLASSIFIED})
    if kw == "COPY":
        if "PROGRAM" in words:
            return DYNAMIC, frozenset({CAP_CODE_EXEC, CAP_DATA_WRITE})
        return WRITE, frozenset({CAP_DATA_WRITE})
    if kw in ("CREATE", "ALTER"):
        obj = _object_after(stmt, i)
        if obj in _IAM_OBJECTS:
            caps = {CAP_IAM_PRIVILEGED}
            if kw == "ALTER":
                caps.add(CAP_CREDENTIAL_CHANGE)
            return PRIVILEGE, frozenset(caps)
        if obj in _PERSIST_OBJECTS:
            return WRITE, frozenset({CAP_PERSISTENCE, CAP_CODE_EXEC})
        if obj in _CODE_OBJECTS:
            return DYNAMIC, frozenset({CAP_CODE_EXEC, CAP_PERSISTENCE})
        if obj in _SYSTEM_OBJECTS or obj == "POLICY":
            return WRITE, frozenset({CAP_SECURITY_CONTROL})
        if kw == "ALTER":
            caps = {CAP_DATA_DESTRUCTIVE, CAP_DATA_WRITE}
            if "DISABLE" in words or "NOCHECK" in words:
                caps.add(CAP_SECURITY_CONTROL)
            return DESTRUCTIVE, frozenset(caps)
        return WRITE, frozenset({CAP_DATA_WRITE})
    if kw in _WRITE_KW:
        return WRITE, frozenset({CAP_DATA_WRITE})
    return UNCLASSIFIED, frozenset({CAP_UNCLASSIFIED})


def _is_clause(stmt: list[Token], i: int, kw: str) -> bool:
    """Whether the keyword at i is a clause or a function, not a statement."""
    prev = stmt[i - 1] if i > 0 else None
    nxt = stmt[i + 1] if i + 1 < len(stmt) else None
    if prev is not None and prev.kind == PUNCT and prev.value == ".":
        return True                                   # t.update, s.delete
    if kw in _ALSO_FUNCTIONS and nxt is not None and nxt.kind == PUNCT and nxt.value == "(":
        return True
    if kw in ("UPDATE", "DELETE") and prev is not None and prev.upper in _CLAUSE_PREFIX:
        # ... unless what follows is unmistakably an UPDATE statement.
        return not _has_shape(stmt, i, kw)
    return False


_TRUNCATE_OPTIONS = frozenset({"CASCADE", "RESTRICT", "RESTART", "CONTINUE",
                               "IDENTITY", "DROP", "REUSE", "STORAGE", "IMMEDIATE",
                               "PURGE"})


_DELETE_TAIL = frozenset({"WHERE", "USING", "RETURNING", "OUTPUT", "LIMIT", "ORDER",
                          "PARTITION", "FROM", "WITH", "OPTION"})
_INSERT_MODIFIERS = frozenset({"IGNORE", "LOW_PRIORITY", "DELAYED", "HIGH_PRIORITY",
                               "OVERWRITE", "ALL", "FIRST", "OR", "REPLACE", "ROLLBACK",
                               "ABORT", "FAIL"})
_INSERT_TAIL = frozenset({"VALUES", "VALUE", "SELECT", "DEFAULT", "SET", "WITH",
                          "USING", "OVERRIDING", "OUTPUT", "PARTITION", "TABLE",
                          "EXEC", "EXECUTE"})


def _parse_name(rest: list[Token], pos: int) -> int:
    """Index after a possibly qualified name (`a`, `a.b`, `"a".[b]`) at pos;
    -1 when there is no name there."""
    if pos >= len(rest) or rest[pos].kind not in (WORD, IDENT):
        return -1
    pos += 1
    while pos + 1 < len(rest) and rest[pos].kind == PUNCT and rest[pos].value == "." \
            and rest[pos + 1].kind in (WORD, IDENT):
        pos += 2
    return pos


def _has_shape(stmt: list[Token], i: int, kw: str) -> bool:
    """Whether the tokens from i have the unambiguous shape of statement `kw`.
    Used to tell SQL from prose in sniff mode."""
    rest = stmt[i + 1:]
    w = [t.upper for t in rest[:8]]

    if not rest:
        return False
    if kw == "DROP":
        return _object_after(stmt, i) in {
            "TABLE", "DATABASE", "SCHEMA", "VIEW", "INDEX", "USER", "ROLE",
            "FUNCTION", "PROCEDURE", "TRIGGER", "SEQUENCE", "TYPE", "COLUMN",
            "CONSTRAINT", "OWNED", "EXTENSION", "EVENT", "LOGIN", "POLICY",
            "TABLESPACE", "COLLECTION", "KEYSPACE", "PARTITION", "SYNONYM"}
    if kw == "TRUNCATE":
        pos = 0
        while pos < len(rest) and rest[pos].upper in ("TABLE", "ONLY"):
            pos += 1
        while True:
            pos = _parse_name(rest, pos)
            if pos < 0:
                return False
            if pos < len(rest) and rest[pos].kind == PUNCT and rest[pos].value == "*":
                pos += 1
            if pos < len(rest) and rest[pos].kind == PUNCT and rest[pos].value == ",":
                pos += 1
                continue
            break
        return all(t.kind == WORD and t.upper in _TRUNCATE_OPTIONS for t in rest[pos:])
    if kw == "DELETE":
        # DELETE [FROM] <name> [alias] then the end of the statement or a
        # clause keyword. "Delete from my calendar the dentist" is prose.
        pos = 1 if w[:1] == ["FROM"] else 0
        if pos == 0 and not (len(rest) >= 2 and rest[1].upper in _DELETE_TAIL | {"FROM"}):
            return False
        pos = _parse_name(rest, pos)
        if pos < 0:
            return False
        if pos < len(rest) and rest[pos].upper == "AS":
            pos += 1
        if pos < len(rest) and rest[pos].kind in (WORD, IDENT) and \
                rest[pos].upper not in _DELETE_TAIL:
            pos += 1                                  # alias
        return pos >= len(rest) or rest[pos].upper in _DELETE_TAIL or (
            rest[pos].kind == PUNCT and rest[pos].value in ",*")
    if kw == "UPDATE":
        pos = 0
        while pos < len(rest) and rest[pos].upper in ("ONLY", "LOW_PRIORITY", "IGNORE"):
            pos += 1
        pos = _parse_name(rest, pos)
        if pos < 0:
            return False
        if pos < len(rest) and rest[pos].upper == "AS":
            pos += 1
        if pos < len(rest) and rest[pos].kind in (WORD, IDENT) and rest[pos].upper != "SET":
            pos += 1                                  # alias
        return pos < len(rest) and rest[pos].upper == "SET"
    if kw in ("INSERT", "REPLACE", "UPSERT", "MERGE"):
        pos = 0
        while pos < len(rest) and rest[pos].upper in _INSERT_MODIFIERS:
            pos += 1
        if pos < len(rest) and rest[pos].upper == "INTO":
            pos += 1
        elif not (kw == "INSERT" and pos > 0 and rest[pos - 1].upper == "OVERWRITE"):
            return False
        if pos < len(rest) and rest[pos].upper == "TABLE":
            pos += 1
        pos = _parse_name(rest, pos)
        if pos < 0:
            return False
        if pos < len(rest) and rest[pos].upper == "AS":
            pos += 1
        if pos < len(rest) and rest[pos].kind in (WORD, IDENT) and \
                rest[pos].upper not in _INSERT_TAIL:
            pos += 1                                  # alias
        return pos >= len(rest) or rest[pos].upper in _INSERT_TAIL or (
            rest[pos].kind == PUNCT and rest[pos].value == "(")
    if kw in ("GRANT", "REVOKE"):
        ws = _words(rest)
        return ("ON" in ws and ("TO" in ws or "FROM" in ws)) or (
            "TO" in ws or "FROM" in ws) and any(x in ws for x in (
                "ALL", "SELECT", "INSERT", "UPDATE", "DELETE", "USAGE", "EXECUTE",
                "ROLE", "ADMIN", "SUPERUSER", "DBA", "PRIVILEGES", "CONNECT",
                "CREATE", "OWNERSHIP", "REFERENCES", "TRIGGER", "TEMPORARY"))
    if kw in ("ALTER", "CREATE"):
        return _object_after(stmt, i) in {
            "TABLE", "USER", "ROLE", "DATABASE", "SYSTEM", "SCHEMA", "VIEW",
            "INDEX", "LOGIN", "SERVER", "FUNCTION", "PROCEDURE", "SEQUENCE",
            "POLICY", "TRIGGER", "EVENT", "EXTENSION", "RULE", "TYPE", "PROC",
            "INSTANCE", "TABLESPACE", "PACKAGE", "LANGUAGE", "SUBSCRIPTION",
            "PUBLICATION", "ASSEMBLY", "JOB", "TASK"}
    if kw in ("EXEC", "EXECUTE"):
        first = rest[0]
        if first.upper == "IMMEDIATE" or first.kind in (STRING, VAR):
            return True
        if first.kind == PUNCT and first.value == "(":
            return True
        if first.kind == WORD and first.upper.startswith(("SP_", "XP_", "DBMS_", "MASTER")):
            return True
        return len(rest) >= 2 and first.kind in (WORD, IDENT) and (
            rest[1].kind == PUNCT and rest[1].value in "(." or rest[1].upper == "USING")
    if kw == "CALL":
        return len(rest) >= 2 and rest[0].kind in (WORD, IDENT) and \
            rest[1].kind == PUNCT and rest[1].value in "(."
    if kw == "PREPARE":
        return "FROM" in _words(rest) or "AS" in _words(rest)
    if kw == "COPY":
        ws = _words(rest)
        return "FROM" in ws or "TO" in ws
    return False


def classify_statement(stmt: list[Token], *, strict: bool) -> list[StatementClass]:
    """Classify one statement. Returns every class found (the leading
    statement and any statement embedded in it); empty when sniff mode finds
    no SQL-shaped statement."""
    found: list[StatementClass] = []
    j = 0
    while j < len(stmt) and stmt[j].kind == PUNCT and stmt[j].value == "(":
        j += 1
    lead_tok = stmt[j] if j < len(stmt) else None
    lead = lead_tok.upper if lead_tok is not None else ""
    lead_index = j

    if strict:
        if lead in _READ_LEAD:
            words = _words(stmt)
            if lead == "EXPLAIN":
                kind, caps = READ, frozenset()
            elif "INTO" in words:
                # SELECT ... INTO new_table / INTO OUTFILE / INTO DUMPFILE
                kind, caps = WRITE, frozenset({CAP_DATA_WRITE})
                if "OUTFILE" in words or "DUMPFILE" in words:
                    caps = caps | {CAP_CODE_EXEC}
            else:
                kind, caps = READ, frozenset()
            found.append(StatementClass(kind, caps, lead))
        elif lead in _TXN_LEAD:
            found.append(StatementClass(TRANSACTION, frozenset(), lead))
        elif lead in _DESTRUCTIVE_KW | _WRITE_KW | _PRIV_KW | _DYNAMIC_KW:
            kind, caps = _keyword_caps(stmt, lead_index, lead)
            found.append(StatementClass(kind, caps, lead))
        else:
            # Unknown statement type, or a statement that does not begin with
            # a keyword at all (`{call p()}`, a bare string): fail closed.
            found.append(StatementClass(UNCLASSIFIED, frozenset({CAP_UNCLASSIFIED}),
                                        lead or (lead_tok.value if lead_tok else "")))

    for k, tok in enumerate(stmt):
        if tok.kind != WORD:
            continue
        kw = tok.upper
        if kw in _FUNCTION_CAPS:
            nxt = stmt[k + 1] if k + 1 < len(stmt) else None
            prev = stmt[k - 1] if k > 0 else None
            called = nxt is not None and nxt.kind == PUNCT and nxt.value == "("
            executed = prev is not None and prev.upper in ("EXEC", "EXECUTE", "CALL")
            if called or executed or strict:
                found.append(StatementClass(
                    DYNAMIC, frozenset(_FUNCTION_CAPS[kw]), kw))
            continue
        if kw not in _EMBEDDED_KW:
            continue
        if strict and k == lead_index:
            continue
        if _is_clause(stmt, k, kw):
            continue
        if not strict and not _has_shape(stmt, k, kw):
            continue
        kind, caps = _keyword_caps(stmt, k, kw)
        found.append(StatementClass(kind, caps, kw))
    return found


@dataclass(frozen=True)
class SqlReading:
    """The union of every dialect's reading of one text."""
    caps: frozenset
    classes: tuple
    complete_in: tuple            # dialects that lexed the whole text
    errors: tuple

    @property
    def kinds(self) -> frozenset:
        return frozenset(c.kind for c in self.classes)


def _variants(text: str) -> list[str]:
    folded = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return [text] if folded == text else [text, folded]


def read_sql(text: str, *, strict: bool) -> SqlReading:
    """Classify `text` under every dialect and union the result."""
    if not isinstance(text, str):
        text = str(text)
    if strict and len(text) > MAX_SQL_CHARS:
        return SqlReading(frozenset({CAP_UNCLASSIFIED}),
                          (StatementClass(UNCLASSIFIED, frozenset({CAP_UNCLASSIFIED}),
                                          "", "too long to classify"),),
                          (), ("text exceeds MAX_SQL_CHARS",))
    caps: set[str] = set()
    classes: list[StatementClass] = []
    complete: list[str] = []
    errors: list[str] = []
    variants = _variants(text)
    if not strict and ("'" in text or '"' in text):
        # Injection context: a value that a tool interpolates into a quoted
        # literal (`WHERE name = '{value}'`) is read from inside that literal.
        # `x'; DELETE FROM users; --` is one unterminated string to a reader
        # that starts outside the quote and two statements to the database.
        variants += [q + v for v in list(variants) for q in ("'", '"')]
    for variant in variants:
        for d in DIALECTS:
            lexed = lex(variant, d)
            if lexed.complete:
                complete.append(d.name)
            else:
                errors.append(lexed.error)
            for stmt in split_statements(lexed.tokens):
                for cls in classify_statement(stmt, strict=strict):
                    classes.append(cls)
                    caps |= cls.caps
    if strict and not complete:
        # No dialect could read it to the end: nothing here establishes what
        # the server would run.
        caps.add(CAP_UNCLASSIFIED)
        classes.append(StatementClass(UNCLASSIFIED, frozenset({CAP_UNCLASSIFIED}),
                                      "", "; ".join(errors)))
    return SqlReading(frozenset(caps), tuple(classes),
                      tuple(dict.fromkeys(complete)), tuple(errors))


# ─────────────────────────────────────────────────────────────
# Which argument values are SQL
# ─────────────────────────────────────────────────────────────

# Argument names that carry SQL whatever the tool is called.
SQL_KEYS = frozenset({
    "sql", "sql_query", "sql_text", "sql_statement", "raw_sql", "rawsql",
    "statement", "statements", "stmt", "stmts", "queries", "ddl", "dml",
})
# Argument names that carry SQL when the TOOL is a database tool.
DB_TOOL_KEYS = SQL_KEYS | frozenset({"query", "q", "script", "command", "cmd",
                                      "code", "body", "text", "input"})

_DB_TOOL_HINTS = ("sql", "database", "query_db", "db_query", "querydb", "dbquery",
                  "postgres", "psql", "mysql", "mariadb", "sqlite", "mssql",
                  "tsql", "oracle", "bigquery", "snowflake", "redshift", "athena",
                  "clickhouse", "duckdb", "warehouse", "run_query",
                  "execute_query", "exec_query")


def is_db_tool(tool: str) -> bool:
    from morrison_governance.kernel.normalize import canonical_tool, normalized_tool_name
    name = normalized_tool_name(tool)
    if canonical_tool(tool) == "db_query":
        return True
    padded = f"_{name}_"
    return any(h in name for h in _DB_TOOL_HINTS) or "_db_" in padded


_JSON_MAX = 200_000


def _string_values(value: Any, key: str = "", depth: int = 0):
    """(key, string) for every string reachable in `value`, decoding strings
    that are themselves JSON documents (one level of `{"sql": "..."}` carried
    as text is the common wrapper shape)."""
    from morrison_governance.kernel.normalize import BudgetExhausted, iter_pairs
    try:
        pairs = list(iter_pairs(value))
    except BudgetExhausted:
        return
    if isinstance(value, str):
        pairs = [(key, value)]
    for k, v in pairs:
        if not isinstance(v, str):
            continue
        yield k, v
        s = v.strip()
        if depth < 3 and len(s) <= _JSON_MAX and s[:1] in "{[" and s[-1:] in "}]":
            try:
                decoded = json.loads(s)
            except (ValueError, RecursionError):
                continue
            if isinstance(decoded, (dict, list)):
                yield from _string_values(decoded, k, depth + 1)


def sql_capabilities(tool: str, args: dict) -> tuple[frozenset, list[dict]]:
    """Capabilities of the SQL carried in a call's arguments.

    Returns (capabilities, findings). Each finding records which argument was
    read, in which mode, and what it was classified as, so an escalation can
    say why.
    """
    caps: set[str] = set()
    findings: list[dict] = []
    db_tool = is_db_tool(tool)
    strict_keys = DB_TOOL_KEYS if db_tool else SQL_KEYS
    for key, text in _string_values(args or {}):
        k = str(key).strip().lower()
        strict = k in strict_keys
        if not strict and not _could_be_sql(text):
            continue
        reading = read_sql(text, strict=strict)
        if reading.caps:
            caps |= reading.caps
            findings.append({"arg": k, "mode": "strict" if strict else "sniff",
                             "classes": sorted(reading.kinds),
                             "capabilities": sorted(reading.caps)})
    return frozenset(caps), findings


_PREFILTER = tuple(w.lower() for w in (_EMBEDDED_KW | set(_FUNCTION_CAPS)))


def _could_be_sql(text: str) -> bool:
    """Cheap pre-filter for sniff mode: only lex text containing a statement
    keyword or a listed function name somewhere."""
    low = text.lower()
    return any(w in low for w in _PREFILTER)
