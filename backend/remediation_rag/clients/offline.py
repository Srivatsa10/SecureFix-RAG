"""OFFLINE stand-ins used when `APP_MODE=offline` (no AWS / Pinecone credentials).

* `HashingEmbeddings` - deterministic bag-of-words feature hashing. Gives meaningful
  lexical similarity so offline retrieval is not random, but it is not a semantic model.
* `OfflinePatchGenerator` - a rule-based SQL parameterizer. It does NOT call an LLM;
  it rewrites common injection shapes (Python f-strings / %-formatting / concatenation /
  SQLAlchemy text(), JS template literals / concatenation, JDBC and JPA concatenation)
  into parameterized queries. When no rule matches it returns the code unchanged (so the
  evaluator fails it and the graph escalates). Output is labelled as offline.

These exist so the LangGraph pipeline, API, UI and tests run end-to-end without keys.
"""

from __future__ import annotations

import difflib
import hashlib
import math
import re
from dataclasses import dataclass

from langchain_core.embeddings import Embeddings

from remediation_rag.domain import Chunk, Citation, PatchDraft
from remediation_rag.generation import DraftContext, GenerationResult
from remediation_rag.telemetry import stopwatch

OFFLINE_MODEL_NAME = "offline-rule-based-generator"
OFFLINE_BANNER = "OFFLINE MODE: rule-based rewrite, no LLM was called."

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]+|[^\sA-Za-z0-9_]")


class HashingEmbeddings(Embeddings):
    """Deterministic hashed bag-of-words embeddings (offline only)."""

    def __init__(self, dimensions: int = 512) -> None:
        self.dimensions = dimensions

    def _embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        for token in _TOKEN.findall(text.lower()):
            digest = hashlib.blake2b(token.encode(), digest_size=8).digest()
            index = int.from_bytes(digest[:4], "little") % self.dimensions
            vector[index] += 1.0 if digest[4] & 1 else -1.0
        norm = math.sqrt(sum(v * v for v in vector)) or 1.0
        return [v / norm for v in vector]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)


# --------------------------------------------------------------------------------------
# Rule-based rewrites
# --------------------------------------------------------------------------------------

_SQL_WORD = re.compile(r"\b(select|insert|update|delete|where|values|set)\b", re.IGNORECASE)


@dataclass(frozen=True)
class Rewrite:
    code: str
    technique: str


# DB-API "paramstyle" differs per driver: sqlite3 is qmark (`?`), most others are `%s`.
_QMARK_DRIVERS = frozenset({"sqlite3", "sqlite", "pyodbc"})


def _python_rewrite(code: str, framework: str | None) -> Rewrite | None:
    ph = "?" if framework in _QMARK_DRIVERS else "%s"

    # cursor.execute(f"... '{expr}' ...")  ->  cursor.execute("... %s ...", (expr,))
    pattern = re.compile(r"""(\.execute\(\s*)f(["'])(.*?)\2(\s*\))""", re.DOTALL)

    def repl(match: re.Match[str]) -> str:
        prefix, quote, body, suffix = match.groups()
        if not _SQL_WORD.search(body):
            return match.group(0)
        args: list[str] = []

        def bind(m: re.Match[str]) -> str:
            args.append(m.group(1).strip())
            return ph

        body = re.sub(r"""['"]?\{([^{}]+)\}['"]?""", bind, body)
        tuple_src = ", ".join(args) + ("," if len(args) == 1 else "")
        return f"{prefix}{quote}{body}{quote}, ({tuple_src}){suffix}"

    rewritten = pattern.sub(repl, code)
    if rewritten != code:
        return Rewrite(rewritten, f"bound f-string interpolations as {ph} parameters")

    # text(f"... '%{term}%' ...")  ->  text("... :term ..."), params {"term": f"%{term}%"}
    text_call = re.compile(r"""text\(\s*f(["'])(.*?)\1\s*\)""", re.DOTALL)
    match = text_call.search(code)
    if match and _SQL_WORD.search(match.group(2)):
        quote, body = match.groups()
        params: dict[str, str] = {}

        def bind_named(m: re.Match[str]) -> str:
            lead, expr, trail = m.group(1), m.group(2).strip(), m.group(3)
            name = re.sub(r"\W", "_", expr.split(".")[-1]).strip("_") or f"p{len(params)}"
            params[name] = f'f"{lead}{{{expr}}}{trail}"' if lead or trail else expr
            return f":{name}"

        body = re.sub(r"""['"]?(%?)\{([^{}]+)\}(%?)['"]?""", bind_named, body)
        new = code[: match.start()] + f"text({quote}{body}{quote})" + code[match.end() :]
        param_src = "{" + ", ".join(f'"{k}": {v}' for k, v in params.items()) + "}"
        executed = re.sub(r"\.execute\(\s*(\w+)\s*\)", rf".execute(\1, {param_src})", new, count=1)
        if executed == new:  # inline form: session.execute(text("..."))
            executed = new.replace(
                f"text({quote}{body}{quote}))", f"text({quote}{body}{quote}), {param_src})", 1
            )
        return Rewrite(executed, "switched text() to named bind parameters")

    # "... '%s' ..." % expr   ->   "... %s ...", [expr]   (Django raw / DB-API params)
    percent = re.compile(
        r"""(["'])([^"'\n]*?)'?%s'?([^"'\n]*?)\1[ \t]*%[ \t]*"""
        r"""(?:\([ \t]*([\w.\[\]]+)[ \t]*,?[ \t]*\)|([\w.\[\]]+))"""
    )
    match = percent.search(code)
    if match and _SQL_WORD.search(match.group(2)):
        quote, head, tail = match.group(1, 2, 3)
        expr = match.group(4) or match.group(5)
        bound = f"[{expr}]" if framework == "django" else f"({expr},)"
        new = (
            code[: match.start()] + f"{quote}{head}{ph}{tail}{quote}, {bound}" + code[match.end() :]
        )
        return Rewrite(new, "passed the value as a driver parameter instead of %-formatting")

    # query = "... '" + expr + "' ..." ; cursor.execute(query)
    concat = re.compile(
        r"""(["'])([^"'\n]*?)'?\1\s*\+\s*([\w.\[\]()'"]+?)\s*\+\s*(["'])'?([^"'\n]*?)\4"""
    )
    match = concat.search(code)
    if match and _SQL_WORD.search(match.group(2)):
        quote = match.group(1)
        expr = match.group(3)
        sql = f"{quote}{match.group(2)}{ph}{match.group(5)}{quote}"
        new = code[: match.start()] + sql + code[match.end() :]
        new = re.sub(r"\.execute\(\s*(\w+)\s*\)", rf".execute(\1, ({expr},))", new, count=1)
        return Rewrite(new, f"replaced string concatenation with a {ph} parameter")
    return None


def _js_rewrite(code: str, framework: str | None) -> Rewrite | None:
    # node-postgres numbers its placeholders; mysql/mysql2 and Sequelize replacements use `?`.
    numbered = framework in (None, "pg", "postgres", "node-postgres")

    def placeholder(n: int) -> str:
        return f"${n}" if numbered else "?"

    # db.query(`... '${expr}' ...`)  ->  db.query('... $1 ...', [expr])
    pattern = re.compile(r"(\.query\(\s*)`([^`]*)`(\s*[,)])", re.DOTALL)

    def repl(match: re.Match[str]) -> str:
        prefix, body, suffix = match.groups()
        if not _SQL_WORD.search(body):
            return match.group(0)
        args: list[str] = []

        def bind(m: re.Match[str]) -> str:
            args.append(m.group(1).strip())
            return placeholder(len(args))

        body = re.sub(r"""['"]?\$\{([^{}]+)\}['"]?""", bind, body)
        if framework == "sequelize":
            opts = f"{{ replacements: [{', '.join(args)}]"
            return f"{prefix}'{body}', " + (f"{opts} }})" if suffix.strip() == ")" else f"{opts},")
        return f"{prefix}'{body}', [{', '.join(args)}]{suffix}"

    rewritten = pattern.sub(repl, code)
    if framework == "sequelize" and rewritten != code:
        # `{ replacements: [...],` was opened above; merge it into the existing options object.
        rewritten = re.sub(
            r"\{ replacements: \[([^\]]*)\],\s*\{", r"{ replacements: [\1],", rewritten
        )
    if rewritten != code:
        return Rewrite(rewritten, "bound template-literal interpolations as query parameters")

    # conn.query("... '" + expr + "' ...", cb)  ->  conn.query("... ? ...", [expr], cb)
    concat = re.compile(
        r"""(\.query\(\s*)(["'])([^"'\n]*?)'?\2\s*\+\s*([\w.\[\]]+)\s*\+\s*\2'?([^"'\n]*)\2(\s*[,)])"""
    )
    match = concat.search(code)
    if match and _SQL_WORD.search(match.group(3)):
        prefix, quote, head, expr, tail, suffix = match.groups()
        call = f"{prefix}{quote}{head}{placeholder(1)}{tail}{quote}, [{expr}]{suffix}"
        return Rewrite(
            code[: match.start()] + call + code[match.end() :],
            "replaced string concatenation with a bound query parameter",
        )
    return None


def _jpa_rewrite(code: str) -> Rewrite | None:
    # em.createQuery("... = '" + x + "'", T.class)  ->  createQuery("... = :x", T.class)
    #                                                   .setParameter("x", x)
    pattern = re.compile(
        r"""(?P<call>\.create(?:Native)?Query\(\s*)"(?P<head>[^"]*?)'?"\s*\+\s*"""
        r"""(?P<expr>[\w.()]+)\s*\+\s*"'?(?P<tail>[^"]*)"(?P<rest>\s*(?:,\s*[\w.]+)?\s*\))"""
    )
    match = pattern.search(code)
    if not match or not _SQL_WORD.search(match.group("head")):
        return None
    name = re.sub(r"\W", "", match.group("expr").split(".")[-1]) or "value"
    replacement = (
        f'{match.group("call")}"{match.group("head")}:{name}{match.group("tail")}"'
        f'{match.group("rest")}\n            .setParameter("{name}", {match.group("expr")})'
    )
    return Rewrite(
        code[: match.start()] + replacement + code[match.end() :],
        "used a named JPQL parameter bound with setParameter",
    )


def _java_rewrite(code: str, framework: str | None) -> Rewrite | None:
    if (jpa := _jpa_rewrite(code)) is not None:
        return jpa
    # Statement st = conn.createStatement(); ResultSet rs = st.executeQuery("..'" + x + "'..");
    exec_pattern = re.compile(
        r"""(?P<indent>[ \t]*)(?P<lhs>ResultSet\s+\w+\s*=\s*)(?P<stmt>\w+)\.executeQuery\(\s*"""
        r""""(?P<head>[^"]*?)'?"\s*\+\s*(?P<expr>[\w.()]+)\s*\+\s*"'?(?P<tail>[^"]*)"\s*\);"""
    )
    match = exec_pattern.search(code)
    if not match or not _SQL_WORD.search(match.group("head")):
        return None
    indent, stmt = match.group("indent"), match.group("stmt")
    sql = f"{match.group('head')}?{match.group('tail')}"
    replacement = (
        f'{indent}PreparedStatement {stmt} = connection.prepareStatement("{sql}");\n'
        f"{indent}{stmt}.setString(1, {match.group('expr')});\n"
        f"{indent}{match.group('lhs')}{stmt}.executeQuery();"
    )
    new = code[: match.start()] + replacement + code[match.end() :]
    new = re.sub(rf"[ \t]*Statement\s+{stmt}\s*=\s*\w+\.createStatement\(\);\n", "", new)
    return Rewrite(new, "switched Statement concatenation to PreparedStatement with setString")


_REWRITERS = {
    "python": _python_rewrite,
    "javascript": _js_rewrite,
    "typescript": _js_rewrite,
    "java": _java_rewrite,
}


def unified_diff(original: str, patched: str, path: str = "snippet") -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class OfflinePatchGenerator:
    """Rule-based patch drafts for offline demos. Clearly labelled; never an LLM."""

    @property
    def is_offline(self) -> bool:
        return True

    async def generate(self, context: DraftContext) -> GenerationResult:
        with stopwatch() as watch:
            draft = self._draft(context)
        prompt_size = len(context.request.code) + sum(
            len(c.text) for c in context.internal_chunks + context.owasp_chunks
        )
        return GenerationResult(
            draft=draft,
            model=OFFLINE_MODEL_NAME,
            input_tokens=_estimate_tokens("x" * prompt_size),
            output_tokens=_estimate_tokens(draft.model_dump_json()),
            latency_ms=watch.elapsed_ms,
            offline=True,
        )

    def _draft(self, context: DraftContext) -> PatchDraft:
        request = context.request
        language = request.language.value if request.language else "python"
        rewriter = _REWRITERS.get(language)
        rewrite = rewriter(request.code, request.framework) if rewriter else None

        top_internal: Chunk | None = context.internal_chunks[0] if context.internal_chunks else None
        top_owasp: Chunk | None = context.owasp_chunks[0] if context.owasp_chunks else None

        citations = [
            Citation(chunk_id=c.id, reason=reason)
            for c, reason in (
                (top_internal, "approved parameterized-query convention"),
                (top_owasp, "OWASP primary defense: parameterized queries"),
            )
            if c is not None
        ]
        conventions = (
            [f"{top_internal.framework} {top_internal.kind.replace('_', ' ')}"]
            if top_internal
            else []
        )

        if rewrite is not None:
            patched = rewrite.code
            explanation = (
                f"{OFFLINE_BANNER} The original builds SQL text from untrusted input, so an "
                f"attacker can change the query's structure. The rewrite {rewrite.technique}, "
                "so the driver sends data separately from the SQL statement."
            )
        else:
            # Do not dress up a snippet as a fix: return the code unchanged so the evaluator
            # (correctly) fails it and the graph escalates to a human.
            patched = request.code
            explanation = (
                f"{OFFLINE_BANNER} No rewrite rule matched this code shape, so no patch was "
                "produced. See the cited approved pattern and OWASP guidance for the fix."
            )
        return PatchDraft(
            explanation=explanation,
            patched_code=patched,
            diff=unified_diff(request.code, patched, request.file_path or "snippet"),
            conventions_applied=conventions,
            citations=citations,
        )
