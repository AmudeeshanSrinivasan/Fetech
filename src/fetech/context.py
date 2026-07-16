"""Bounded context broker for Graphify, QMD, and exact source evidence."""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from pathlib import Path

from fetech.models import ContextBundle, ContextSource


@dataclass(frozen=True)
class ContextBudget:
    graphify_tokens: int = 1_200
    qmd_tokens: int = 1_200
    source_tokens: int = 2_000
    total_tokens: int = 4_000
    hard_ceiling: int = 8_000
    qmd_notes: int = 3


class ContextBroker:
    def __init__(
        self,
        repository: Path,
        *,
        vault: Path | None = None,
        qmd_index: str = "obsidian-mind",
        budget: ContextBudget | None = None,
    ) -> None:
        self.repository = repository.expanduser().resolve()
        self.vault = vault.expanduser().resolve() if vault else None
        self.qmd_index = qmd_index
        self.budget = budget or ContextBudget()

    async def search(self, question: str, *, token_budget: int | None = None) -> ContextBundle:
        limit = min(token_budget or self.budget.total_tokens, self.budget.hard_ceiling)
        graph_limit = min(self.budget.graphify_tokens, limit)
        qmd_limit = min(self.budget.qmd_tokens, max(0, limit - graph_limit))
        source_limit = max(0, limit - graph_limit - qmd_limit)
        graph_task = asyncio.create_task(self._graphify(question, graph_limit))
        qmd_task = asyncio.create_task(self._qmd(question, qmd_limit))
        graph_sources, qmd_sources = await asyncio.gather(graph_task, qmd_task)
        sources = _deduplicate([*graph_sources, *qmd_sources])
        fallback_reason: str | None = None
        if not sources:
            simplified = " ".join(_terms(question)[:6])
            if simplified and simplified != question:
                retry_graph, retry_qmd = await asyncio.gather(
                    self._graphify(simplified, graph_limit), self._qmd(simplified, qmd_limit)
                )
                sources = _deduplicate([*retry_graph, *retry_qmd])
                fallback_reason = "simplified query after retrieval miss"
        exact_sources = await self._exact_source(
            question, source_limit, exclude={source.locator for source in sources}
        )
        sources = _deduplicate([*sources, *exact_sources])
        estimated = sum(_estimate_tokens(source.excerpt) for source in sources)
        while sources and estimated > limit:
            sources.pop()
            estimated = sum(_estimate_tokens(source.excerpt) for source in sources)
        return ContextBundle(
            question=question,
            sources=tuple(sources),
            confidence=min(1.0, 0.35 * len(sources)),
            omitted_results=0,
            token_budget=limit,
            estimated_tokens=estimated,
            fallback_reason=fallback_reason,
        )

    async def _graphify(self, question: str, token_limit: int) -> list[ContextSource]:
        if token_limit <= 0 or not (self.repository / "graphify-out" / "graph.json").exists():
            return []
        result = await _run(
            "graphify",
            "query",
            question,
            "--budget",
            str(token_limit),
            "--graph",
            str(self.repository / "graphify-out" / "graph.json"),
            cwd=self.repository,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        excerpt = _truncate(result.stdout.strip(), token_limit)
        return [
            ContextSource(
                source_type="graphify",
                title="Repository architecture graph",
                locator=str(self.repository / "graphify-out" / "graph.json"),
                excerpt=excerpt,
                score=1.0,
                provenance=("graphify query",),
            )
        ]

    async def _qmd(self, question: str, token_limit: int) -> list[ContextSource]:
        if token_limit <= 0:
            return []
        result = await _run(
            "qmd",
            "search",
            question,
            "--index",
            self.qmd_index,
            "--format",
            "json",
            "--full-path",
            "-n",
            str(self.budget.qmd_notes),
            cwd=self.repository,
        )
        if result.returncode != 0:
            return []
        try:
            documents = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        sources: list[ContextSource] = []
        for document in documents:
            if not isinstance(document, dict):
                continue
            excerpt = _truncate(str(document.get("snippet", "")), token_limit // self.budget.qmd_notes)
            sources.append(
                ContextSource(
                    source_type="obsidian",
                    title=str(document.get("title", "QMD result")),
                    locator=str(document.get("file", "qmd://unknown")),
                    excerpt=excerpt,
                    score=float(document.get("score", 0.0)),
                    provenance=("QMD search",),
                )
            )
        return sources[: self.budget.qmd_notes]

    async def _exact_source(
        self, question: str, token_limit: int, *, exclude: set[str]
    ) -> list[ContextSource]:
        terms = _terms(question)
        if token_limit <= 0 or not terms:
            return []
        pattern = "|".join(re.escape(term) for term in terms[:8])
        result = await _run(
            "rg",
            "-n",
            "-i",
            "--glob",
            "!graphify-out/**",
            "--glob",
            "!*.lock",
            pattern,
            str(self.repository),
            cwd=self.repository,
        )
        if result.returncode not in {0, 1}:
            return []
        lines = result.stdout.splitlines()[:12]
        excerpt = _truncate("\n".join(lines), token_limit)
        if not excerpt:
            return []
        locator = str(self.repository)
        if locator in exclude:
            return []
        return [
            ContextSource(
                source_type="source",
                title="Exact repository matches",
                locator=locator,
                excerpt=excerpt,
                score=0.7,
                provenance=("rg exact search",),
            )
        ]


@dataclass(frozen=True)
class _ProcessResult:
    returncode: int
    stdout: str
    stderr: str


async def _run(*arguments: str, cwd: Path) -> _ProcessResult:
    try:
        process = await asyncio.create_subprocess_exec(
            *arguments,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return _ProcessResult(127, "", f"{arguments[0]} is not installed")
    stdout, stderr = await process.communicate()
    return _ProcessResult(
        process.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    )


def _terms(question: str) -> list[str]:
    ignored = {
        "about",
        "from",
        "have",
        "into",
        "that",
        "the",
        "this",
        "what",
        "when",
        "where",
        "which",
        "with",
    }
    return [
        word for word in re.findall(r"[A-Za-z_][A-Za-z0-9_-]{2,}", question) if word.lower() not in ignored
    ]


def _truncate(text: str, token_limit: int) -> str:
    return text[: max(0, token_limit * 4)]


def _estimate_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


def _deduplicate(sources: list[ContextSource]) -> list[ContextSource]:
    seen: set[tuple[str, str]] = set()
    result: list[ContextSource] = []
    for source in sorted(sources, key=lambda item: item.score, reverse=True):
        key = (source.locator, source.excerpt)
        if key not in seen:
            seen.add(key)
            result.append(source)
    return result
