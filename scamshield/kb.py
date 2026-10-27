"""Knowledge base of official advisories + BM25 retrieval.

Each markdown file in knowledge_base/ has front matter (id, title, scam_type,
sources) and '## ' sections. Every section becomes a retrievable chunk with an
id like 'KB-UPI#2', so the LLM can cite it and the guard can verify the cite.

BM25 is used instead of dense embeddings on purpose: the corpus is small, the
app must run on free hosting with no model download, and exact terms
("TRAI", "UPI PIN", ".apk") matter more than semantic paraphrase here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from rank_bm25 import BM25Okapi

KB_DIR = Path(__file__).resolve().parent.parent / "knowledge_base"
TOKEN = re.compile(r"[a-z0-9]+|[ऀ-ॿ]+", re.I)


@dataclass(frozen=True)
class Chunk:
    id: str
    doc_id: str
    title: str
    heading: str
    text: str
    scam_type: str
    sources: tuple[str, ...]


def _tok(s: str) -> list[str]:
    return [t.lower() for t in TOKEN.findall(s)]


def _parse(path: Path) -> list[Chunk]:
    raw = path.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", raw, re.S)
    meta_txt, body = (m.group(1), m.group(2)) if m else ("", raw)
    meta: dict[str, object] = {}
    sources: list[str] = []
    for line in meta_txt.splitlines():
        if line.strip().startswith("- "):
            sources.append(line.strip()[2:].strip())
        elif ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    doc_id = str(meta.get("id", path.stem))
    title = str(meta.get("title", path.stem))
    scam_type = str(meta.get("scam_type", ""))
    chunks = []
    for i, sec in enumerate(re.split(r"\n(?=## )", body.strip()), start=1):
        heading = sec.splitlines()[0].lstrip("# ").strip() if sec.startswith("## ") else title
        text = sec.split("\n", 1)[1].strip() if sec.startswith("## ") and "\n" in sec else sec.strip()
        chunks.append(Chunk(f"{doc_id}#{i}", doc_id, title, heading, text, scam_type, tuple(sources)))
    return chunks


class KnowledgeBase:
    def __init__(self, kb_dir: Path = KB_DIR) -> None:
        self.chunks: list[Chunk] = []
        for p in sorted(kb_dir.glob("*.md")):
            self.chunks.extend(_parse(p))
        self.by_id = {c.id: c for c in self.chunks}
        self._bm25 = BM25Okapi([_tok(f"{c.title} {c.heading} {c.text}") for c in self.chunks])

    def search(self, query: str, k: int = 4, prefer_doc: str | None = None) -> list[Chunk]:
        scores = list(self._bm25.get_scores(_tok(query)))
        if prefer_doc:
            top = max(scores) if scores else 1.0
            for i, c in enumerate(self.chunks):
                if c.doc_id == prefer_doc:
                    scores[i] += 0.5 * top + 1.0
        order = sorted(range(len(self.chunks)), key=lambda i: scores[i], reverse=True)
        out = [self.chunks[i] for i in order[:k]]
        # Always include where-to-report guidance.
        report = next((c for c in self.chunks if c.doc_id == "KB-REPORT"), None)
        if report and report not in out:
            out.append(report)
        return out


@lru_cache(maxsize=1)
def get_kb() -> KnowledgeBase:
    return KnowledgeBase()
