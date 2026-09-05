"""
Runbook retrieval engine (Steps 8 & 9) + evidence-backed recommendation (Step 10).

Responsibilities
----------------
* Load local runbooks from ``data/runbooks/`` (project-created markdown files).
* Parse structure: Title, Applicable Alert Types, sections.
* Chunk runbooks for FAISS / embedding retrieval.
* Retrieve relevant runbooks for an incident via:
  - local deterministic keyword matching (always available)
  - FAISS + Gemini embeddings (when GEMINI_API_KEY is present)
* Generate grounded recommendation (Gemini when available, deterministic fallback).

Design rules
-------------
* Never invent a runbook — only returns runbooks that exist on disk.
* Clearly reports when no suitable runbook exists.
* Graceful fallback: if Gemini or FAISS unavailable, local keyword matching continues to work.
* Never crashes the NOC application because API is unavailable.
"""

from __future__ import annotations

import json
import hashlib
import re
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any, Sequence

import numpy as np

from src.config import RUNBOOKS_DIR, FAISS_INDEX_DIR, FAISS_INDEX_FILE, FAISS_META_FILE, GEMINI_API_KEY, GEMINI_MODEL_EMBEDDING, GEMINI_MODEL_GENERATION
from src.scorer import CandidateIncident, AlertView
from src.priority import PriorityResult
from src.topology import get_topology

# Optional FAISS import — degrade gracefully if not installed
try:
    import faiss
    HAS_FAISS = True
except Exception:
    faiss = None  # type: ignore
    HAS_FAISS = False

# Optional Gemini import
try:
    from google import genai  # new SDK: google-genai
    HAS_GENAI = True
except Exception:
    genai = None  # type: ignore
    HAS_GENAI = False

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Runbook:
    id: str  # filename e.g. link_down.md
    title: str
    applicable_types: Set[str]
    sections: Dict[str, str]
    raw_text: str
    path: Path

@dataclass
class Chunk:
    id: str
    runbook_id: str
    section: str
    text: str

@dataclass
class RunbookMatch:
    runbook_id: str
    section: str
    text: str
    score: float
    reason: str

    def to_dict(self) -> dict:
        return {
            "runbook": self.runbook_id,
            "section": self.section,
            "reason": self.reason,
            "score": round(self.score, 3),
            "snippet": self.text[:300],
        }

# ---------------------------------------------------------------------------
# Runbook loading & parsing
# ---------------------------------------------------------------------------

_TITLE_RE = re.compile(r"^#\s+Runbook:\s*(.+)$", re.MULTILINE)
_APPLICABLE_RE = re.compile(r"\*\*Applicable Alert Types:\*\*\s*(.+)", re.IGNORECASE)
_SECTION_RE = re.compile(r"^##\s+(.+)$", re.MULTILINE)


def _extract_title(text: str, fallback: str) -> str:
    m = _TITLE_RE.search(text)
    if m:
        return m.group(1).strip()
    # Fallback to first # heading
    m2 = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    if m2:
        return m2.group(1).strip()
    return fallback


def _extract_applicable_types(text: str) -> Set[str]:
    m = _APPLICABLE_RE.search(text)
    if not m:
        return set()
    raw = m.group(1)
    # Extract backticked or uppercase tokens
    tokens = re.findall(r"[A-Z_]+", raw)
    # Filter to known pattern (must contain underscore or be known type)
    result = set()
    for tok in tokens:
        if tok in {"LINK_DOWN", "DEVICE_UNREACHABLE", "PACKET_LOSS", "HIGH_LATENCY", "AUTH_FAILURE",
                   "RADIUS_TIMEOUT", "LINK_UP", "JITTER_THRESHOLD", "CRC_ERRORS", "IF_FLAP",
                   "BGP_SESSION_DROP", "OPTICAL_RX_LOW", "CPU_HIGH", "MEMORY_HIGH", "CONFIG_CHANGE",
                   "UNKNOWN"}:
            result.add(tok)
        elif "_" in tok:
            result.add(tok)
    return result


def _parse_sections(text: str) -> Dict[str, str]:
    sections: Dict[str, str] = {}
    matches = list(_SECTION_RE.finditer(text))
    for idx, m in enumerate(matches):
        title = m.group(1).strip()
        start = m.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        sections[title] = body
    return sections


def parse_runbook_file(path: Path) -> Runbook:
    text = path.read_text(encoding="utf-8")
    title = _extract_title(text, path.stem)
    applicable = _extract_applicable_types(text)
    sections = _parse_sections(text)
    return Runbook(
        id=path.name,
        title=title,
        applicable_types=applicable,
        sections=sections,
        raw_text=text,
        path=path,
    )


def load_runbooks(runbooks_dir: Optional[Path] = None) -> List[Runbook]:
    directory = Path(runbooks_dir) if runbooks_dir else RUNBOOKS_DIR
    if not directory.exists():
        return []
    runbooks: List[Runbook] = []
    for md in sorted(directory.glob("*.md")):
        try:
            rb = parse_runbook_file(md)
            runbooks.append(rb)
        except Exception:
            continue
    return runbooks


def list_runbooks() -> List[dict]:
    """Public API helper for /api/runbooks."""
    rbs = load_runbooks()
    result = []
    for rb in rbs:
        result.append({
            "id": rb.id,
            "title": rb.title,
            "applicable_types": sorted(rb.applicable_types),
            "sections": list(rb.sections.keys()),
        })
    return result


def _chunk_runbook(rb: Runbook) -> List[Chunk]:
    chunks: List[Chunk] = []
    for sec_name, sec_body in rb.sections.items():
        # Keep header + body; if body long, split by paragraphs
        # Simple: each section is one chunk, but if >800 chars split into paragraphs
        full = f"{rb.title} — {sec_name}\n{sec_body}"
        if len(full) <= 900:
            chunks.append(Chunk(id=f"{rb.id}::{sec_name}", runbook_id=rb.id, section=sec_name, text=full))
        else:
            # Split by blank lines
            paras = [p.strip() for p in sec_body.split("\n\n") if p.strip()]
            cur = ""
            part_idx = 0
            for para in paras:
                candidate = f"{cur}\n\n{para}" if cur else para
                if len(candidate) > 800 and cur:
                    chunks.append(Chunk(id=f"{rb.id}::{sec_name}#{part_idx}", runbook_id=rb.id, section=sec_name, text=f"{rb.title} — {sec_name}\n{cur}"))
                    part_idx += 1
                    cur = para
                else:
                    cur = candidate
            if cur:
                chunks.append(Chunk(id=f"{rb.id}::{sec_name}#{part_idx}", runbook_id=rb.id, section=sec_name, text=f"{rb.title} — {sec_name}\n{cur}"))
    # Fallback: if no sections, chunk whole file
    if not chunks:
        chunks.append(Chunk(id=f"{rb.id}::full", runbook_id=rb.id, section="Full Document", text=rb.raw_text[:1200]))
    return chunks


def get_all_chunks(runbooks: Optional[List[Runbook]] = None) -> List[Chunk]:
    if runbooks is None:
        runbooks = load_runbooks()
    all_chunks: List[Chunk] = []
    for rb in runbooks:
        all_chunks.extend(_chunk_runbook(rb))
    return all_chunks

# ---------------------------------------------------------------------------
# Embeddings — local deterministic fallback + Gemini
# ---------------------------------------------------------------------------

def _local_embed(text: str, dim: int = 384) -> np.ndarray:
    """
    Deterministic bag-of-hashed-words embedding.
    Each token hashed to an index, count++ then L2 normalized.
    Produces same vector for same text across runs, no external API.
    """
    vec = np.zeros(dim, dtype=np.float32)
    # Simple tokenization: lower, alphanumeric chunks
    tokens = re.findall(r"[a-zA-Z0-9_]+", text.lower())
    if not tokens:
        return vec
    for tok in tokens:
        # Deterministic hash via hashlib
        h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)
        idx = h % dim
        vec[idx] += 1.0
        # Also bigram influence: add neighboring token pair hash
    # Add slight boost for alert-type keywords
    # L2 normalize
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec = vec / norm
    return vec


def _gemini_embed_batch(texts: List[str], api_key: Optional[str] = None) -> Optional[List[np.ndarray]]:
    """
    Attempt to embed via Gemini gemini-embedding-001.
    Returns list of normalized vectors or None if unavailable.
    """
    if not HAS_GENAI:
        return None
    key = api_key or GEMINI_API_KEY or os.getenv("GEMINI_API_KEY", "")
    if not key:
        return None
    try:
        client = genai.Client(api_key=key)  # type: ignore
        # New SDK: client.models.embed_content
        # Batch embedding
        vectors: List[np.ndarray] = []
        for txt in texts:
            # Truncate to avoid excessive token limit
            snippet = txt[:2000]
            resp = client.models.embed_content(  # type: ignore
                model=GEMINI_MODEL_EMBEDDING,
                contents=[snippet],
            )
            # Response structure: resp.embeddings[0].values
            # Older wrapper may return resp.embeddings
            emb = None
            if hasattr(resp, "embeddings") and resp.embeddings:
                emb = resp.embeddings[0].values  # type: ignore
            elif hasattr(resp, "embedding") and resp.embedding:
                emb = resp.embedding.values  # type: ignore
            else:
                # Try dict access
                try:
                    emb = resp["embeddings"][0]["values"]  # type: ignore
                except Exception:
                    emb = None
            if emb is None:
                return None
            vec = np.array(emb, dtype=np.float32)
            # Normalize
            n = np.linalg.norm(vec)
            if n > 0:
                vec = vec / n
            vectors.append(vec)
        return vectors
    except Exception as e:
        # Silently fall back
        print(f"[runbook_engine] Gemini embedding failed: {e}")
        return None


def embed_texts(texts: List[str], prefer_gemini: bool = True) -> List[np.ndarray]:
    """
    Embed a batch of texts, preferring Gemini when available.
    Falls back to local embedding per-text if Gemini fails.
    Returns list of L2-normalized vectors.
    """
    if prefer_gemini and GEMINI_API_KEY and HAS_GENAI:
        gem_vectors = _gemini_embed_batch(texts)
        if gem_vectors is not None and len(gem_vectors) == len(texts):
            return gem_vectors
    # Fallback local
    return [_local_embed(t) for t in texts]

# ---------------------------------------------------------------------------
# FAISS index building / loading
# ---------------------------------------------------------------------------

def build_faiss_index(
    chunks: Optional[List[Chunk]] = None,
    force_rebuild: bool = False,
    use_gemini: bool = False,
) -> Tuple[Optional[Any], List[Chunk]]:
    """
    Build or load FAISS index for runbook chunks.
    Returns (index, chunks). If FAISS unavailable, returns (None, chunks).
    Index is cached on disk under data/faiss_index/ when possible.
    """
    if chunks is None:
        chunks = get_all_chunks()
    if not chunks:
        return None, []

    if not HAS_FAISS:
        return None, chunks

    # If index exists and not force rebuild, try to load
    if FAISS_INDEX_FILE.exists() and FAISS_META_FILE.exists() and not force_rebuild:
        try:
            index = faiss.read_index(str(FAISS_INDEX_FILE))  # type: ignore
            meta = json.loads(FAISS_META_FILE.read_text(encoding="utf-8"))
            # Reconstruct chunks from meta (ensure same order)
            # But we still have current chunks; verify counts match
            if len(meta.get("chunks", [])) == len(chunks):
                # Use loaded index
                return index, chunks
        except Exception:
            pass  # rebuild

    # Build fresh
    prefer_gemini = use_gemini and bool(GEMINI_API_KEY)
    texts = [c.text for c in chunks]
    vectors = embed_texts(texts, prefer_gemini=prefer_gemini)
    if not vectors:
        return None, chunks

    dim = vectors[0].shape[0]
    # Use Inner Product on normalized vectors = cosine similarity
    try:
        index = faiss.IndexFlatIP(dim)  # type: ignore
        mat = np.vstack(vectors).astype(np.float32)
        # Ensure normalized for IP
        faiss.normalize_L2(mat)  # type: ignore  # already normalized but ensure
        index.add(mat)  # type: ignore
    except Exception as e:
        print(f"[runbook_engine] FAISS build failed: {e}")
        return None, chunks

    # Persist if possible
    try:
        FAISS_INDEX_DIR.mkdir(parents=True, exist_ok=True)
        faiss.write_index(index, str(FAISS_INDEX_FILE))  # type: ignore
        meta = {
            "chunks": [{"id": c.id, "runbook_id": c.runbook_id, "section": c.section, "text": c.text[:2000]} for c in chunks],
            "dim": dim,
            "use_gemini": prefer_gemini,
        }
        FAISS_META_FILE.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[runbook_engine] FAISS persist failed: {e}")

    return index, chunks


def _semantic_search(
    query: str,
    index: Any,
    chunks: List[Chunk],
    top_k: int = 3,
    use_gemini: bool = False,
) -> List[Tuple[Chunk, float]]:
    if index is None or not chunks or not HAS_FAISS:
        return []
    prefer_gemini = use_gemini and bool(GEMINI_API_KEY)
    q_vecs = embed_texts([query], prefer_gemini=prefer_gemini)
    if not q_vecs:
        return []
    q = q_vecs[0].reshape(1, -1).astype(np.float32)
    try:
        faiss.normalize_L2(q)  # type: ignore
        scores, ids = index.search(q, min(top_k, len(chunks)))  # type: ignore
        results: List[Tuple[Chunk, float]] = []
        for score, idx in zip(scores[0], ids[0]):
            if idx == -1:
                continue
            results.append((chunks[int(idx)], float(score)))
        return results
    except Exception as e:
        print(f"[runbook_engine] FAISS search failed: {e}")
        return []

# ---------------------------------------------------------------------------
# Keyword retrieval (deterministic fallback)
# ---------------------------------------------------------------------------

def _keyword_score_incident_vs_runbook(
    incident: CandidateIncident,
    rb: Runbook,
) -> Tuple[float, str]:
    """
    Compute keyword score based on alert type overlap and section relevance.
    Returns (score 0-1, reason).
    """
    incident_types: Set[str] = set()
    for av in incident.alerts:
        t = av.alert_type
        if isinstance(t, str):
            incident_types.add(t.upper())
        else:
            incident_types.add(str(t).upper())

    # Intersection with applicable types
    applicable = {x.upper() for x in rb.applicable_types}
    if not applicable:
        return 0.0, "No applicable types declared"

    overlap = incident_types & applicable
    # Also consider if runbook applicable contains related types via scorer's RELATED_ALERT_TYPES?
    # We keep strict overlap for determinism.

    if not overlap:
        # Check for partial keyword: e.g., incident has UNKNOWN but runbook title contains words?
        # If incident types are all UNKNOWN, no runbook matches well — return low score
        return 0.0, "No alert type overlap"

    # Score proportional to overlap size relative to incident distinct types
    # Example: incident has LINK_DOWN, DEVICE_UNREACHABLE, PACKET_LOSS and runbook covers those -> high
    base_score = len(overlap) / max(1, len(incident_types))

    # Boost for core/multi-device runbooks when incident is large
    if len(incident.affected_devices) >= 3 and rb.id in ("core_router_failure.md", "multi_device_cascade.md"):
        base_score += 0.2
    if "core" in rb.id and any(d.startswith("R1") or d == "R1" for d in incident.affected_devices):
        base_score += 0.15

    # Boost if incident has multiple alert types related to runbook's scope
    # Cap at 1.0
    score = min(1.0, base_score)

    reason = f"Alert type overlap {sorted(overlap)} vs incident {sorted(incident_types)}"
    if score >= 1.0:
        reason += " — full match"
    return score, reason


def keyword_retrieve(
    incident: CandidateIncident,
    top_k: int = 3,
) -> List[RunbookMatch]:
    runbooks = load_runbooks()
    scored: List[Tuple[Runbook, float, str]] = []
    for rb in runbooks:
        score, reason = _keyword_score_incident_vs_runbook(incident, rb)
        if score > 0:
            scored.append((rb, score, reason))
    # Sort descending by score, then id for determinism
    scored.sort(key=lambda x: (-x[1], x[0].id))
    results: List[RunbookMatch] = []
    for rb, score, reason in scored[:top_k]:
        # Pick most relevant section: prefer Initial Checks, then Recommended Actions
        # Heuristic: choose section with highest keyword overlap
        preferred_sections = ["Initial Checks", "Recommended Actions", "Symptoms", "Likely Causes"]
        chosen_section = None
        chosen_text = ""
        for sec in preferred_sections:
            if sec in rb.sections:
                chosen_section = sec
                chosen_text = rb.sections[sec]
                break
        if chosen_section is None and rb.sections:
            chosen_section = next(iter(rb.sections))
            chosen_text = rb.sections[chosen_section]
        if not chosen_section:
            chosen_section = "Full Document"
            chosen_text = rb.raw_text[:800]

        # Truncate snippet
        snippet = chosen_text[:600]
        results.append(RunbookMatch(
            runbook_id=rb.id,
            section=chosen_section,
            text=snippet,
            score=score,
            reason=reason,
        ))
    return results

# ---------------------------------------------------------------------------
# Public retrieval API
# ---------------------------------------------------------------------------

# Global cache for index/chunks to avoid rebuilding per request
_cached_index: Optional[Any] = None
_cached_chunks: Optional[List[Chunk]] = None

def get_cached_index(force_reload: bool = False) -> Tuple[Optional[Any], List[Chunk]]:
    global _cached_index, _cached_chunks
    if _cached_index is not None and _cached_chunks is not None and not force_reload:
        return _cached_index, _cached_chunks
    # Try to build without Gemini for speed; Gemini only if key present and requested
    use_gemini = bool(GEMINI_API_KEY) and HAS_GENAI
    idx, chunks = build_faiss_index(use_gemini=use_gemini)
    _cached_index = idx
    _cached_chunks = chunks
    return idx, chunks


def retrieve_runbooks(
    incident: CandidateIncident,
    top_k: int = 3,
    use_semantic: Optional[bool] = None,
) -> List[RunbookMatch]:
    """
    Retrieve relevant runbooks for an incident.
    Strategy:
      1. Attempt semantic FAISS search if available and use_semantic not false.
      2. Fall back (or blend) with keyword retrieval.
      3. If still empty, return [] indicating no suitable runbook.

    Semantic results are validated against keyword overlap to avoid hallucinated
    matches for uncovered alert types (e.g. UNKNOWN) — this ensures unknown_escalation
    correctly yields no suitable runbook and triggers escalation.
    """
    # Determine whether to attempt semantic
    attempt_semantic = True
    if use_semantic is False:
        attempt_semantic = False
    if use_semantic is None:
        attempt_semantic = HAS_FAISS and (GEMINI_API_KEY or True)

    semantic_matches: List[RunbookMatch] = []
    if attempt_semantic and HAS_FAISS:
        try:
            index, chunks = get_cached_index()
            if index is not None and chunks:
                parts = []
                type_set = set()
                for av in incident.alerts:
                    type_set.add(av.alert_type)
                    src = av.source
                    msg = ""
                    if hasattr(src, "representative") and hasattr(src.representative, "message"):
                        msg = src.representative.message
                    elif hasattr(src, "message"):
                        msg = getattr(src, "message", "")
                    if msg:
                        parts.append(msg)
                query_text = f"Incident {incident.incident_id} alert types: {', '.join(sorted(type_set))}. Devices: {', '.join(incident.affected_devices)}. Messages: {' '.join(parts[:5])}"
                sem_results = _semantic_search(query_text, index, chunks, top_k=top_k*2)
                # Precompute keyword validity for runbooks to filter hallucinations
                runbooks_by_id = {rb.id: rb for rb in load_runbooks()}
                for chunk, score in sem_results:
                    threshold = 0.35 if GEMINI_API_KEY else 0.12
                    if score < threshold:
                        continue
                    # Validate keyword overlap for parent runbook
                    rb = runbooks_by_id.get(chunk.runbook_id)
                    if rb is not None:
                        kw_score, _ = _keyword_score_incident_vs_runbook(incident, rb)
                        if kw_score == 0:
                            # For UNKNOWN-heavy incidents, semantic alone should not invent a match
                            continue
                    reason = f"Semantic similarity {score:.3f} to chunk {chunk.id}"
                    semantic_matches.append(RunbookMatch(
                        runbook_id=chunk.runbook_id,
                        section=chunk.section,
                        text=chunk.text[:600],
                        score=float(score),
                        reason=reason,
                    ))
                    if len(semantic_matches) >= top_k:
                        break
        except Exception as e:
            print(f"[runbook_engine] semantic retrieval failed: {e}")

    # Keyword fallback / primary
    keyword_matches = keyword_retrieve(incident, top_k=top_k)

    if semantic_matches:
        # Combine both sources, deduplicate, then rank by score (keyword typically higher)
        combined = semantic_matches + keyword_matches
        seen = set()
        deduped: List[RunbookMatch] = []
        for m in combined:
            key = (m.runbook_id, m.section)
            if key not in seen:
                seen.add(key)
                deduped.append(m)
        deduped.sort(key=lambda x: (-x.score, x.runbook_id))
        return deduped[:top_k]
    else:
        return keyword_matches


def retrieve_evidence(
    incident: CandidateIncident,
    top_k: int = 3,
) -> List[dict]:
    """Convenience wrapper returning JSON-serializable evidence list."""
    matches = retrieve_runbooks(incident, top_k=top_k)
    return [m.to_dict() for m in matches]

# ---------------------------------------------------------------------------
# Recommendation generation (grounded)
# ---------------------------------------------------------------------------

def _build_incident_context(
    incident: CandidateIncident,
    priority: Optional[PriorityResult],
) -> str:
    """Build textual context for LLM prompting from incident data."""
    lines = []
    lines.append(f"Incident {incident.incident_id}: {len(incident.alert_ids)} alerts, {len(incident.affected_devices)} devices affected: {', '.join(incident.affected_devices)}")
    lines.append(f"First seen {incident.first_seen.isoformat()}, last seen {incident.last_seen.isoformat()}, duration {(incident.last_seen - incident.first_seen).total_seconds():.0f}s")
    lines.append(f"Correlation score {incident.correlation_score}, reasons: {'; '.join(incident.correlation_reasons[:3])}")
    if priority:
        lines.append(f"Priority {priority.priority} score {priority.score}, signals {priority.signals}, reasons: {'; '.join(priority.reasons[:3])}")
    # Alerts
    for av in incident.alerts[:8]:
        sev = "UNKNOWN"
        msg = ""
        src = av.source
        if hasattr(src, "representative"):
            sev = getattr(src.representative, "severity", "UNKNOWN")
            msg = getattr(src.representative, "message", "")
            sev = sev.value if hasattr(sev, "value") else str(sev)
        elif hasattr(src, "severity"):
            sev = getattr(src, "severity", "UNKNOWN")
            sev = sev.value if hasattr(sev, "value") else str(sev)
            msg = getattr(src, "message", "")
        lines.append(f" - Alert {av.alert_id}: {av.alert_type} on {av.device_id} severity {sev} — {msg[:120]}")
    return "\n".join(lines)


def _deterministic_recommendation(
    incident: CandidateIncident,
    priority: Optional[PriorityResult],
    evidence: List[RunbookMatch],
) -> dict:
    """
    Fallback deterministic recommendation when Gemini unavailable.
    Grounded strictly on evidence and incident data.
    """
    incident_id = incident.incident_id
    affected = list(incident.affected_devices)

    if not evidence:
        # No runbook → cannot confidently recommend
        return {
            "incident_id": incident_id,
            "summary": f"Incident {incident_id} affecting {', '.join(affected) if affected else 'unknown devices'} has no matching runbook.",
            "priority": priority.priority if priority else "LOW",
            "what_happened": f"Grouped {len(incident.alert_ids)} alerts (correlation score {incident.correlation_score}) but no runbook matches the alert types. The system cannot ground a recommendation.",
            "affected_devices": affected,
            "recommended_actions": [],
            "evidence": [],
            "confidence": "low",
            "needs_escalation": True,
            "escalation_reason": "No matching runbook found — human investigation required",
        }

    # Use top evidence
    primary = evidence[0]
    # Build what_happened from incident
    # Determine root candidate: earliest alert device
    sorted_alerts = sorted(incident.alerts, key=lambda av: av.timestamp)
    root_device = sorted_alerts[0].device_id if sorted_alerts else (affected[0] if affected else "unknown")
    type_set = sorted({av.alert_type for av in incident.alerts})

    # Priority label
    pri = priority.priority if priority else "MEDIUM"
    conf = "high" if pri == "CRITICAL" and len(evidence) >= 2 else ("medium" if pri in ("HIGH", "CRITICAL") else "low")
    if len(incident.alert_ids) >= 5 and len(affected) >= 3 and pri == "CRITICAL":
        conf = "high"

    # Build summary & actions from runbook sections
    # Load full runbook to get Recommended Actions
    runbooks = {rb.id: rb for rb in load_runbooks()}
    primary_rb = runbooks.get(primary.runbook_id)
    actions: List[str] = []
    if primary_rb and "Recommended Actions" in primary_rb.sections:
        # Take first 2-3 actions bullet points
        raw = primary_rb.sections["Recommended Actions"]
        # Split by numbered steps or bullets
        steps = re.split(r"\n\d+\.\s+|\n-\s+|\n•\s+", raw)
        steps = [s.strip() for s in steps if s.strip()]
        # First line may be empty due to split, clean
        for step in steps[:3]:
            # Remove markdown noise, keep first sentence-ish
            step_clean = step.split("\n")[0].strip()
            if step_clean:
                actions.append(step_clean[:200])
    if not actions:
        actions.append(f"Follow {primary.runbook_id} section {primary.section}")

    # Add upstream-first guidance for cascade
    if len(affected) >= 3 and "cascade" in primary.runbook_id or len(affected) >= 3 and "core" in primary.runbook_id:
        if not any("upstream" in a.lower() for a in actions):
            actions.insert(0, f"Investigate upstream device {root_device} first before downstream nodes")

    summary = f"Incident {incident_id} correlates {len(incident.alert_ids)} alerts across {len(affected)} devices (priority {pri}). Likely root near {root_device} with alert types {', '.join(type_set[:4])}."
    what_happened = f"Earliest alert on {root_device} at {incident.first_seen.isoformat()} followed by {len(incident.alert_ids)-1} related alerts within {(incident.last_seen - incident.first_seen).total_seconds():.0f}s. Devices affected: {', '.join(affected)}. Correlation: {incident.correlation_reasons[0] if incident.correlation_reasons else 'no detail'}."

    # Evidence citable
    evidence_list = [m.to_dict() for m in evidence]

    needs_escalation = False
    escalation_reason = None
    if pri == "CRITICAL" and conf != "high":
        # Could still need escalation if confidence low
        pass

    return {
        "incident_id": incident_id,
        "summary": summary,
        "priority": pri,
        "what_happened": what_happened,
        "affected_devices": affected,
        "recommended_actions": actions,
        "evidence": evidence_list,
        "confidence": conf,
        "needs_escalation": needs_escalation,
        "escalation_reason": escalation_reason,
    }


def _gemini_generate_recommendation(
    incident: CandidateIncident,
    priority: Optional[PriorityResult],
    evidence: List[RunbookMatch],
) -> Optional[dict]:
    """
    Attempt to call Gemini generation model for grounded recommendation.
    Must be prompt-engineered to only use supplied evidence.
    Returns dict or None on failure.
    """
    if not HAS_GENAI or not GEMINI_API_KEY:
        return None
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)  # type: ignore
        context = _build_incident_context(incident, priority)
        evidence_text = "\n".join([f"- Runbook {m.runbook_id} Section {m.section}: {m.text[:500]} (score {m.score:.3f} reason: {m.reason})" for m in evidence])
        if not evidence_text:
            evidence_text = "No runbook matched. You must state that no grounded recommendation can be made and suggest escalation."

        system_prompt = (
            "You are NetSentry-AI, a telecom NOC assistant. You must be strictly grounded. "
            "Given the incident context and the supplied runbook evidence, produce a JSON recommendation. "
            "Rules:\n"
            "- Do NOT invent network facts, device types, or runbook names beyond supplied context\n"
            "- You may only cite runbooks/sections from the Evidence list\n"
            "- If evidence is insufficient, set needs_escalation=true and explain why\n"
            "- Respond ONLY with valid JSON matching the schema: {incident_id, summary, priority, what_happened, affected_devices, recommended_actions[], evidence[{runbook, section, reason}], confidence, needs_escalation, escalation_reason}\n"
            "- Keep recommended_actions to 2-3 concrete steps drawn from runbook Recommended Actions\n"
        )
        user_prompt = f"Incident Context:\n{context}\n\nEvidence:\n{evidence_text}\n\nGenerate the JSON recommendation grounded in the evidence. Use incident_id {incident.incident_id} and priority {priority.priority if priority else 'MEDIUM'}."

        # Use generate_content
        resp = client.models.generate_content(  # type: ignore
            model=GEMINI_MODEL_GENERATION,
            contents=[system_prompt + "\n\n" + user_prompt],
            config={"temperature": 0.2, "max_output_tokens": 800},  # type: ignore
        )
        text = ""
        if hasattr(resp, "text") and resp.text:
            text = resp.text  # type: ignore
        elif hasattr(resp, "candidates") and resp.candidates:
            # Extract from candidates
            try:
                text = resp.candidates[0].content.parts[0].text  # type: ignore
            except Exception:
                text = str(resp)
        else:
            text = str(resp)

        # Try to extract JSON from response (may be wrapped in markdown)
        import re as _re
        json_match = _re.search(r"\{.*\}", text, _re.DOTALL)
        if not json_match:
            return None
        json_str = json_match.group(0)
        parsed = json.loads(json_str)
        # Validate required fields and ensure evidence runbooks are legit
        # Filter evidence to only those that were supplied
        allowed_runbooks = {m.runbook_id for m in evidence}
        filtered_evidence = []
        for ev in parsed.get("evidence", []):
            rb = ev.get("runbook", "")
            if rb in allowed_runbooks or not allowed_runbooks:
                filtered_evidence.append(ev)
            else:
                # Hallucinated runbook — drop it
                continue
        parsed["evidence"] = filtered_evidence
        # Ensure incident_id correct
        parsed["incident_id"] = incident.incident_id
        # Ensure priority correct if priority supplied
        if priority:
            parsed["priority"] = priority.priority
        # Ensure affected_devices is list
        if "affected_devices" not in parsed or not isinstance(parsed["affected_devices"], list):
            parsed["affected_devices"] = list(incident.affected_devices)
        # Confidence sanity
        if parsed.get("confidence") not in ("high", "medium", "low"):
            parsed["confidence"] = "medium"
        # If evidence empty but gemini claimed recommendation, force escalation
        if not evidence and not parsed.get("needs_escalation"):
            parsed["needs_escalation"] = True
            parsed["escalation_reason"] = "No matching runbook — recommendation not grounded"

        # Never invent runbook — already filtered
        return parsed
    except Exception as e:
        print(f"[runbook_engine] Gemini generation failed: {e}")
        return None


def generate_recommendation(
    incident: CandidateIncident,
    priority: Optional[PriorityResult] = None,
    top_k: int = 3,
) -> dict:
    """
    Public entry point for AI recommendation.
    Pipeline: incident -> priority -> runbook retrieval -> evidence -> Gemini/deterministic recommendation
    Returns structured recommendation dict as specified in Step 10.
    """
    evidence_matches = retrieve_runbooks(incident, top_k=top_k)
    # Try Gemini generation if available
    gem_result = _gemini_generate_recommendation(incident, priority, evidence_matches)
    if gem_result is not None:
        # Add tagging that this is AI-generated but grounded
        gem_result["_source"] = "gemini"
        return gem_result
    # Fallback deterministic
    det = _deterministic_recommendation(incident, priority, evidence_matches)
    det["_source"] = "deterministic"
    return det


__all__ = [
    "Runbook",
    "Chunk",
    "RunbookMatch",
    "load_runbooks",
    "list_runbooks",
    "parse_runbook_file",
    "get_all_chunks",
    "embed_texts",
    "build_faiss_index",
    "keyword_retrieve",
    "retrieve_runbooks",
    "retrieve_evidence",
    "generate_recommendation",
    "get_cached_index",
]
