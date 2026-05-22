"""
detector.py — WAFisGoingOn detection engine
Fixes all original bugs and upgrades to semantic embedding-based detection.
"""

import re
import math
import logging
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Fallback: cosine similarity on word counts (no ML deps required)
# ---------------------------------------------------------------------------

_WORD = re.compile(r"\w+")


def _text_to_vector(text: str) -> Counter:
    return Counter(_WORD.findall(text.lower()))


def _cosine(vec1: Counter, vec2: Counter) -> float:
    if not vec1 or not vec2:
        return 0.0
    intersection = set(vec1) & set(vec2)
    numerator = sum(vec1[x] * vec2[x] for x in intersection)
    denom = math.sqrt(sum(v ** 2 for v in vec1.values())) * math.sqrt(
        sum(v ** 2 for v in vec2.values())
    )
    return float(numerator) / denom if denom else 0.0


# ---------------------------------------------------------------------------
# Embedding-based detector (sentence-transformers + FAISS)
# ---------------------------------------------------------------------------

class EmbeddingDetector:
    """
    Semantic similarity detector using sentence-transformers and FAISS.
    Falls back gracefully to cosine-on-words if deps are unavailable.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self._model = None
        self._index = None
        self._payloads: list[str] = []
        self._model_name = model_name
        self._ready = False
        self._try_init()

    def _try_init(self):
        try:
            from sentence_transformers import SentenceTransformer
            import faiss
            import numpy as np

            self._np = np
            self._faiss = faiss
            self._model = SentenceTransformer(self._model_name)
            self._dim = self._model.get_sentence_embedding_dimension()
            self._index = faiss.IndexFlatIP(self._dim)  # inner-product = cosine on L2-normalised vecs
            self._ready = True
            logger.info("EmbeddingDetector ready (sentence-transformers + FAISS)")
        except ImportError:
            logger.warning(
                "sentence-transformers or faiss not installed — falling back to word-cosine detection"
            )

    def load_payloads(self, payloads: list[str]):
        self._payloads = [p.strip() for p in payloads if p.strip()]
        if self._ready and self._payloads:
            vecs = self._encode(self._payloads)
            self._index.reset()
            self._index.add(vecs)
            logger.info(f"Indexed {len(self._payloads)} payloads in FAISS")

    def _encode(self, texts: list[str]):
        vecs = self._model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
        return vecs.astype(self._np.float32)

    def score(self, text: str) -> float:
        """Return the highest similarity score against the payload database."""
        if not self._payloads:
            return 0.0

        if self._ready:
            vec = self._encode([text])
            distances, _ = self._index.search(vec, k=1)
            return float(distances[0][0])  # cosine similarity (0-1)

        # Fallback: max word-cosine over all payloads
        vec1 = _text_to_vector(text)
        return max(_cosine(vec1, _text_to_vector(p)) for p in self._payloads)

    def add_payload(self, text: str):
        """Dynamically add a new confirmed attack payload."""
        text = text.strip()
        if text and text not in self._payloads:
            self._payloads.append(text)
            if self._ready:
                vec = self._encode([text])
                self._index.add(vec)


# ---------------------------------------------------------------------------
# Main WAF detector
# ---------------------------------------------------------------------------

class WAFDetector:
    """
    Inspects HTTP requests for injection attempts across all surfaces:
    POST body, GET params, headers, and URL path.
    """

    def __init__(self, config: dict, db_path: str = "waf_events.db"):
        self.config = config
        self.db_path = db_path
        self.threshold: float = config.get("threshold", 0.75)
        self.wordlist_path: str = config.get("wordlist", "data.txt")
        self._detector = EmbeddingDetector(
            model_name=config.get("embedding_model", "all-MiniLM-L6-v2")
        )
        self._init_db()
        self._load_wordlist()

    # ------------------------------------------------------------------ DB

    def _init_db(self):
        con = sqlite3.connect(self.db_path)
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT    NOT NULL,
                ip        TEXT,
                method    TEXT,
                path      TEXT,
                surface   TEXT,
                payload   TEXT,
                score     REAL,
                blocked   INTEGER
            )
            """
        )
        con.commit()
        con.close()

    def _log_event(self, ip: str, method: str, path: str,
                   surface: str, payload: str, score: float, blocked: bool):
        con = sqlite3.connect(self.db_path)
        con.execute(
            "INSERT INTO events(ts,ip,method,path,surface,payload,score,blocked) VALUES(?,?,?,?,?,?,?,?)",
            (datetime.utcnow().isoformat(), ip, method, path, surface, payload, score, int(blocked)),
        )
        con.commit()
        con.close()

    # --------------------------------------------------------- Wordlist I/O

    def _load_wordlist(self):
        path = Path(self.wordlist_path)
        if not path.exists():
            logger.warning(f"Wordlist not found at {path} — starting empty")
            self._detector.load_payloads([])
            return
        payloads = path.read_text(errors="replace").splitlines()
        self._detector.load_payloads(payloads)
        logger.info(f"Loaded {len(payloads)} payloads from {path}")

    def _append_to_wordlist(self, payload: str):
        """Append a newly confirmed attack payload to the wordlist file."""
        try:
            with open(self.wordlist_path, "a") as f:
                f.write(payload.strip() + "\n")
            self._detector.add_payload(payload)
        except OSError as e:
            logger.error(f"Could not write to wordlist: {e}")

    # ------------------------------------------------------------ Allowlist

    def _is_allowlisted(self, ip: str, path: str) -> bool:
        allowlist = self.config.get("allowlist", {})
        if ip in allowlist.get("ips", []):
            return True
        for pattern in allowlist.get("paths", []):
            if re.match(pattern, path):
                return True
        return False

    # ------------------------------------------------------------ Inspection

    def _check(self, text: str) -> tuple[bool, float]:
        """Return (is_malicious, score)."""
        score = self._detector.score(text)
        return score >= self.threshold, score

    def inspect(
        self,
        ip: str,
        method: str,
        path: str,
        get_params: dict,
        post_params: dict,
        headers: dict,
    ) -> tuple[bool, str, float]:
        """
        Inspect all surfaces of an incoming request.

        Returns (blocked, surface_name, score).
        """
        if self._is_allowlisted(ip, path):
            return False, "", 0.0

        surfaces: dict[str, list[str]] = {
            "url_path": [path],
            "get_param": list(get_params.values()),
            "post_param": list(post_params.values()),
            "header": [
                v for k, v in headers.items()
                if k.lower() in ("user-agent", "referer", "x-forwarded-for", "cookie")
            ],
        }

        # Per-route threshold override
        route_rules = self.config.get("route_rules", {})
        threshold = route_rules.get(path, {}).get("threshold", self.threshold)

        for surface, values in surfaces.items():
            for value in values:
                if not value:
                    continue
                score = self._detector.score(str(value))
                blocked = score >= threshold
                if blocked:
                    self._log_event(ip, method, path, surface, str(value), score, True)
                    self._append_to_wordlist(str(value))
                    return True, surface, score

        self._log_event(ip, method, path, "none", "", 0.0, False)
        return False, "", 0.0

    # ------------------------------------------------------------ Stats API

    def get_stats(self) -> dict:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        total = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        blocked = cur.execute("SELECT COUNT(*) FROM events WHERE blocked=1").fetchone()[0]
        top_ips = cur.execute(
            "SELECT ip, COUNT(*) as c FROM events WHERE blocked=1 GROUP BY ip ORDER BY c DESC LIMIT 5"
        ).fetchall()
        recent = cur.execute(
            "SELECT ts,ip,method,path,surface,payload,score,blocked FROM events ORDER BY id DESC LIMIT 50"
        ).fetchall()
        per_minute = cur.execute(
            """
            SELECT strftime('%Y-%m-%dT%H:%M', ts) as minute,
                   COUNT(*) as total,
                   SUM(blocked) as blocked
            FROM events
            WHERE ts >= datetime('now','-1 hour')
            GROUP BY minute
            ORDER BY minute
            """
        ).fetchall()
        con.close()

        return {
            "total": total,
            "blocked": blocked,
            "allowed": total - blocked,
            "block_rate": round(blocked / total * 100, 1) if total else 0,
            "top_ips": [dict(r) for r in top_ips],
            "recent": [dict(r) for r in recent],
            "per_minute": [dict(r) for r in per_minute],
        }
