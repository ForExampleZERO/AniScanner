"""
scanner/db.py  (v5.0)
SQLite-backed session storage — drop-in replacement for in-memory SESSIONS dict.

Features:
  - Thread-safe via connection-per-operation pattern
  - JSON-serialised results stored in sessions table
  - Auto-cleanup of expired sessions
  - Graceful fallback: if SQLite fails, falls back to in-memory dict
"""

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path

logger = logging.getLogger("aniscanner.db")

_DB_PATH = Path("aniscanner_sessions.db")
_lock    = threading.Lock()


# ── Schema ─────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    status       TEXT NOT NULL DEFAULT 'running',
    scan_mode    TEXT NOT NULL DEFAULT 'TCP',
    ports        TEXT NOT NULL DEFAULT '[443]',
    concurrency  INTEGER NOT NULL DEFAULT 30,
    timeout      REAL    NOT NULL DEFAULT 3.0,
    scanned      INTEGER NOT NULL DEFAULT 0,
    total        INTEGER NOT NULL DEFAULT 0,
    stop_flag    INTEGER NOT NULL DEFAULT 0,
    started_at   REAL    NOT NULL,
    updated_at   REAL    NOT NULL,
    entries      TEXT    NOT NULL DEFAULT '[]',
    results      TEXT    NOT NULL DEFAULT '[]',
    adaptive_concurrency INTEGER NOT NULL DEFAULT 30
);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False, timeout=10)
    conn.row_factory  = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(_DDL)
    conn.commit()
    return conn


# ── SessionStore ───────────────────────────────────────────────────────

class SessionStore:
    """
    Manages scan session state in SQLite.
    In-memory listeners (SSE queues) are kept per-process only — not persisted.
    """

    def __init__(self):
        self._listeners:  dict[str, list] = {}   # sid → [queue, ...]
        self._mem_extras: dict[str, dict] = {}   # sid → {stop_flag, adaptive_concurrency}
        try:
            _connect().close()
            self._sqlite_ok = True
            logger.info("SessionStore: SQLite backend at %s", _DB_PATH)
        except Exception as exc:
            logger.warning("SessionStore: SQLite unavailable, using memory — %s", exc)
            self._sqlite_ok = False
            self._fallback:  dict[str, dict] = {}

    # ── Public API ───────────────────────────────────────────────────

    def create(self, sid: str, data: dict) -> None:
        now = time.time()
        if self._sqlite_ok:
            try:
                with _lock, _connect() as conn:
                    conn.execute(
                        """INSERT OR REPLACE INTO sessions
                           (id, status, scan_mode, ports, concurrency, timeout,
                            scanned, total, stop_flag, started_at, updated_at,
                            entries, results, adaptive_concurrency)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            sid,
                            data.get("status", "running"),
                            data.get("scan_mode", "TCP"),
                            json.dumps(data.get("ports", [443])),
                            data.get("concurrency", 30),
                            data.get("timeout", 3.0),
                            0,
                            len(data.get("entries", [])),
                            0,
                            data.get("started_at", now),
                            now,
                            json.dumps(data.get("entries", [])),
                            "[]",
                            data.get("concurrency", 30),
                        ),
                    )
                self._listeners[sid]  = []
                self._mem_extras[sid] = {"stop_flag": False, "adaptive_concurrency": data.get("concurrency", 30)}
                return
            except Exception as exc:
                logger.error("SessionStore.create SQLite error: %s", exc)

        # Fallback
        self._fallback[sid] = {**data, "results": [], "scanned": 0, "listeners": []}

    def get(self, sid: str) -> dict | None:
        if self._sqlite_ok:
            try:
                with _lock, _connect() as conn:
                    row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
                if row is None:
                    return None
                extras = self._mem_extras.get(sid, {})
                return {
                    "status":               row["status"],
                    "scan_mode":            row["scan_mode"],
                    "ports":               json.loads(row["ports"]),
                    "concurrency":         row["concurrency"],
                    "timeout":             row["timeout"],
                    "scanned":             row["scanned"],
                    "total":               row["total"],
                    "stop_flag":           bool(extras.get("stop_flag", row["stop_flag"])),
                    "started_at":          row["started_at"],
                    "entries":             json.loads(row["entries"]),
                    "results":             json.loads(row["results"]),
                    "adaptive_concurrency": extras.get("adaptive_concurrency", row["adaptive_concurrency"]),
                    "listeners":           self._listeners.get(sid, []),
                }
            except Exception as exc:
                logger.error("SessionStore.get SQLite error: %s", exc)
                return None

        return self._fallback.get(sid)

    def append_result(self, sid: str, result: dict) -> None:
        if self._sqlite_ok:
            try:
                with _lock, _connect() as conn:
                    row = conn.execute("SELECT results, scanned FROM sessions WHERE id=?", (sid,)).fetchone()
                    if row is None:
                        return
                    results = json.loads(row["results"])
                    results.append(result)
                    conn.execute(
                        "UPDATE sessions SET results=?, scanned=?, updated_at=? WHERE id=?",
                        (json.dumps(results), row["scanned"] + 1, time.time(), sid),
                    )
                return
            except Exception as exc:
                logger.error("SessionStore.append_result error: %s", exc)

        sess = self._fallback.get(sid)
        if sess:
            sess["results"].append(result)
            sess["scanned"] += 1

    def set_status(self, sid: str, status: str) -> None:
        if self._sqlite_ok:
            try:
                with _lock, _connect() as conn:
                    conn.execute(
                        "UPDATE sessions SET status=?, updated_at=? WHERE id=?",
                        (status, time.time(), sid),
                    )
                return
            except Exception as exc:
                logger.error("SessionStore.set_status error: %s", exc)

        if sid in self._fallback:
            self._fallback[sid]["status"] = status

    def set_stop_flag(self, sid: str, value: bool = True) -> None:
        extras = self._mem_extras.setdefault(sid, {})
        extras["stop_flag"] = value
        if not self._sqlite_ok and sid in self._fallback:
            self._fallback[sid]["stop_flag"] = value

    def get_stop_flag(self, sid: str) -> bool:
        return bool(self._mem_extras.get(sid, {}).get("stop_flag", False))

    def set_adaptive_concurrency(self, sid: str, value: int) -> None:
        extras = self._mem_extras.setdefault(sid, {})
        extras["adaptive_concurrency"] = value
        if not self._sqlite_ok and sid in self._fallback:
            self._fallback[sid]["adaptive_concurrency"] = value

    def add_listener(self, sid: str, q) -> None:
        self._listeners.setdefault(sid, []).append(q)

    def remove_listener(self, sid: str, q) -> None:
        try:
            self._listeners.get(sid, []).remove(q)
        except ValueError:
            pass

    def get_listeners(self, sid: str) -> list:
        return list(self._listeners.get(sid, []))

    def exists(self, sid: str) -> bool:
        if self._sqlite_ok:
            try:
                with _lock, _connect() as conn:
                    row = conn.execute("SELECT 1 FROM sessions WHERE id=?", (sid,)).fetchone()
                return row is not None
            except Exception:
                return False
        return sid in self._fallback

    def cleanup_expired(self, session_ttl: float = 1800) -> int:
        now = time.time()
        removed = 0
        if self._sqlite_ok:
            try:
                with _lock, _connect() as conn:
                    rows = conn.execute(
                        """SELECT id, status, started_at FROM sessions
                           WHERE (status IN ('done','stopped') AND ? - started_at > ?)
                              OR (? - started_at > ?)""",
                        (now, session_ttl, now, session_ttl * 2),
                    ).fetchall()
                    for row in rows:
                        # notify listeners
                        for q in self._listeners.get(row["id"], []):
                            try: q.put_nowait(None)
                            except Exception: pass
                        conn.execute("DELETE FROM sessions WHERE id=?", (row["id"],))
                        self._listeners.pop(row["id"], None)
                        self._mem_extras.pop(row["id"], None)
                        removed += 1
            except Exception as exc:
                logger.error("SessionStore.cleanup error: %s", exc)
        else:
            expired = []
            for sid, sess in list(self._fallback.items()):
                age    = now - sess.get("started_at", now)
                status = sess.get("status", "")
                if (status in ("done", "stopped") and age > session_ttl) or age > session_ttl * 2:
                    expired.append(sid)
            for sid in expired:
                for q in self._fallback[sid].get("listeners", []):
                    try: q.put_nowait(None)
                    except Exception: pass
                del self._fallback[sid]
                self._listeners.pop(sid, None)
                self._mem_extras.pop(sid, None)
                removed += 1

        if removed:
            logger.info("SessionStore cleanup: removed %d expired sessions", removed)
        return removed


# ── Singleton ─────────────────────────────────────────────────────────
session_store = SessionStore()
