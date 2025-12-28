# local_store.py
from __future__ import annotations

import base64
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from crypto_utils import aes_encrypt, aes_decrypt, kdf_scrypt, hkdf_conv_key


def _default_root() -> Path:
    """Default per-user app data root, cross-platform."""
    if os.name == "nt":
        root = os.environ.get("APPDATA") or str(Path.home())
        return Path(root) / "SecureChat"
    # Linux/macOS
    return Path.home() / ".local" / "share" / "SecureChat"


@dataclass
class StorePaths:
    root: Path
    keystore: Path
    db: Path


class LocalMessageStore:
    """
    Local message store with encryption-at-rest.

    Security model:
    - A per-user LSMK (Local Store Master Key) is generated on first run.
    - LSMK is wrapped under a password-derived KEK (scrypt) and stored in keystore.json.
    - Per-conversation at-rest keys are derived via HKDF(LSMK, username|peer_key).
    - Messages are stored encrypted in SQLite with AES-GCM + per-row AAD.

    Practical design goals:
    - No server-side message storage.
    - Import/export is password-protected.
    - Import behavior: OVERWRITE (not merge). Importing the same archive twice does NOT duplicate history.

    Robustness goals (fixes common "missing history" issues):
    - Serialize DB access with a lock (SQLite connection is not safe for concurrent use).
    - Add 'peer_key' column for stable conversation identity, independent of display label changes.
    - Decrypt each row using its stored peer_key (backward compatible with older DBs).
    """

    SCHEMA_VERSION = 2  # v1: messages(peer,...). v2: add peer_key, peer_display (keep old 'peer' as display)

    def __init__(self, username: str, root: Optional[Path] = None):
        self.username = username
        self.paths = self._paths(username, root=root)
        self._db: Optional[sqlite3.Connection] = None
        self._lsmk: Optional[bytes] = None
        self._lock = threading.RLock()

        # Cached capabilities after schema check
        self._has_peer_key: bool = False

    @staticmethod
    def _paths(username: str, root: Optional[Path] = None) -> StorePaths:
        base = root or _default_root()
        user_root = Path(base) / username
        return StorePaths(
            root=user_root,
            keystore=user_root / "keystore.json",
            db=user_root / "messages.sqlite",
        )

    def is_unlocked(self) -> bool:
        return self._lsmk is not None and self._db is not None

    # ---------------- Internal helpers ----------------

    def _require_unlocked(self) -> None:
        if not self.is_unlocked():
            raise RuntimeError("LocalMessageStore is locked/not initialized")

    @staticmethod
    def _canon_peer(peer: str) -> str:
        """
        Canonical peer identifier used to group history and derive keys.

        We keep this conservative (strip only) to avoid surprising behavior.
        If your UI decorates names (e.g., "alice (offline)"), consider passing the raw username to the store.
        """
        if not isinstance(peer, str):
            raise ValueError("peer must be a string")
        return peer.strip()

    def _conv_key(self, peer_key: str) -> bytes:
        self._require_unlocked()
        assert self._lsmk is not None
        return hkdf_conv_key(self._lsmk, self.username, peer_key)

    def _connect_db(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.paths.db), check_same_thread=False)
        # WAL is good for responsiveness; we still lock access ourselves.
        db.execute("PRAGMA journal_mode=WAL;")
        db.execute("PRAGMA synchronous=NORMAL;")
        db.execute("PRAGMA foreign_keys=ON;")
        db.execute("PRAGMA busy_timeout=3000;")
        return db

    def _column_exists(self, table: str, col: str) -> bool:
        assert self._db is not None
        rows = self._db.execute(f"PRAGMA table_info({table});").fetchall()
        return any(r[1] == col for r in rows)

    def _ensure_schema(self) -> None:
        """
        Ensure DB schema exists and perform lightweight migrations.

        Backward compatibility:
        - If an existing DB has only 'peer' column, we treat it as display and add 'peer_key' column.
        - Existing rows default peer_key = peer, so decryption continues to work.
        """
        self._require_unlocked()
        assert self._db is not None

        # Create baseline table (v1 compatible)
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                peer TEXT NOT NULL,
                direction TEXT NOT NULL,   -- 'in' | 'out'
                ts INTEGER NOT NULL,
                e2ee INTEGER NOT NULL,
                status TEXT NOT NULL,      -- 'queued' | 'sent' | 'recv'
                aad BLOB NOT NULL,
                blob BLOB NOT NULL
            );
            """
        )
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_peer_ts ON messages(peer, ts);")

        # Migration to v2: add peer_key (stable conv id) if missing
        if not self._column_exists("messages", "peer_key"):
            self._db.execute("ALTER TABLE messages ADD COLUMN peer_key TEXT NOT NULL DEFAULT peer;")
        # Optional: keep a more explicit display column for future UI decoration without breaking grouping
        if not self._column_exists("messages", "peer_display"):
            self._db.execute("ALTER TABLE messages ADD COLUMN peer_display TEXT NOT NULL DEFAULT peer;")

        # Keep peer column as "legacy display" but ensure peer_display matches it for old DBs.
        # For new writes we populate both peer_display and peer.
        self._has_peer_key = True

        # Prefer indexing by peer_key for conversation queries
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_peerkey_ts ON messages(peer_key, ts);")
        self._db.commit()

    def _checkpoint(self) -> None:
        """Flush WAL into the main DB file (useful before copying/exporting)."""
        if self._db is None:
            return
        try:
            self._db.execute("PRAGMA wal_checkpoint(FULL);")
        except Exception:
            pass

    # ---------------- Public API ----------------

    def unlock(self, password: str) -> None:
        """Unlock (or initialize) the local store using the provided password."""
        if not password:
            raise ValueError("password must not be empty")

        self.paths.root.mkdir(parents=True, exist_ok=True)

        with self._lock:
            # ---------- Keystore ----------
            if not self.paths.keystore.exists():
                # First-time init
                salt = os.urandom(16)
                kek = kdf_scrypt(password=password, salt=salt)
                lsmk = os.urandom(32)
                wrapped = aes_encrypt(lsmk, kek, associated_data=f"LSMK|{self.username}|v1".encode("utf-8"))
                data = {
                    "version": 1,
                    "kdf": {
                        "name": "scrypt",
                        "n": 2**14,
                        "r": 8,
                        "p": 1,
                        "salt_b64": base64.b64encode(salt).decode("utf-8"),
                    },
                    "wrapped_lsmk_b64": base64.b64encode(wrapped).decode("utf-8"),
                    "created_ts": int(time.time()),
                }
                self.paths.keystore.write_text(json.dumps(data, indent=2), encoding="utf-8")
                self._lsmk = lsmk
            else:
                try:
                    data = json.loads(self.paths.keystore.read_text(encoding="utf-8"))
                    kdf = data.get("kdf") or {}
                    salt_b64 = kdf.get("salt_b64", "")
                    wrapped_b64 = data.get("wrapped_lsmk_b64", "")
                    salt = base64.b64decode(salt_b64.encode("utf-8"), validate=False)
                    wrapped = base64.b64decode(wrapped_b64.encode("utf-8"), validate=False)
                except Exception as e:
                    raise ValueError(f"Corrupted keystore.json: {e}") from e

                kek = kdf_scrypt(
                    password=password,
                    salt=salt,
                    n=int(kdf.get("n", 2**14)),
                    r=int(kdf.get("r", 8)),
                    p=int(kdf.get("p", 1)),
                )
                lsmk = aes_decrypt(wrapped, kek, associated_data=f"LSMK|{self.username}|v1".encode("utf-8"))
                if lsmk is None:
                    raise ValueError("Invalid local-store password (cannot unwrap LSMK).")
                self._lsmk = lsmk

            # ---------- DB ----------
            self._db = self._connect_db()
            self._ensure_schema()

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                try:
                    self._checkpoint()
                    self._db.close()
                except Exception:
                    pass
            self._db = None
            self._lsmk = None

    def save_message(
        self,
        msg_id: str,
        peer: str,
        direction: str,
        ts: int,
        plaintext: str,
        e2ee: bool,
        status: str,
    ) -> None:
        """Insert or replace a message record."""
        self._require_unlocked()
        if not msg_id:
            raise ValueError("msg_id required")
        if not isinstance(peer, str) or not peer.strip():
            raise ValueError("peer required")
        if direction not in ("in", "out"):
            raise ValueError("direction must be 'in' or 'out'")
        if status not in ("queued", "sent", "recv"):
            raise ValueError("status invalid")
        if not isinstance(ts, int):
            ts = int(ts)

        peer_display = peer
        peer_key = self._canon_peer(peer)

        # Derive key using stable peer_key (not display label)
        key = self._conv_key(peer_key)

        # AAD is stored per-row, so decrypt will always use exact same AAD.
        aad = f"{self.username}|{peer_key}|{direction}|{ts}|{msg_id}|e2ee={int(bool(e2ee))}|v1".encode("utf-8")
        blob = aes_encrypt(plaintext.encode("utf-8"), key, associated_data=aad)

        with self._lock:
            assert self._db is not None
            cur = self._db.cursor()
            # Populate both legacy 'peer' and explicit 'peer_display' for compatibility / UI.
            cur.execute(
                """
                INSERT OR REPLACE INTO messages
                (id, peer, peer_display, peer_key, direction, ts, e2ee, status, aad, blob)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (msg_id, peer_display, peer_display, peer_key, direction, int(ts), int(bool(e2ee)), status, aad, blob),
            )
            self._db.commit()

    def update_status(self, msg_id: str, status: str) -> None:
        self._require_unlocked()
        if status not in ("queued", "sent", "recv"):
            raise ValueError("status invalid")
        with self._lock:
            assert self._db is not None
            cur = self._db.cursor()
            cur.execute("UPDATE messages SET status=? WHERE id=?", (status, msg_id))
            self._db.commit()

    def load_conversation(self, peer: str, limit: int = 500) -> List[Dict]:
        """
        Load and decrypt conversation history.

        Key detail:
        - We *do not* derive a single key from the input 'peer' and use it for all rows.
          Instead, we decrypt each row using its stored peer_key. This fixes cases where:
            * UI peer labels changed,
            * the store was called with a decorated display label,
            * or you migrated the schema.
        """
        self._require_unlocked()
        peer_display = peer
        peer_key = self._canon_peer(peer)

        with self._lock:
            assert self._db is not None
            cur = self._db.cursor()
            rows = cur.execute(
                """
                SELECT id, direction, ts, e2ee, status, aad, blob, peer_key, peer_display
                FROM messages
                WHERE peer_key=? OR peer_display=? OR peer=?
                ORDER BY ts ASC
                LIMIT ?
                """,
                (peer_key, peer_display, peer_display, int(limit)),
            ).fetchall()

        out: List[Dict] = []
        for mid, direction, ts, e2ee, status, aad, blob, row_peer_key, row_peer_display in rows:
            try:
                key = self._conv_key(str(row_peer_key))
            except Exception:
                # As a fallback, try legacy display
                key = self._conv_key(str(row_peer_display))

            pt = aes_decrypt(blob, key, associated_data=aad)
            text = pt.decode("utf-8", errors="replace") if pt is not None else "[CORRUPTED]"
            out.append(
                {
                    "id": mid,
                    "direction": direction,
                    "ts": int(ts),
                    "e2ee": bool(e2ee),
                    "status": status,
                    "text": text,
                }
            )
        return out

    def list_conversations(self, limit: int = 200) -> List[Tuple[str, int]]:
        """
        Return a list of conversations as (peer_key, last_ts), newest first.
        Useful if you want to render a sidebar from DB instead of RAM.
        """
        self._require_unlocked()
        with self._lock:
            assert self._db is not None
            rows = self._db.execute(
                """
                SELECT peer_key, MAX(ts) as last_ts
                FROM messages
                GROUP BY peer_key
                ORDER BY last_ts DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        return [(str(peer_key), int(last_ts)) for peer_key, last_ts in rows]

    # -------- Export / Import --------

    def export_archive(self, out_zip_path: str, passphrase: str) -> str:
        """
        Export local store to a zip file, wrapping the LSMK under passphrase.
        The export is device-independent and can be imported elsewhere.
        """
        self._require_unlocked()
        if not passphrase:
            raise ValueError("Export passphrase must not be empty.")

        out_zip = Path(out_zip_path)
        out_zip.parent.mkdir(parents=True, exist_ok=True)

        with self._lock:
            # Flush WAL so the copied DB is complete.
            self._checkpoint()
            if self._db is not None:
                self._db.commit()

            assert self._lsmk is not None
            salt = os.urandom(16)
            kek = kdf_scrypt(password=passphrase, salt=salt, n=2**14, r=8, p=1)
            wrapped = aes_encrypt(self._lsmk, kek, associated_data=f"EXPORT_LSMK|{self.username}|v1".encode("utf-8"))
            export_meta = {
                "version": 1,
                "username": self.username,
                "kdf": {
                    "name": "scrypt",
                    "n": 2**14,
                    "r": 8,
                    "p": 1,
                    "salt_b64": base64.b64encode(salt).decode("utf-8"),
                },
                "wrapped_lsmk_b64": base64.b64encode(wrapped).decode("utf-8"),
                "created_ts": int(time.time()),
            }

            with tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                meta_path = tmp / "export_keystore.json"
                db_path = tmp / "messages.sqlite"

                meta_path.write_text(json.dumps(export_meta, indent=2), encoding="utf-8")

                if self.paths.db.exists():
                    shutil.copy2(self.paths.db, db_path)
                else:
                    db_path.write_bytes(b"")

                with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.write(meta_path, arcname="export_keystore.json")
                    zf.write(db_path, arcname="messages.sqlite")

        return str(out_zip)

    def import_archive(self, zip_path: str, passphrase: str, device_password: str) -> Dict[str, str]:
        """
        Import an exported archive into the current user's local store.

        Behavior:
        - OVERWRITE (not merge). It replaces local history on this device.
        - A timestamped backup is created first.
        - Importing the same archive twice does NOT duplicate history (it overwrites).
        """
        if not passphrase:
            raise ValueError("Import passphrase must not be empty.")
        if not device_password:
            raise ValueError("Device password must not be empty.")

        zp = Path(zip_path)
        if not zp.exists():
            raise FileNotFoundError(f"Archive not found: {zip_path}")

        with self._lock:
            # Extract to temp
            with tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                with zipfile.ZipFile(zp, "r") as zf:
                    zf.extractall(tmp)

                meta_path = tmp / "export_keystore.json"
                db_path = tmp / "messages.sqlite"
                if not meta_path.exists() or not db_path.exists():
                    raise ValueError("Invalid archive (missing export_keystore.json or messages.sqlite).")

                export_meta = json.loads(meta_path.read_text(encoding="utf-8"))
                export_user = export_meta.get("username")
                if export_user != self.username:
                    raise ValueError(
                        f"Archive belongs to '{export_user}', cannot import into '{self.username}'."
                    )

                # Derive KEK from passphrase, unwrap exported LSMK
                kdf = export_meta.get("kdf") or {}
                salt = base64.b64decode(kdf.get("salt_b64", "").encode("utf-8"), validate=False)
                kek = kdf_scrypt(
                    password=passphrase,
                    salt=salt,
                    n=int(kdf.get("n", 2**14)),
                    r=int(kdf.get("r", 8)),
                    p=int(kdf.get("p", 1)),
                )
                wrapped = base64.b64decode(export_meta.get("wrapped_lsmk_b64", "").encode("utf-8"), validate=False)
                lsmk = aes_decrypt(wrapped, kek, associated_data=f"EXPORT_LSMK|{self.username}|v1".encode("utf-8"))
                if lsmk is None:
                    raise ValueError("Invalid passphrase (cannot unwrap exported LSMK).")

                # Backup current store
                backup_dir = self.paths.root / "backups"
                backup_dir.mkdir(parents=True, exist_ok=True)
                ts = time.strftime("%Y%m%d-%H%M%S")
                backup_zip = backup_dir / f"backup_{ts}.zip"
                try:
                    # If not unlocked, still try to zip raw files as backup
                    if self.is_unlocked():
                        self.export_archive(str(backup_zip), passphrase=f"backup-{ts}")
                    else:
                        # Raw copy
                        with zipfile.ZipFile(backup_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                            if self.paths.keystore.exists():
                                zf.write(self.paths.keystore, arcname="keystore.json")
                            if self.paths.db.exists():
                                zf.write(self.paths.db, arcname="messages.sqlite")
                except Exception:
                    # Backup is best-effort; continue.
                    pass

                # Re-wrap imported LSMK under device_password and replace keystore.json
                salt2 = os.urandom(16)
                kek2 = kdf_scrypt(password=device_password, salt=salt2)
                wrapped2 = aes_encrypt(lsmk, kek2, associated_data=f"LSMK|{self.username}|v1".encode("utf-8"))
                new_keystore = {
                    "version": 1,
                    "kdf": {
                        "name": "scrypt",
                        "n": 2**14,
                        "r": 8,
                        "p": 1,
                        "salt_b64": base64.b64encode(salt2).decode("utf-8"),
                    },
                    "wrapped_lsmk_b64": base64.b64encode(wrapped2).decode("utf-8"),
                    "created_ts": int(time.time()),
                    "imported_from": str(zp.name),
                    "imported_ts": int(time.time()),
                }

                # Close current DB before overwriting
                if self._db is not None:
                    try:
                        self._checkpoint()
                        self._db.close()
                    except Exception:
                        pass
                    self._db = None

                self.paths.keystore.write_text(json.dumps(new_keystore, indent=2), encoding="utf-8")
                shutil.copy2(db_path, self.paths.db)

                # Re-open with new password (so _lsmk matches imported)
                self._lsmk = None
                self.unlock(device_password)

                return {
                    "status": "ok",
                    "backup_zip": str(backup_zip),
                }
