# ============================================================
# Secure E2EE Chat Server
# Graceful shutdown | TLS | PBKDF2 | Rate-limit
# ============================================================

import base64
import socket
import threading
import os
import json
import hashlib
import hmac
import secrets
import time
import ssl
import sys

from protocol import (
    TYPE_NAME_REQ, TYPE_NAME,
    TYPE_AUTH_REQ, TYPE_AUTH, TYPE_AUTH_OK,
    TYPE_PUBKEY_REQ, TYPE_PUBKEY,
    TYPE_USER_ANNOUNCE,
    TYPE_SESSION_OFFER, TYPE_SESSION_ACK,
    TYPE_PRIVATE_MSG, TYPE_BROADCAST, TYPE_DIRECT_MSG,
)
from server_transport import ProtoPeer

# ============================================================
# CONFIG
# ============================================================

HOST = "127.0.0.1"
PORT = 12345

TLS_CERTFILE = "../certs/server_cert.pem"
TLS_KEYFILE = "../certs/server_key.pem"

AUTH_FILE = "Users/auth_users.json"

PBKDF2_ITERS = 200_000
PBKDF2_SALT_LEN = 16
PBKDF2_DK_LEN = 32

AUTH_WINDOW_SEC = 60
AUTH_MAX_FAILS = 8
AUTH_LOCK_SEC = 30

# Rate limit (per-connection)
MSG_WINDOW_SEC = 2.0
MSG_MAX_IN_WINDOW = 40          # tune: 20-60 tùy demo
MAX_TEXT_LEN = 2000
MAX_B64_LEN = 64_000            # ciphertext cap
MAX_PUBKEY_B64_LEN = 16_000     # pubkey cap

# ============================================================
# GLOBAL STATE
# ============================================================

server_running = True

user_db_lock = threading.Lock()
clients_data: dict[socket.socket, dict] = {}
clients_lock = threading.Lock()

user_db: dict[str, object] = {}
auth_failures: dict[str, dict] = {}
auth_lock = threading.Lock()

server_socket: socket.socket | None = None

# ============================================================
# AUTH HELPERS
# ============================================================

def hash_password(password: str, *, salt: bytes | None = None) -> dict:
    if salt is None:
        salt = secrets.token_bytes(PBKDF2_SALT_LEN)

    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        PBKDF2_ITERS,
        dklen=PBKDF2_DK_LEN,
    )

    return {
        "kdf": "pbkdf2_sha256",
        "i": PBKDF2_ITERS,
        "s": base64.b64encode(salt).decode(),
        "h": base64.b64encode(dk).decode(),
    }


def verify_password(password: str, stored) -> tuple[bool, bool]:
    if stored is None:
        return False, False

    # Legacy SHA256
    if isinstance(stored, str):
        return (
            hmac.compare_digest(
                hashlib.sha256(password.encode()).hexdigest(),
                stored
            ),
            True,
        )

    try:
        iters = int(stored["i"])
        salt = base64.b64decode(stored["s"])
        want = base64.b64decode(stored["h"])
    except Exception:
        return False, False

    got = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        iters,
        dklen=len(want),
    )

    return hmac.compare_digest(want, got), False


def auth_key(name: str, sock: socket.socket) -> str:
    try:
        ip = sock.getpeername()[0]
    except Exception:
        ip = "unknown"
    return f"{ip}:{name}"


def auth_check_locked(key: str) -> int:
    now = time.time()
    with auth_lock:
        rec = auth_failures.get(key)
        if not rec:
            return 0
        if now < rec.get("lock_until", 0):
            return int(rec["lock_until"] - now)
        return 0


def auth_on_fail(key: str) -> int:
    now = time.time()
    with auth_lock:
        rec = auth_failures.setdefault(key, {"fails": [], "lock_until": 0})
        rec["fails"] = [t for t in rec["fails"] if now - t <= AUTH_WINDOW_SEC]
        rec["fails"].append(now)

        if len(rec["fails"]) >= AUTH_MAX_FAILS:
            rec["lock_until"] = now + AUTH_LOCK_SEC
            return AUTH_LOCK_SEC
        return 0


def auth_on_success(key: str):
    with auth_lock:
        auth_failures.pop(key, None)

# ============================================================
# USER DB
# ============================================================

def load_user_db():
    global user_db
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE, "r", encoding="utf-8") as f:
                user_db = json.load(f)
        except Exception:
            user_db = {}
    else:
        user_db = {}


def save_user_db():
    try:
        os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(user_db, f, indent=2)
    except Exception as e:
        print(f"[AUTH] Save failed: {e}")

# ============================================================
# CLIENT REGISTRY
# ============================================================

def find_socket_by_name(name: str):
    with clients_lock:
        for s, info in clients_data.items():
            if info["name"] == name:
                return s
    return None


def broadcast(msg: dict):
    dead = []
    with clients_lock:
        sockets = list(clients_data.keys())

    for s in sockets:
        try:
            ProtoPeer(s).send(msg)
        except Exception:
            dead.append(s)

    if dead:
        offline_names: list[str] = []
        with clients_lock:
            for s in dead:
                info = clients_data.pop(s, None)
                if info and "name" in info:
                    offline_names.append(info["name"])
                try:
                    s.close()
                except Exception:
                    pass

        # announce offline for those who silently died
        now_ts = int(time.time())
        for n in offline_names:
            try:
                broadcast({"type": TYPE_USER_ANNOUNCE, "payload": {"name": n, "pubkey_b64": None, "ts": now_ts}})
            except Exception:
                pass

def send_existing_users(to_sock: socket.socket):
    peer = ProtoPeer(to_sock)
    with clients_lock:
        users = list(clients_data.values())

    now = int(time.time())
    for info in users:
        peer.send_user_announce(
            info["name"],
            base64.b64encode(info["pubkey"]).decode(),
            now
        )

# ============================================================
# CLIENT HANDLER
# ============================================================

def handle_client(sock: socket.socket):
    peer = ProtoPeer(sock)
    name = None

    try:
        # ---- NAME ----
        peer.send({"type": TYPE_NAME_REQ, "payload": {}})
        m = peer.recv()
        if m.get("type") != TYPE_NAME:
            peer.send_error("Expected NAME")
            return

        name = (m["payload"].get("name") or "").strip()
        if not name or " " in name or ":" in name:
            peer.send_error("Invalid name")
            return

        with clients_lock:
            if any(c["name"] == name for c in clients_data.values()):
                peer.send_error("Name already in use")
                return

        # ---- AUTH ----
        peer.send({"type": TYPE_AUTH_REQ, "payload": {}})
        m = peer.recv()
        if m.get("type") != TYPE_AUTH:
            peer.send_error("Expected AUTH")
            return

        password = (m["payload"].get("password") or "").strip()
        if not password:
            peer.send_error("Empty password")
            return

        # Lockout key: ip:name
        key = auth_key(name, sock)
        wait = auth_check_locked(key)
        if wait > 0:
            peer.send_error(f"Locked {wait}s")
            return

        # 1) Snapshot stored record under user_db_lock (DO NOT verify under lock)
        with user_db_lock:
            stored = user_db.get(name)

        if stored is None:
            # 2) Register new user (write path under lock)
            new_rec = hash_password(password)
            with user_db_lock:
                # Re-check to avoid race: two clients register same name concurrently
                if user_db.get(name) is None:
                    user_db[name] = new_rec
                    save_user_db()
                else:
                    stored = user_db.get(name)

            # If stored was filled by another thread in the race, verify against it
            if stored is not None:
                ok, legacy = verify_password(password, stored)
                if not ok:
                    lock = auth_on_fail(key)
                    peer.send_error("Auth failed" if lock == 0 else f"Locked {lock}s")
                    return
                if legacy:
                    upgraded = hash_password(password)
                    with user_db_lock:
                        user_db[name] = upgraded
                        save_user_db()
        else:
            # 3) Existing user: verify outside lock
            ok, legacy = verify_password(password, stored)
            if not ok:
                lock = auth_on_fail(key)
                peer.send_error("Auth failed" if lock == 0 else f"Locked {lock}s")
                return

            # 4) Upgrade legacy SHA256 record to PBKDF2 (write under lock)
            if legacy:
                upgraded = hash_password(password)
                with user_db_lock:
                    # Optional: ensure it hasn't changed; but overwrite is acceptable here
                    user_db[name] = upgraded
                    save_user_db()

        auth_on_success(key)
        peer.send({"type": TYPE_AUTH_OK, "payload": {}})

        # ---- PUBKEY ----
        peer.send({"type": TYPE_PUBKEY_REQ, "payload": {}})
        m = peer.recv()
        pub_b64 = m.get("payload", {}).get("pubkey_b64")
        if not pub_b64 or not isinstance(pub_b64, str) or len(pub_b64) > MAX_PUBKEY_B64_LEN:
            peer.send_error("Missing/invalid pubkey")
            return

        try:
            pubkey = base64.b64decode(pub_b64, validate=True)
        except Exception:
            peer.send_error("Invalid pubkey_b64")
            return

        if len(pubkey) < 64 or len(pubkey) > 8192:
            peer.send_error("Invalid pubkey size")
            return

        with clients_lock:
            clients_data[sock] = {"name": name, "pubkey": pubkey}

        send_existing_users(sock)
        broadcast({
            "type": TYPE_USER_ANNOUNCE,
            "payload": {"name": name, "pubkey_b64": pub_b64, "ts": int(time.time())}
        })
        
        # ---- HELPERS ----
        def _pget(d: dict, *keys, default=None):
            """payload getter: try top-level then payload dict."""
            if not isinstance(d, dict):
                return default
            for k in keys:
                if k in d:
                    return d.get(k, default)
            payload = d.get("payload")
            if isinstance(payload, dict):
                for k in keys:
                    if k in payload:
                        return payload.get(k, default)
            return default
        
        # ---- RATE LIMIT HELPERS ----
        msg_times: list[float] = []

        def rate_limit_hit() -> bool:
            now = time.time()
            # keep only within window
            while msg_times and (now - msg_times[0] > MSG_WINDOW_SEC):
                msg_times.pop(0)
            msg_times.append(now)
            return len(msg_times) > MSG_MAX_IN_WINDOW
        
        def b64_is_valid(s: str, max_len: int) -> bool:
            if not isinstance(s, str) or not s or len(s) > max_len:
                return False
            try:
                base64.b64decode(s, validate=True)
                return True
            except Exception:
                return False

        # ---- MESSAGE LOOP ----
        while server_running:
            m = peer.recv()
            if rate_limit_hit():
                peer.send_error("Rate limit exceeded")
                continue

            t = m.get("type")

            if t == TYPE_BROADCAST:
                text = _pget(m, "text", default="")
                if not isinstance(text, str):
                    peer.send_error("Malformed BROADCAST (text must be string)")
                    continue
                if len(text) > MAX_TEXT_LEN:
                    peer.send_error("BROADCAST too long")
                    continue

                broadcast({"type": TYPE_BROADCAST, "payload": {"from": name, "text": text}})

            elif t == TYPE_PRIVATE_MSG:
                target = _pget(m, "to")
                ctb64 = _pget(m, "ciphertext_b64")
                ctr = _pget(m, "ctr")
                msg_id = _pget(m, "msg_id")
                ts = _pget(m, "ts")

                if not target or not ctb64 or ctr is None or not msg_id or ts is None:
                    peer.send_error("Malformed PRIVATE_MSG (missing to/ciphertext_b64/ctr/msg_id/ts)")
                    continue

                if not b64_is_valid(ctb64, MAX_B64_LEN):
                    peer.send_error("Malformed PRIVATE_MSG (ciphertext_b64 invalid/too large)")
                    continue

                if not isinstance(msg_id, str) or len(msg_id) > 128:
                    peer.send_error("Malformed PRIVATE_MSG (msg_id invalid)")
                    continue

                try:
                    ctr_i = int(ctr)
                    if ctr_i <= 0:
                        raise ValueError("ctr must be > 0")
                except Exception:
                    peer.send_error("Malformed PRIVATE_MSG (ctr must be positive int)")
                    continue

                try:
                    ts_i = int(ts)
                except Exception:
                    peer.send_error("Malformed PRIVATE_MSG (ts must be int)")
                    continue

                cs = find_socket_by_name(target)
                if cs:
                    ProtoPeer(cs).forward_private(name, ctb64, ctr_i, str(msg_id), ts_i)
                else:
                    peer.send_error("User offline")

            elif t == TYPE_DIRECT_MSG:
                target = _pget(m, "to")
                text = _pget(m, "text", default="")
                if not isinstance(text, str):
                    peer.send_error("Malformed DIRECT_MSG (text must be string)")
                    continue
                if len(text) > MAX_TEXT_LEN:
                    peer.send_error("DIRECT_MSG too long")
                    continue

                if not target:
                    peer.send_error("Malformed DIRECT_MSG (missing to)")
                    continue

                cs = find_socket_by_name(target)
                if cs:
                    ProtoPeer(cs).forward_direct(name, str(text))
                else:
                    peer.send_error("User offline")

            elif t == TYPE_SESSION_OFFER:
                target = _pget(m, "to")
                session_id = _pget(m, "session_id")
                encrypted_key_b64 = _pget(m, "encrypted_key_b64")
                sig_b64 = _pget(m, "sig_b64")
                ts = _pget(m, "ts")
                if ts is None:
                    peer.send_error("Malformed SESSION_OFFER (missing ts)")
                    continue

                if not target or not session_id or not encrypted_key_b64 or not sig_b64:
                    peer.send_error("Malformed SESSION_OFFER (missing fields)")
                    continue
                
                if not b64_is_valid(encrypted_key_b64, MAX_B64_LEN):
                    peer.send_error("Malformed SESSION_OFFER (encrypted_key_b64 invalid/too large)")
                    continue

                if not b64_is_valid(sig_b64, 8_000):
                    peer.send_error("Malformed SESSION_OFFER (sig_b64 invalid/too large)")
                    continue

                if not isinstance(session_id, str) or len(session_id) > 128:
                    peer.send_error("Malformed SESSION_OFFER (session_id invalid)")
                    continue

                cs = find_socket_by_name(target)
                if cs:
                    ProtoPeer(cs).forward_session_offer(name, session_id, encrypted_key_b64, sig_b64, int(ts))
                else:
                    peer.send_error("User offline")

            elif t == TYPE_SESSION_ACK:
                target = _pget(m, "to")
                session_id = _pget(m, "session_id")
                confirm_hex = _pget(m, "confirm_hex")

                if not target or not session_id or not confirm_hex:
                    peer.send_error("Malformed SESSION_ACK (missing fields)")
                    continue

                cs = find_socket_by_name(target)
                if cs:
                    ProtoPeer(cs).forward_session_ack(name, session_id, confirm_hex)
                else:
                    peer.send_error("User offline")

            else:
                peer.send_error("Unsupported type")

    except Exception as e:
        print(f"[SERVER] Client error ({name}): {e}")

    finally:
        # Remove first, then broadcast offline to remaining sockets
        if name:
            with clients_lock:
                clients_data.pop(sock, None)
            try:
                broadcast({"type": TYPE_USER_ANNOUNCE, "payload": {"name": name, "pubkey_b64": None, "ts": int(time.time())}})
            except Exception:
                pass
        else:
            with clients_lock:
                clients_data.pop(sock, None)

        try:
            sock.close()
        except Exception:
            pass


# ============================================================
# SERVER CONTROL
# ============================================================

def command_input():
    global server_running
    while server_running:
        cmd = input().strip().lower()
        if cmd in ("exit", "quit"):
            print("[SERVER] Shutdown requested by console.")
            server_running = False
            break

def start_server():
    global server_socket
    global server_running

    load_user_db()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(TLS_CERTFILE, TLS_KEYFILE)
    
    # Harden TLS context
    ctx.options |= ssl.OP_NO_COMPRESSION
    # Prefer modern ciphersuites (OpenSSL dependent)
    try:
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!3DES")
    except Exception:
        pass

    server_socket = socket.socket()
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    server_socket.settimeout(1.0)  # <<< CỐT LÕI GIÚP CTRL+C TẮT ĐƯỢC

    print(f"[SERVER] Listening TLS on {HOST}:{PORT}")
    print("[SERVER] Type 'exit' or Ctrl+C to stop.")

    try:
        while server_running:
            try:
                raw, addr = server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                sock = ctx.wrap_socket(raw, server_side=True)
            except ssl.SSLError:
                try:
                    raw.close()
                except Exception:
                    pass
                continue
            except Exception:
                try:
                    raw.close()
                except Exception:
                    pass
                continue

            threading.Thread(target=handle_client, args=(sock,), daemon=True).start()

    except KeyboardInterrupt:
        print("\n[SERVER] Ctrl+C received.")

    finally:
        server_running = False
        server_socket.close()
        print("[SERVER] Server stopped.")

# ============================================================
# ENTRY
# ============================================================

if __name__ == "__main__":
    threading.Thread(target=command_input, daemon=True).start()
    start_server()