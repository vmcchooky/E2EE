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
    TYPE_PRIVATE_MSG, TYPE_BROADCAST
)
from server_transport import ProtoPeer

# ============================================================
# CONFIG
# ============================================================

HOST = "127.0.0.1"
PORT = 12345

# Làm đường dẫn cert/key theo vị trí file để tránh phụ thuộc "working directory"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TLS_CERTFILE = os.path.normpath(os.path.join(BASE_DIR, "..", "certs", "server_cert.pem"))
TLS_KEYFILE = os.path.normpath(os.path.join(BASE_DIR, "..", "certs", "server_key.pem"))

AUTH_FILE = "Users/auth_users.json"

PBKDF2_ITERS = 200_000
PBKDF2_SALT_LEN = 16
PBKDF2_DK_LEN = 32

AUTH_WINDOW_SEC = 60
AUTH_MAX_FAILS = 8
AUTH_LOCK_SEC = 30

# ============================================================
# GLOBAL STATE
# ============================================================

server_running = True

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
        with clients_lock:
            for s in dead:
                clients_data.pop(s, None)
                try:
                    s.close()
                except Exception:
                    pass


def send_existing_users(to_sock: socket.socket):
    peer = ProtoPeer(to_sock)
    with clients_lock:
        users = list(clients_data.values())

    for info in users:
        peer.send_user_announce(
            info["name"],
            base64.b64encode(info["pubkey"]).decode()
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

        key = auth_key(name, sock)
        wait = auth_check_locked(key)
        if wait > 0:
            peer.send_error(f"Locked {wait}s")
            return

        stored = user_db.get(name)
        if stored is None:
            user_db[name] = hash_password(password)
            save_user_db()
        else:
            ok, legacy = verify_password(password, stored)
            if not ok:
                lock = auth_on_fail(key)
                peer.send_error("Auth failed" if lock == 0 else f"Locked {lock}s")
                return
            if legacy:
                user_db[name] = hash_password(password)
                save_user_db()

        auth_on_success(key)
        peer.send({"type": TYPE_AUTH_OK, "payload": {}})

        # ---- PUBKEY ----
        peer.send({"type": TYPE_PUBKEY_REQ, "payload": {}})
        m = peer.recv()
        pub_b64 = m.get("payload", {}).get("pubkey_b64")
        if not pub_b64:
            peer.send_error("Missing pubkey")
            return

        pubkey = base64.b64decode(pub_b64)

        with clients_lock:
            clients_data[sock] = {"name": name, "pubkey": pubkey}

        send_existing_users(sock)
        broadcast({
            "type": TYPE_USER_ANNOUNCE,
            "payload": {"name": name, "pubkey_b64": pub_b64}
        })

        # ---- MESSAGE LOOP ----
        while server_running:
            m = peer.recv()
            t = m.get("type")

            if t == TYPE_BROADCAST:
                broadcast({
                    "type": TYPE_BROADCAST,
                    "payload": {
                        "from": name,
                        "text": m["payload"].get("text", "")
                    }
                })

            elif t == TYPE_PRIVATE_MSG:
                target = m.get("to") or m["payload"].get("to")
                cs = find_socket_by_name(target)
                if cs:
                    ProtoPeer(cs).forward_private(
                        name,
                        m["payload"]["ciphertext_b64"],
                        m["payload"]["ctr"]
                    )
                else:
                    peer.send_error("User offline")

            elif t == TYPE_SESSION_OFFER:
                cs = find_socket_by_name(m.get("to"))
                if cs:
                    ProtoPeer(cs).forward_session_offer(name, **m["payload"])

            elif t == TYPE_SESSION_ACK:
                cs = find_socket_by_name(m.get("to"))
                if cs:
                    ProtoPeer(cs).forward_session_ack(name, **m["payload"])

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
                broadcast({"type": TYPE_USER_ANNOUNCE, "payload": {"name": name, "pubkey_b64": None}})
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
            if server_socket:
                server_socket.close()
            break


def start_server():
    # IMPORTANT: phải khai báo server_running là global vì ta có gán lại ở finally.
    # Nếu không, Python sẽ coi server_running là biến local và crash UnboundLocalError.
    global server_socket, server_running

    load_user_db()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(TLS_CERTFILE, TLS_KEYFILE)

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
                # server_socket có thể bị close từ thread command_input
                break

            sock = ctx.wrap_socket(raw, server_side=True)
            threading.Thread(
                target=handle_client,
                args=(sock,),
                daemon=True
            ).start()

    except KeyboardInterrupt:
        print("\n[SERVER] Ctrl+C received.")

    finally:
        server_running = False
        try:
            if server_socket:
                server_socket.close()
        except Exception:
            pass
        server_socket = None
        print("[SERVER] Server stopped.")

# ============================================================
# ENTRY
# ============================================================

if __name__ == "__main__":
    threading.Thread(target=command_input, daemon=True).start()
    start_server()
