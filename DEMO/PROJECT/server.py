import base64
import socket
import threading
import sys
import os
import json
import hashlib
import hmac
import secrets
import time
import ssl


# import all methods in protocol.py
from protocol import TYPE_NAME_REQ, TYPE_NAME, TYPE_AUTH_REQ, TYPE_AUTH, TYPE_AUTH_OK, TYPE_ERROR, TYPE_PUBKEY_REQ, TYPE_PUBKEY, TYPE_USER_ANNOUNCE, TYPE_SESSION_OFFER, TYPE_SESSION_ACK, TYPE_PRIVATE_MSG, TYPE_BROADCAST
from server_transport import ProtoPeer

# ---- Password hashing (PBKDF2-HMAC-SHA256) ----
_PBKDF2_ITERS = 200_000
_SALT_LEN = 16
_DK_LEN = 32

def _hash_password_pbkdf2(password: str, *, salt: bytes | None = None, iters: int = _PBKDF2_ITERS) -> dict:
    if salt is None:
        salt = secrets.token_bytes(_SALT_LEN)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=_DK_LEN)
    return {
        "kdf": "pbkdf2_sha256",
        "i": int(iters),
        "s": base64.b64encode(salt).decode("ascii"),
        "h": base64.b64encode(dk).decode("ascii"),
    }

def _verify_password(password: str, stored) -> tuple[bool, bool]:
    """
    Returns (ok, is_legacy_sha256)
    - legacy format: stored is a hex string sha256(password)
    - new format: stored is dict {kdf,i,s,h}
    """
    if stored is None:
        return False, False

    # Legacy: sha256 hex string
    if isinstance(stored, str):
        candidate = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(stored, candidate), True

    if not isinstance(stored, dict):
        return False, False

    if stored.get("kdf") != "pbkdf2_sha256":
        return False, False

    try:
        iters = int(stored["i"])
        salt = base64.b64decode(stored["s"])
        want = base64.b64decode(stored["h"])
    except Exception:
        return False, False

    got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=len(want))
    return hmac.compare_digest(want, got), False
# ---- Server State ----

AUTH_FILE = "Users/auth_users.json"
user_db = {}  # {name: password_hash}

HOST = '127.0.0.1'
PORT = 12345

server_running = True
clients_data = {}  # {socket: {"name": str, "pubkey": bytes}}
clients_lock = threading.Lock()


def _find_socket_by_name(target_name: str):
    with clients_lock:
        for s, info in clients_data.items():
            if info.get("name") == target_name:
                return s
    return None

def load_user_db():
    """Nạp database user từ file JSON (nếu có)."""
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
    """Lưu database user ra file JSON."""
    try:
        folder = os.path.dirname(AUTH_FILE)
        if folder:
            os.makedirs(folder, exist_ok=True)
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(user_db, f, indent=2)
    except Exception as e:
        print(f"[AUTH] Loi khi luu auth db: {e}")

        
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

load_user_db()

def broadcast(msg: dict) -> None:
    # Broadcast to all connected clients (including sender if applicable)
    dead = []
    with clients_lock:
        sockets = list(clients_data.keys())

    for cs in sockets:
        try:
            ProtoPeer(cs).send(msg)
        except Exception:
            dead.append(cs)

    if dead:
        with clients_lock:
            for cs in dead:
                try:
                    cs.close()
                except Exception:
                    pass
                clients_data.pop(cs, None)

def send_existing_users(to_sock: socket.socket) -> None:
    """Send snapshot of all currently-online users to the newly connected client."""
    peer = ProtoPeer(to_sock)
    with clients_lock:
        items = list(clients_data.items())

    for s, info in items:
        try:
            pub_b64 = base64.b64encode(info["pubkey"]).decode("utf-8")
            peer.send_user_announce(info["name"], pub_b64)
        except Exception:
            # ignore one-off failures; client may disconnect mid-snapshot
            pass

# Trong server.py

def handle_client(sock: socket.socket) -> None:
    peer = ProtoPeer(sock)
    name = None

    try:
        # ---- Handshake: NAME_REQ -> NAME -> AUTH_REQ -> AUTH -> AUTH_OK -> PUBKEY_REQ -> PUBKEY ----
        peer.send({"type": TYPE_NAME_REQ, "payload": {}})

        m = peer.recv()
        if m.get("type") != TYPE_NAME:
            peer.send_error("Expected NAME")
            return

        name = (m.get("payload", {}).get("name") or "").strip()
        if not name:
            peer.send_error("Name cannot be empty")
            return
        if ":" in name or " " in name:
            peer.send_error("Name contains invalid characters")
            return
        with clients_lock:
            if any(info["name"] == name for info in clients_data.values()):
                peer.send_error("Name already in use")
                return

        peer.send({"type": TYPE_AUTH_REQ, "payload": {}})

        m = peer.recv()
        if m.get("type") != TYPE_AUTH:
            peer.send_error("Expected AUTH")
            return

        password = (m.get("payload", {}).get("password") or "").strip()
        if not password:
            peer.send_error("Password cannot be empty")
            return

        stored = user_db.get(name)
        if stored is None:
            # First login: create account
            user_db[name] = _hash_password_pbkdf2(password)
            save_user_db()
        else:
            ok, is_legacy = _verify_password(password, stored)
            if not ok:
                peer.send_error("Authentication failed")
                return

            # Auto-migrate legacy SHA256 -> PBKDF2 once user logs in successfully
            if is_legacy:
                user_db[name] = _hash_password_pbkdf2(password)
                save_user_db()

        peer.send({"type": TYPE_AUTH_OK, "payload": {}})
        print(f"[AUTH] User '{name}' authenticated OK.")

        peer.send({"type": TYPE_PUBKEY_REQ, "payload": {}})

        m = peer.recv()
        if m.get("type") != TYPE_PUBKEY:
            peer.send_error("Expected PUBKEY")
            return

        pubkey_b64 = m.get("payload", {}).get("pubkey_b64")
        if not pubkey_b64:
            peer.send_error("PUBKEY missing pubkey_b64")
            return

        pubkey_bytes = base64.b64decode(pubkey_b64)

        # Save client record
        with clients_lock:
            clients_data[sock] = {"name": name, "pubkey": pubkey_bytes}

        # Send snapshot + announce
        send_existing_users(sock)
        broadcast({"type": TYPE_USER_ANNOUNCE, "payload": {"name": name, "pubkey_b64": pubkey_b64}})

        # ---- Message loop ----
        while True:
            m = peer.recv()
            t = m.get("type")

            # Always trust sender identity from socket-side state (not from payload)
            sender_name = name

            if t == TYPE_BROADCAST:
                text = m.get("payload", {}).get("text", "")
                broadcast({"type": TYPE_BROADCAST, "payload": {"from": sender_name, "text": text}})

            elif t == TYPE_PRIVATE_MSG:
                # Protocol: "to" is top-level in your client sender (preferred), but we tolerate both.
                target_name = m.get("to") or m.get("payload", {}).get("to")
                ciphertext_b64 = m.get("payload", {}).get("ciphertext_b64")
                if not target_name or not ciphertext_b64:
                    peer.send_error("PRIVATE_MSG missing 'to' or 'ciphertext_b64'")
                    continue

                target_socket = _find_socket_by_name(target_name)
                if target_socket:
                    ProtoPeer(target_socket).forward_private(sender_name, ciphertext_b64)
                else:
                    peer.send_error(f"User '{target_name}' not online")

            elif t == TYPE_SESSION_OFFER:
                target_name = m.get("to") or m.get("payload", {}).get("to")
                session_id = m.get("payload", {}).get("session_id")
                encrypted_key_b64 = m.get("payload", {}).get("encrypted_key_b64")
                if not target_name or not session_id or not encrypted_key_b64:
                    peer.send_error("SESSION_OFFER missing 'to', 'session_id' or 'encrypted_key_b64'")
                    continue

                target_socket = _find_socket_by_name(target_name)
                if target_socket:
                    ProtoPeer(target_socket).forward_session_offer(sender_name, session_id, encrypted_key_b64)
                else:
                    peer.send_error(f"User '{target_name}' not online")
            elif t == TYPE_SESSION_ACK:
                target_name = m.get("to") or m.get("payload", {}).get("to")
                session_id = m.get("payload", {}).get("session_id")
                confirm_hex = m.get("payload", {}).get("confirm_hex")

                if not target_name or not session_id or not confirm_hex:
                    peer.send_error("SESSION_ACK missing 'to', 'session_id' or 'confirm_hex'")
                    continue

                target_socket = _find_socket_by_name(target_name)
                if target_socket:
                    ProtoPeer(target_socket).forward_session_ack(sender_name, session_id, confirm_hex)
                else:
                    peer.send_error(f"User '{target_name}' not online")


            else:
                peer.send_error("Unsupported message type")

    except Exception as e:
        print(f"[SERVER] Client error name={name}: {e}")

    finally:
        try:
            sock.close()
        except Exception:
            pass

        removed = False
        with clients_lock:
            if sock in clients_data:
                clients_data.pop(sock, None)
                removed = True

        if removed and name:
            # Notify others to drop directory/session state for this user
            broadcast({"type": TYPE_USER_ANNOUNCE, "payload": {"name": name, "pubkey_b64": None}})
            broadcast({"type": TYPE_BROADCAST, "payload": {"from": "SERVER", "text": f"User '{name}' disconnected."}})

def start_server() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="../certs/server_cert.pem", keyfile="../certs/server_key.pem")
    
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Server dang lang nghe tren {HOST}:{PORT} (TLS)")
    print("Go 'quit' hoac 'exit' va nhan Enter de tat server.")

    while server_running:
        try:
            server_socket.settimeout(1.0)
            raw_sock, address = server_socket.accept()
            sock = context.wrap_socket(raw_sock, server_side=True)

            print(f"Ket noi moi tu {str(address)}")
            thread = threading.Thread(target=handle_client, args=(sock,))
            thread.daemon = True
            thread.start()
        except socket.timeout:
            continue
        except OSError:
            break


def command_input() -> None:
    global server_running
    while server_running:
        command = input()
        if command.lower() in ["quit", "exit"]:
            print("Dang tat server...")
            server_running = False
            server_socket.close()
            break


if __name__ == "__main__":
    input_thread = threading.Thread(target=command_input)
    input_thread.daemon = True
    input_thread.start()

    start_server()

    print("Server da tat.")
