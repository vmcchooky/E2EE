import base64
import socket
import threading
import sys
import os
import json
import hashlib

# import all methods in protocol.py
from protocol import TYPE_NAME_REQ, TYPE_NAME, TYPE_AUTH_REQ, TYPE_AUTH, TYPE_AUTH_OK, TYPE_ERROR, TYPE_PUBKEY_REQ, TYPE_PUBKEY, TYPE_USER_ANNOUNCE, TYPE_SESSION_OFFER, TYPE_PRIVATE_MSG, TYPE_BROADCAST
from server_transport import ProtoPeer

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

        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        stored_hash = user_db.get(name)
        if stored_hash is None:
            user_db[name] = password_hash
            save_user_db()
        elif stored_hash != password_hash:
            peer.send_error("Authentication failed")
            return

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
                encrypted_key_b64 = m.get("payload", {}).get("encrypted_key_b64")
                if not target_name or not encrypted_key_b64:
                    peer.send_error("SESSION_OFFER missing 'to' or 'encrypted_key_b64'")
                    continue

                target_socket = _find_socket_by_name(target_name)
                if target_socket:
                    ProtoPeer(target_socket).forward_session_offer(sender_name, encrypted_key_b64)
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
            broadcast({"type": TYPE_BROADCAST, "payload": {"from": "SERVER", "text": f"User '{name}' disconnected."}})

def start_server() -> None:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Server dang lang nghe tren {HOST}:{PORT}")
    print("Go 'quit' hoac 'exit' va nhan Enter de tat server.")

    while server_running:
        try:
            server_socket.settimeout(1.0)
            sock, address = server_socket.accept()
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
