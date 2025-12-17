# protocol.py
from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass
from typing import Any, Dict, Optional

# 4-byte big-endian length prefix
_LEN_STRUCT = struct.Struct("!I")


class ProtoError(Exception):
    pass


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from TCP socket or raise ProtoError."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtoError("Socket closed while receiving data")
        buf.extend(chunk)
    return bytes(buf)


def send_msg(sock: socket.socket, msg: Dict[str, Any]) -> None:
    """Send one message as: [4-byte length][json bytes]."""
    raw = json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    header = _LEN_STRUCT.pack(len(raw))
    sock.sendall(header + raw)


def recv_msg(sock: socket.socket) -> Dict[str, Any]:
    """Receive one message as: [4-byte length][json bytes]."""
    header = _recv_exact(sock, _LEN_STRUCT.size)
    (length,) = _LEN_STRUCT.unpack(header)
    if length <= 0 or length > 10_000_000:
        raise ProtoError(f"Invalid message length: {length}")
    raw = _recv_exact(sock, length)
    try:
        msg = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ProtoError(f"Invalid JSON: {e}") from e
    if not isinstance(msg, dict) or "type" not in msg:
        raise ProtoError("Invalid message format (missing type)")
    return msg


# ---- Message type constants ----
TYPE_NAME_REQ = "NAME_REQ"
TYPE_NAME = "NAME"
TYPE_AUTH_REQ = "AUTH_REQ"
TYPE_AUTH = "AUTH"
TYPE_AUTH_OK = "AUTH_OK"
TYPE_ERROR = "ERROR"

TYPE_PUBKEY_REQ = "PUBKEY_REQ"
TYPE_PUBKEY = "PUBKEY"

TYPE_USER_ANNOUNCE = "USER_ANNOUNCE"      # server -> clients
TYPE_SESSION_OFFER = "SESSION_OFFER"      # client -> server -> target
TYPE_PRIVATE_MSG = "PRIVATE_MSG"          # client -> server -> target
TYPE_BROADCAST = "BROADCAST"              # client -> server -> all

# Optional: type for re-key acknowledgement if you want later
TYPE_ACK = "ACK"

def m_name(name: str) -> Dict[str, Any]:
    return {"type": TYPE_NAME, "payload": {"name": name}}

def m_auth(password: str) -> Dict[str, Any]:
    return {"type": TYPE_AUTH, "payload": {"password": password}}

def m_pubkey(pubkey_b64: str) -> Dict[str, Any]:
    return {"type": TYPE_PUBKEY, "payload": {"pubkey_b64": pubkey_b64}}

def m_broadcast(text: str) -> Dict[str, Any]:
    return {"type": TYPE_BROADCAST, "payload": {"text": text}}

def m_session_offer(to: str, encrypted_key_b64: str) -> Dict[str, Any]:
    return {"type": TYPE_SESSION_OFFER, "to": to, "payload": {"encrypted_key_b64": encrypted_key_b64}}

def m_private_msg(to: str, ciphertext_b64: str) -> Dict[str, Any]:
    return {"type": TYPE_PRIVATE_MSG, "to": to, "payload": {"ciphertext_b64": ciphertext_b64}}
# You can add more helper functions for other message types as needed
# End of protocol.py
