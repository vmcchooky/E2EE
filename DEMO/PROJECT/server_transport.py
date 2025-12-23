# server_transport.py
from __future__ import annotations

from protocol import (
    send_msg,
    recv_msg,
    TYPE_ERROR,
    TYPE_BROADCAST,
    TYPE_PRIVATE_MSG,
    TYPE_DIRECT_MSG,
    TYPE_SESSION_OFFER,
    TYPE_SESSION_ACK,
    TYPE_USER_ANNOUNCE,
)


class ProtoPeer:
    """Server-side protocol adapter for one connected socket."""

    def __init__(self, sock):
        self.sock = sock

    def recv(self) -> dict:
        return recv_msg(self.sock)

    def send(self, msg: dict) -> None:
        send_msg(self.sock, msg)

    def send_error(self, reason: str) -> None:
        self.send({"type": TYPE_ERROR, "payload": {"message": reason, "reason": reason}})

    def send_user_announce(self, name: str, pubkey_b64: str | None) -> None:
        self.send({"type": TYPE_USER_ANNOUNCE, "payload": {"name": name, "pubkey_b64": pubkey_b64}})

    def send_broadcast_from(self, sender: str, text: str) -> None:
        self.send({"type": TYPE_BROADCAST, "payload": {"from": sender, "text": text}})

    def forward_private(self, sender: str, ciphertext_b64: str, ctr: int) -> None:
        self.send(
            {
                "type": TYPE_PRIVATE_MSG,
                "payload": {
                    "from": sender,
                    "ciphertext_b64": ciphertext_b64,
                    "ctr": int(ctr),
                },
            }
        )

    def forward_direct(self, sender: str, text: str) -> None:
        self.send(
            {
                "type": TYPE_DIRECT_MSG,
                "payload": {
                    "from": sender,
                    "text": text,
                },
            }
        )

    def forward_session_offer(self, sender: str, session_id: str, encrypted_key_b64: str, sig_b64: str) -> None:
        self.send(
            {
                "type": TYPE_SESSION_OFFER,
                "payload": {
                    "from": sender,
                    "session_id": session_id,
                    "encrypted_key_b64": encrypted_key_b64,
                    "sig_b64": sig_b64,
                },
            }
        )

    def forward_session_ack(self, sender: str, session_id: str, confirm_hex: str) -> None:
        self.send(
            {
                "type": TYPE_SESSION_ACK,
                "payload": {"from": sender, "session_id": session_id, "confirm_hex": confirm_hex},
            }
        )
