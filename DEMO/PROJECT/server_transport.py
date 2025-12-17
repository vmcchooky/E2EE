# server_transport.py
from __future__ import annotations

from protocol import (
    send_msg, recv_msg,
    TYPE_ERROR, TYPE_BROADCAST, TYPE_PRIVATE_MSG, TYPE_SESSION_OFFER, TYPE_USER_ANNOUNCE
)

class ProtoPeer:
    """Server-side protocol adapter for one connected socket."""
    def __init__(self, sock):
        self.sock = sock

    def recv(self) -> dict:
        return recv_msg(self.sock)

    def send(self, msg: dict) -> None:
        send_msg(self.sock, msg)

    def send_error(self, message: str) -> None:
        self.send({"type": TYPE_ERROR, "payload": {"message": message}})

    def send_user_announce(self, name: str, pubkey_b64: str | None) -> None:
        self.send({"type": TYPE_USER_ANNOUNCE, "payload": {"name": name, "pubkey_b64": pubkey_b64}})

    def send_broadcast_from(self, sender: str, text: str) -> None:
        self.send({"type": TYPE_BROADCAST, "payload": {"from": sender, "text": text}})

    def forward_private(self, sender: str, ciphertext_b64: str) -> None:
        self.send({"type": TYPE_PRIVATE_MSG, "payload": {"from": sender, "ciphertext_b64": ciphertext_b64}})

    def forward_session_offer(self, sender: str, encrypted_key_b64: str) -> None:
        self.send({"type": TYPE_SESSION_OFFER, "payload": {"from": sender, "encrypted_key_b64": encrypted_key_b64}})

# Example usage in server.py:
# peer = ProtoPeer(sock)
# msg = peer.recv()
# peer.send_broadcast_from(sender_name, text)
# peer.send_error("Some error message")
# peer.forward_private(sender_name, ciphertext_b64)
# peer.forward_session_offer(sender_name, encrypted_key_b64)
# peer.send_user_announce(name, pubkey_b64)
# Then replace direct socket operations with peer methods.

# In server.py, you would replace direct socket operations with ProtoPeer methods.

# Example replacement in server.py:
# peer = ProtoPeer(sock)    
# m = peer.recv()
# peer.send_broadcast_from(sender_name, text)
# peer.send_error(f"User '{target_name}' not online")
# peer.forward_private(sender_name, ciphertext_b64)
# peer.forward_session_offer(sender_name, encrypted_key_b64)
# peer.send_user_announce(name, pubkey_b64)
# This encapsulates the protocol logic and makes server.py cleaner.

# Note: The actual integration into server.py is not shown here, as per the instruction to only provide the completed code snippet.
