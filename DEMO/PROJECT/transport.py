
# transport.py

import time

from protocol import (
    send_msg, recv_msg,
    m_name, m_auth, m_pubkey, m_broadcast, m_private_msg, m_direct_msg, m_session_offer, m_session_ack
)

class ProtoClient:
    def __init__(self, sock):
        self.sock = sock

    def recv(self) -> dict:
        m = recv_msg(self.sock)
        p = m.get("payload", {})
        if p is None:
            m["payload"] = {}
        elif not isinstance(p, dict):
            raise ValueError("Invalid payload (must be object)")
        return m

    def send_name(self, name: str) -> None:
        send_msg(self.sock, m_name(name))

    def send_auth(self, password: str) -> None:
        send_msg(self.sock, m_auth(password))

    def send_pubkey(self, pubkey_b64: str) -> None:
        send_msg(self.sock, m_pubkey(pubkey_b64))

    def send_broadcast(self, text: str) -> None:
        send_msg(self.sock, m_broadcast(text))

    def send_private_msg(self, to: str, ciphertext_b64: str, ctr: int, msg_id: str, ts: int) -> None:
        send_msg(self.sock, m_private_msg(to, ciphertext_b64, ctr, msg_id, ts))

    def send_direct_msg(self, to: str, text: str) -> None:
        send_msg(self.sock, m_direct_msg(to, text))

    def send_session_offer(self, to: str, session_id: str, encrypted_key_b64: str, sig_b64: str, ts: int | None = None) -> None:
            if ts is None:
                ts = int(time.time())
            send_msg(self.sock, m_session_offer(to, session_id, encrypted_key_b64, sig_b64, ts))

    def send_session_ack(self, to: str, session_id: str, confirm_hex: str) -> None:
        send_msg(self.sock, m_session_ack(to, session_id, confirm_hex))
# End of transport.py