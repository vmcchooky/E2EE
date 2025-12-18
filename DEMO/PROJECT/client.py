import os
import socket
import threading
import sys
import base64
from getpass import getpass
import time
import json
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

from crypto_utils import (
    aes_decrypt,
    aes_encrypt,
    generate_aes_key,
    load_public_key_from_bytes,
    rsa_decrypt,
    rsa_encrypt,
    generate_or_load_keys,
    public_key_fingerprint,
    session_confirm_token,
)

from protocol import (
    TYPE_NAME_REQ, TYPE_AUTH_REQ, TYPE_AUTH_OK, TYPE_ERROR, TYPE_PUBKEY_REQ,
    TYPE_USER_ANNOUNCE, TYPE_SESSION_OFFER, TYPE_SESSION_ACK, TYPE_PRIVATE_MSG, TYPE_BROADCAST
)
from transport import ProtoClient


KNOWN_KEYS_FILE = "FingerPrint/known_keys.json"
known_keys = {}   # {"Alice": "abcd1234..."}

my_name = ""
my_private_key = None  # store private key object
user_directory = {}   # {"Alice": <public_key_obj>}
session_keys = {}     # {"Alice": <aes_key_bytes>}
session_confirmed = {}  # {"Alice": bool}  (initiator-side: confirmed via SESSION_ACK)
pending_session_acks = {}  # {(peer_name, session_id): aes_key_bytes}
last_rekey_time = {}  # {"Alice": timestamp}
REKEY_SUGGEST_INTERVAL = 300   # 5 phút -> gợi ý re-key

def load_known_keys():
    """Nạp danh sách fingerprint đã lưu (TOFU)."""
    global known_keys
    if os.path.exists(KNOWN_KEYS_FILE):
        try:
            with open(KNOWN_KEYS_FILE, "r", encoding="utf-8") as f:
                known_keys = json.load(f)
        except Exception:
            known_keys = {}
    else:
        known_keys = {}

def save_known_keys():
    """Lưu danh sách fingerprint ra file."""
    try:
        os.makedirs(os.path.dirname(KNOWN_KEYS_FILE), exist_ok=True)
        with open(KNOWN_KEYS_FILE, "w", encoding="utf-8") as f:
            json.dump(known_keys, f, indent=2)
    except Exception as e:
        print(f"Loi khi luu known_keys: {e}")

def receive_messages(proto: ProtoClient) -> None:
    while True:
        try:
            m = proto.recv()
            t = m["type"]

            if t == TYPE_USER_ANNOUNCE:
                name = m["payload"]["name"]
                pubkey_b64 = m["payload"]["pubkey_b64"]

                # user offline
                if pubkey_b64 is None:
                    print(f"[INFO] {name} vua offline.")
                    user_directory.pop(name, None)
                    session_keys.pop(name, None)
                    session_confirmed.pop(name, None)
                    last_rekey_time.pop(name, None)
                    # Drop any pending ACKs involving this peer
                    for k in list(pending_session_acks.keys()):
                        if k[0] == name:
                            pending_session_acks.pop(k, None)
                    continue

                if name == my_name:
                    continue

                pubkey_bytes = base64.b64decode(pubkey_b64)
                fp = public_key_fingerprint(pubkey_bytes)

                if name not in known_keys:
                    known_keys[name] = fp
                    save_known_keys()
                    print(f"[HE THONG] {name} vua tham gia. Fingerprint key: {fp}")
                    print("  >> Hay so sanh fingerprint nay qua kenh ngoai de dam bao an toan.")
                else:
                    if known_keys[name] != fp:
                        print(f"[CANH BAO] Public key cua {name} DA THAY DOI!")
                        print(f"  - Fingerprint cu : {known_keys[name]}")
                        print(f"  - Fingerprint moi: {fp}")
                        print("  >> Co the dang bi tan cong MITM hoac user cai lai key.")
                        continue

                user_directory[name] = load_public_key_from_bytes(pubkey_bytes)
                print(f"[HE THONG] {name} vua tham gia. San sang ket noi E2EE.")

            elif t == TYPE_SESSION_OFFER:
                sender_name = m["payload"]["from"]
                session_id = m["payload"].get("session_id")
                encrypted_key_b64 = m["payload"]["encrypted_key_b64"]

                if not session_id:
                    print(f"[LOI] SESSION_OFFER tu {sender_name} thieu session_id, bo qua.")
                    continue

                encrypted_key_bytes = base64.b64decode(encrypted_key_b64)
                aes_key = rsa_decrypt(encrypted_key_bytes, my_private_key)

                session_keys[sender_name] = aes_key
                session_confirmed[sender_name] = True
                last_rekey_time[sender_name] = time.time()

                # Send ACK to confirm receiver decrypted the same key
                confirm_hex = session_confirm_token(aes_key, session_id)
                proto.send_session_ack(sender_name, session_id, confirm_hex)

                print(f"[HE THONG] Da thiet lap / cap nhat phien E2EE voi {sender_name} (session_id={session_id}).")
                print(f"[HE THONG] Da gui ACK xac nhan khoa cho {sender_name}.")

            elif t == TYPE_SESSION_ACK:
                sender_name = m["payload"].get("from")
                session_id = m["payload"].get("session_id")
                confirm_hex = m["payload"].get("confirm_hex")

                if not sender_name or not session_id or not confirm_hex:
                    print(f"[LOI] SESSION_ACK khong hop le: {m}")
                    continue

                key = pending_session_acks.pop((sender_name, session_id), None)
                if key is None:
                    print(
                        f"[INFO] Nhan SESSION_ACK tu {sender_name} nhung khong tim thay pending session_id={session_id}."
                    )
                    continue

                expected = session_confirm_token(key, session_id)
                if expected != confirm_hex:
                    print(
                        f"[CANH BAO] SESSION_ACK tu {sender_name} KHONG KHOP (session_id={session_id})."
                    )
                    continue

                session_confirmed[sender_name] = True
                last_rekey_time[sender_name] = time.time()
                print(
                    f"[HE THONG] {sender_name} da ACK thanh cong. Kenh E2EE da duoc xac nhan (session_id={session_id})."
                )

            elif t == TYPE_PRIVATE_MSG:
                sender_name = m["payload"]["from"]
                encrypted_content_b64 = m["payload"]["ciphertext_b64"]
                if sender_name in session_keys:
                    session_key = session_keys[sender_name]
                    encrypted_bytes = base64.b64decode(encrypted_content_b64)
                    decrypted_text = aes_decrypt(encrypted_bytes, session_key)
                    if decrypted_text:
                        print(f"[E2EE] <{sender_name}>: {decrypted_text.decode('utf-8')}")
                    else:
                        print(f"[LOI] Khong the giai ma tin nhan tu {sender_name}.")
                else:
                    print(f"[INFO] Nhan tin nhan ma hoa tu {sender_name} nhung chua co khoa. Hay go /connect {sender_name}")

            elif t == TYPE_BROADCAST:
                print(f"<{m['payload']['from']}> {m['payload']['text']}")

            elif t == TYPE_ERROR:
                print(f"[ERROR] {m['payload']['message']}")

            else:
                print(f"[UNKNOWN] {m}")

        except Exception as e:
            print(f"Loi khi nhan tin nhan: {e}")
            break


def start_client() -> None:
    HOST = '127.0.0.1'
    PORT = 12345

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("Khong the ket noi den server. Server co dang chay khong?")
        return
    proto = ProtoClient(client_socket)
    
    load_known_keys()

    try:
        m = proto.recv()
        if m["type"] != TYPE_NAME_REQ:
            print(f"[ERROR] Expected NAME_REQ, got {m}")
            client_socket.close()
            return

        name = input("Nhap ten cua ban: ").strip()
        if not name:
            print("[ERROR] Name cannot be empty")
            client_socket.close()
            return

        proto.send_name(name)
        global my_name
        my_name = name

        # AUTH
        m = proto.recv()
        if m["type"] == TYPE_ERROR:
            print(f"[ERROR] {m['payload']['message']}")
            client_socket.close()
            return
        if m["type"] != TYPE_AUTH_REQ:
            print(f"[ERROR] Expected AUTH_REQ, got {m}")
            client_socket.close()
            return

        server_pwd = getpass("Nhap mat khau dang nhap server (lan dau se dung de dang ky): ")
        proto.send_auth(server_pwd)

        m = proto.recv()
        if m["type"] == TYPE_ERROR:
            print(f"[AUTH] That bai: {m['payload']['message']}")
            client_socket.close()
            return
        if m["type"] != TYPE_AUTH_OK:
            print(f"[AUTH] Khong hop le: {m}")
            client_socket.close()
            return
        print("[AUTH] Xac thuc voi server thanh cong.")

        # Hỏi password bảo vệ private key (RSA) - giữ nguyên logic bạn đang có
        private_key_file = f"Keys/Private/private_key_{name}.pem"

        if os.path.exists(private_key_file):
            # Đã có khóa -> yêu cầu nhập password để mở
            pwd = getpass("Nhap mat khau de mo private key: ")
        else:
            # Chưa có -> tạo mật khẩu mới
            while True:
                pwd1 = getpass("Tao mat khau moi de bao ve private key: ")
                pwd2 = getpass("Nhap lai mat khau: ")
                if pwd1 != pwd2:
                    print("Mat khau khong khop, vui long thu lai.")
                    continue
                if not pwd1:
                    print("Mat khau khong duoc rong.")
                    continue
                pwd = pwd1
                break

        private_key, public_key_bytes = generate_or_load_keys(name, pwd)
        global my_private_key
        my_private_key = private_key
        if not private_key:
            print("Khong the xu ly khoa (co the sai mat khau). Dang thoat...")
            client_socket.close()
            return

        # PUBKEY
        m = proto.recv()
        if m["type"] == TYPE_ERROR:
            print(f"[ERROR] {m['payload']['message']}")
            client_socket.close()
            return
        if m["type"] != TYPE_PUBKEY_REQ:
            print(f"[ERROR] Expected PUBKEY_REQ, got {m}")
            client_socket.close()
            return

        pubkey_b64 = base64.b64encode(public_key_bytes).decode("utf-8")
        proto.send_pubkey(pubkey_b64)
        print("[SYSTEM] Da ket noi thanh cong!")

    except Exception as e:  # noqa: BLE001
        print(f"Loi trong qua trinh thiet lap ket noi: {e}")
        client_socket.close()
        return

    receive_thread = threading.Thread(target=receive_messages, args=(proto,))
    receive_thread.daemon = True
    receive_thread.start()

    print("Da ket noi. Go tin nhan va nhan Enter de gui.")
    print("Go '/quit' de thoat.")

    try:
        while True:
            message = input()

            if message.lower() == '/quit':
                break

            elif message.startswith("/connect "):
                target_name = message.split(" ", 1)[1]

                if target_name == my_name:
                    print("[LOI] Ban khong the ket noi voi chinh minh.")
                    continue
                if target_name not in user_directory:
                    print(f"[LOI] Khong tim thay nguoi dung: {target_name}.")
                    continue
                if target_name in session_keys:
                    print(f"[INFO] Ban da co phien E2EE voi {target_name}.")
                    continue

                target_pubkey_obj = user_directory[target_name]
                aes_key = generate_aes_key()
                encrypted_aes_key = rsa_encrypt(aes_key, target_pubkey_obj)
                session_keys[target_name] = aes_key
                last_rekey_time[target_name] = time.time()

                encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
                session_id = uuid.uuid4().hex
                pending_session_acks[(target_name, session_id)] = aes_key
                session_confirmed[target_name] = False
                proto.send_session_offer(target_name, session_id, encrypted_key_b64)
                print(f"[HE THONG] Da gui loi moi E2EE den {target_name}.")

            elif message.startswith("/chat "):
                try:
                    parts = message.split(" ", 2)
                    if len(parts) < 3:
                        print("Cu phap: /chat <ten nguoi nhan> <noi dung>")
                        continue

                    target_name = parts[1]
                    plain_content = parts[2]

                    if target_name not in session_keys:
                        print(f"[LOI] Chua co ket noi bao mat voi {target_name}. Hay dung /connect {target_name} truoc.")
                        continue
                    last_t = last_rekey_time.get(target_name, 0)
                    if last_t and (time.time() - last_t > REKEY_SUGGEST_INTERVAL):
                        print(f"[INFO] Phien E2EE voi {target_name} da dung lau, "
                              f"ban nen re-key (GUI co nut Re-key, hoac tu mo rong CLI).")

                    if not session_confirmed.get(target_name, False):
                        print(f"[INFO] Phien voi {target_name} chua duoc ACK xac nhan. Tin nhan van co the gui, nhung nen doi ACK de dam bao doi phuong da nhan khoa.")

                    session_key = session_keys[target_name]
                    encrypted_bytes = aes_encrypt(plain_content.encode('utf-8'), session_key)
                    if encrypted_bytes is None:
                        print("[LOI] Ma hoa that bai, khong gui tin nhan.")
                        continue
                    encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')

                    proto.send_private_msg(target_name, encrypted_b64)

                    print(f"[DA GUI] toi {target_name}: {plain_content}")

                except Exception as e:  # noqa: BLE001
                    print(f"Loi khi gui tin nhan: {e}")
            else:
                proto.send_broadcast(message)

    except KeyboardInterrupt:
        print("\nDang thoat...")
    finally:
        client_socket.close()
        print("Da ngat ket noi khoi server.")
        sys.exit(0)

if __name__ == "__main__":
    start_client()
