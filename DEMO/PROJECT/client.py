import os
import socket
import threading
import sys
import base64
import getpass

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
)

import json

KNOWN_KEYS_FILE = "FingerPrint/known_keys.json"
known_keys = {}   # {"Alice": "abcd1234..."}


my_name = ""
my_private_key = None  # store private key object
user_directory = {}   # {"Alice": <public_key_obj>}
session_keys = {}     # {"Alice": <aes_key_bytes>}

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

def receive_messages(client_socket: socket.socket) -> None:
    """Listen for incoming messages from server on a background thread."""
    buffer = ""
    while True:
        try:
            data = client_socket.recv(2048).decode("utf-8")
            if not data:
                print("Mat ket noi voi server.")
                break

            buffer += data

            while "\n" in buffer:
                message, buffer = buffer.split("\n", 1)
                if not message:
                    continue

                if message.startswith("NEW_USER:"):
                    _, name, pubkey_b64 = message.split(":", 2)
                    if name != my_name:
                        pubkey_bytes = base64.b64decode(pubkey_b64)

                        # Tính fingerprint
                        fp = public_key_fingerprint(pubkey_bytes)

                        # TOFU: nếu chưa biết user này -> lưu fingerprint lần đầu
                        if name not in known_keys:
                            known_keys[name] = fp
                            save_known_keys()
                            print(f"[HE THONG] {name} vua tham gia. Fingerprint key: {fp}")
                            print("  >> Hay so sanh fingerprint nay qua kenh ngoai de dam bao an toan.")
                        else:
                            # Đã có fingerprint -> kiểm tra xem có đổi không
                            if known_keys[name] != fp:
                                print(f"[CANH BAO] Public key cua {name} DA THAY DOI!")
                                print(f"  - Fingerprint cu : {known_keys[name]}")
                                print(f"  - Fingerprint moi: {fp}")
                                print("  >> Co the dang bi tan cong MITM hoac user cai lai key.")
                                # Tùy chọn: KHÔNG cập nhật key mới để tránh bị MITM
                                # continue  # bỏ qua, không lưu public key mới
                                # Ở đây mình sẽ không update user_directory nếu key đổi:
                                continue

                        # Nếu fingerprint ổn -> lưu public key
                        user_directory[name] = load_public_key_from_bytes(pubkey_bytes)
                        print(f"[HE THONG] {name} vua tham gia. San sang ket noi E2EE.")

                # SERVER gửi về:
                #   SESSION_OFFER:<sender_name_thực>:<encrypted_key_b64>
                # => Ở phía client chỉ cần:
                #   - Lấy sender_name để lưu session_keys[sender_name]
                #   - Giải mã encrypted_key_b64 bằng private_key của chính mình.

                elif message.startswith("SESSION_OFFER:"):
                    _, sender_name, encrypted_key_b64 = message.split(":", 2)
                    encrypted_key_bytes = base64.b64decode(encrypted_key_b64)
                    aes_key = rsa_decrypt(encrypted_key_bytes, my_private_key)
                    session_keys[sender_name] = aes_key
                    print(f"[HE THONG] Da thiet lap phien E2EE voi {sender_name}.")

                elif message.startswith("<"):
                    print(message)

                elif message.startswith("PRIVATE_MSG:"):
                    try:
                        _, sender_name, encrypted_content_b64 = message.split(":", 2)
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
                    except Exception as e:  # noqa: BLE001
                        print(f"Loi xu ly tin nhan rieng: {e}")

                else:
                    print(message)
        except Exception as e:  # noqa: BLE001
            print(f"Loi khi nhan tin nhan: {e}")
            client_socket.close()
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
    
    load_known_keys()

    try:
        message = client_socket.recv(1024).decode('utf-8')
        name = ""
        if message == "NAME":
            name = input("Nhap ten cua ban: ")
            client_socket.send(name.encode('utf-8'))
            global my_name
            my_name = name
        else:
            print("Server khong yeu cau ten.")
            client_socket.close()
            return
        
        # --- Hỏi password bảo vệ private key ---
        private_key_file = f"private_key_{name}.pem"

        if os.path.exists(private_key_file):
            # Đã có khóa -> yêu cầu nhập password để mở
            pwd = getpass.getpass("Nhap mat khau de mo private key: ")
        else:
            # Chưa có -> tạo mật khẩu mới
            while True:
                pwd1 = getpass.getpass("Tao mat khau moi de bao ve private key: ")
                pwd2 = getpass.getpass("Nhap lai mat khau: ")
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

        msg = client_socket.recv(1024).decode('utf-8')

        # Nếu server trả về lỗi
        if msg.startswith("[ERROR]"):
            print(msg.strip())
            client_socket.close()
            return

        # Nếu server yêu cầu public key
        if msg == "PUBKEY_REQ":
            client_socket.sendall(public_key_bytes)
            print("[SYSTEM] Đã kết nối thành công!")
        else:
            print(f"[ERROR] Handshake thất bại: {msg}")
            client_socket.close()
            return

    except Exception as e:  # noqa: BLE001
        print(f"Loi trong qua trinh thiet lap ket noi: {e}")
        client_socket.close()
        return

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
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

                encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
                offer_message = f"SESSION_OFFER:{target_name}:{my_name}:{encrypted_key_b64}\n"
                client_socket.sendall(offer_message.encode('utf-8'))
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

                    session_key = session_keys[target_name]
                    encrypted_bytes = aes_encrypt(plain_content.encode('utf-8'), session_key)
                    if encrypted_bytes is None:
                        print("[LOI] Ma hoa that bai, khong gui tin nhan.")
                        continue
                    encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')

                    final_msg = f"PRIVATE_MSG:{target_name}:{encrypted_b64}\n"
                    client_socket.send(final_msg.encode('utf-8'))

                    print(f"[DA GUI] toi {target_name}: {plain_content}")

                except Exception as e:  # noqa: BLE001
                    print(f"Loi khi gui tin nhan: {e}")
            else:
                client_socket.send((message + "\n").encode('utf-8'))

    except KeyboardInterrupt:
        print("\nDang thoat...")
    finally:
        client_socket.close()
        print("Da ngat ket noi khoi server.")
        sys.exit(0)

if __name__ == "__main__":
    start_client()
