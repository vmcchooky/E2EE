import base64
import socket
import threading
import sys
import os
import json
import hashlib

# ============================================================
# PROTOCOL GIỮA SERVER VÀ CLIENT (dạng text + '\n')
#
# 1) Handshake:
#    - Server -> Client: "NAME"
#    - Client -> Server: <tên người dùng, không chứa ':' hoặc space>
#    - Nếu OK:
#         Server -> Client: "PUBKEY_REQ"
#         Client -> Server: <public_key_PEM_bytes>
#      Sau đó server lưu:
#         clients_data[socket] = {"name": name, "pubkey": pubkey_bytes}
#
# 2) Thông báo user mới:
#    - Server -> Tất cả client:
#         "NEW_USER:<name>:<pubkey_base64>\n"
#
# 3) Trao đổi khóa E2EE (SESSION_OFFER):
#    - Client gửi lên server:
#         "SESSION_OFFER:<target_name>:<encrypted_key_base64>\n"
#      (Một số client cũ có thể gửi 4 phần:
#         SESSION_OFFER:<target>:<sender>:<encrypted_key_base64>
#       nên server phải xử lý linh hoạt.)
#
#    - Server chỉ tin "sender_name" lấy từ socket,
#      không tin dữ liệu tên do client gửi.
#      Server forward cho client đích:
#         "SESSION_OFFER:<sender_name_thực>:<encrypted_key_base64>\n"
#
# 4) Tin nhắn riêng (đã mã hóa AES):
#    - Client -> Server:
#         "PRIVATE_MSG:<target_name>:<ciphertext_base64>\n"
#    - Server -> Client đích:
#         "PRIVATE_MSG:<sender_name>:<ciphertext_base64>\n"
#
# 5) Chat broadcast (không mã hóa):
#    - Client -> Server:
#         "<text chat bình thường + '\\n'>"
#    - Server -> Tất cả client (kể cả sender):
#         "<sender_name>: <text>\n"
# ============================================================

AUTH_FILE = "Users/auth_users.json"
user_db = {}  # {name: password_hash}

HOST = '127.0.0.1'
PORT = 12345

server_running = True
clients_data = {}  # socket -> {"name": str, "pubkey": bytes}
        
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

def broadcast(message: bytes, _client_socket: socket.socket) -> None:
    """
    Gửi message tới TẤT CẢ client đang online (kể cả người gửi).
    _client_socket được giữ lại để sau này nếu muốn loại trừ thì vẫn có tham số.
    """
    for client_socket in list(clients_data.keys()):
        try:
            client_socket.send(message)
        except Exception:  # noqa: BLE001
            client_socket.close()
            clients_data.pop(client_socket, None)

# Trong server.py

def handle_client(client_socket: socket.socket) -> None:
    # 1. Tạo buffer riêng cho client này để xử lý lỗi dính gói tin TCP
    buffer = ""
    
    try:
        # --- Phần Handshake ban đầu (Giữ nguyên logic cũ nhưng thêm try/except) ---
        client_socket.send("NAME".encode('utf-8'))
        name = client_socket.recv(1024).decode('utf-8').strip()

        if any(info['name'] == name for info in clients_data.values()):
            client_socket.send("[ERROR] Ten da duoc su dung.\n".encode('utf-8'))
            client_socket.close()
            return

        if ":" in name or " " in name:
             client_socket.send("[ERROR] Ten khong chua ky tu dac biet.\n".encode('utf-8'))
             client_socket.close()
             return
        
        # --- BƯỚC 2: XÁC THỰC USERNAME + PASSWORD ĐƠN GIẢN ---
        client_socket.send("AUTH_REQ".encode("utf-8"))
        password = client_socket.recv(1024).decode("utf-8").strip()

        if not password:
            client_socket.send("[ERROR] Mat khau khong duoc rong.\n".encode("utf-8"))
            client_socket.close()
            return

        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()

        global user_db
        stored_hash = user_db.get(name)

        if stored_hash is None:
            # Chưa có user này -> ĐĂNG KÝ mới
            user_db[name] = password_hash
            save_user_db()
            print(f"[AUTH] Dang ky user moi: {name}")
            client_socket.send("AUTH_OK".encode("utf-8"))
        elif stored_hash == password_hash:
            # Đăng nhập
            print(f"[AUTH] {name} dang nhap thanh cong.")
            client_socket.send("AUTH_OK".encode("utf-8"))
        else:
            # Sai mật khẩu
            print(f"[AUTH] {name} nhap sai mat khau.")
            client_socket.send("[ERROR] Sai mat khau.\n".encode("utf-8"))
            client_socket.close()
            return
        # Yêu cầu public key từ client
        client_socket.send("PUBKEY_REQ".encode('utf-8'))
        pubkey_bytes = client_socket.recv(2048)

        # Gửi danh sách user cũ
        for existing_socket, info in clients_data.items():
            existing_name = info["name"]
            existing_pubkey_b64 = base64.b64encode(info["pubkey"]).decode('utf-8')
            message = f"NEW_USER:{existing_name}:{existing_pubkey_b64}\n"
            client_socket.send(message.encode('utf-8'))

        clients_data[client_socket] = {
            "name": name,
            "pubkey": pubkey_bytes
        }

        # Broadcast user mới
        new_user_pubkey_b64 = base64.b64encode(pubkey_bytes).decode('utf-8')
        broadcast(f"NEW_USER:{name}:{new_user_pubkey_b64}\n".encode('utf-8'), client_socket)
        print(f"{name} da ket noi.")

        # --- VÒNG LẶP NHẬN TIN NHẮN (Đã sửa lỗi Buffer) ---
        while True:
            data = client_socket.recv(4096).decode('utf-8')
            if not data:
                raise ConnectionResetError
            
            buffer += data
            
            # Xử lý cắt tin nhắn dựa trên ký tự xuống dòng '\n'
            while "\n" in buffer:
                message, buffer = buffer.split("\n", 1)
                decoded_msg = message.strip()
                if not decoded_msg: continue

                sender_name = clients_data[client_socket]["name"]

                if decoded_msg.lower() in {"quit", "exit"}:
                    raise ConnectionResetError

                # --- XỬ LÝ LOGIC ---
                
                # 1. Chat riêng (PRIVATE_MSG)
                if decoded_msg.startswith("PRIVATE_MSG:"):
                    parts = decoded_msg.split(":", 2)
                    if len(parts) == 3:
                        _, target_name, content = parts
                        target_socket = next((s for s, info in clients_data.items() if info["name"] == target_name), None)
                        if target_socket:
                            # Server tự điền tên người gửi thật (sender_name) để chống giả mạo
                            fwd_msg = f"PRIVATE_MSG:{sender_name}:{content}\n".encode('utf-8')
                            target_socket.send(fwd_msg)
                        else:
                            client_socket.send(f"[SYSTEM] User '{target_name}' khong online.\n".encode('utf-8'))

                                # 2. Trao đổi khóa (SESSION_OFFER) - Đã sửa lỗi bảo mật
                #
                # Format mong đợi từ client:
                #   SESSION_OFFER:<target_name>:<encrypted_key_b64>
                #
                # Một số client có thể gửi thêm tên sender:
                #   SESSION_OFFER:<target_name>:<sender_name>:<encrypted_key_b64>
                #
                # => Server xử lý LINH HOẠT:
                #    - Chỉ quan tâm:
                #         + target_name  = parts[1]
                #         + content_b64  = phần cuối cùng (parts[-1])
                #    - Tên người gửi (sender_name) luôn lấy từ
                #      clients_data[client_socket]["name"], KHÔNG tin
                #      tên do client gửi lên, tránh giả mạo.
                #
                # Server sẽ forward cho client đích dạng:
                #   SESSION_OFFER:<sender_name_thực>:<encrypted_key_b64>\n
        
                # 2. Trao đổi khóa (SESSION_OFFER) - Đã sửa lỗi bảo mật
                elif decoded_msg.startswith("SESSION_OFFER:"):
                    # Format mong đợi từ client: SESSION_OFFER:target_name:encrypted_key_b64
                    parts = decoded_msg.split(":")
                    
                    # Logic linh hoạt: Dù client gửi 3 hay 4 phần, ta chỉ lấy Target và Content
                    if len(parts) >= 3:
                        target_name = parts[1]
                        # Nội dung key luôn nằm ở phần cuối cùng
                        content_b64 = parts[-1] 
                        
                        target_socket = next((s for s, info in clients_data.items() if info["name"] == target_name), None)
                        
                        if target_socket:
                            # QUAN TRỌNG: Server ép buộc tên người gửi là sender_name (lấy từ socket)
                            # Không tin tên do client gửi lên.
                            fwd = f"SESSION_OFFER:{sender_name}:{content_b64}\n".encode('utf-8')
                            target_socket.send(fwd)
                        else:
                             client_socket.send(f"[SYSTEM] '{target_name}' khong con online.\n".encode('utf-8'))

                # 3. Chat Broadcast
                else:
                    broadcast_message = f"<{sender_name}> {decoded_msg}\n".encode('utf-8')
                    broadcast(broadcast_message, client_socket)

    except Exception as e:
        if client_socket in clients_data:
            name = clients_data[client_socket]["name"]
            print(f"{name} ngat ket noi: {e}")
            del clients_data[client_socket]
            broadcast(f"[SYSTEM] {name} da roi phong chat.\n".encode('utf-8'), None)
        client_socket.close()


def start_server() -> None:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Server dang lang nghe tren {HOST}:{PORT}")
    print("Go 'quit' hoac 'exit' va nhan Enter de tat server.")

    while server_running:
        try:
            server_socket.settimeout(1.0)
            client_socket, address = server_socket.accept()
            print(f"Ket noi moi tu {str(address)}")

            thread = threading.Thread(target=handle_client, args=(client_socket,))
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
