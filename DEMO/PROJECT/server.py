import base64
import socket
import threading
import sys

HOST = '127.0.0.1'
PORT = 12345

server_running = True
clients_data = {}  # socket -> {"name": str, "pubkey": bytes}

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def broadcast(message: bytes, _client_socket: socket.socket) -> None:
    for client_socket in list(clients_data.keys()):
        if client_socket != _client_socket:
            try:
                client_socket.send(message)
            except Exception:  # noqa: BLE001
                client_socket.close()
                clients_data.pop(client_socket, None)


def handle_client(client_socket: socket.socket) -> None:
    try:
        # 1. Nhận và kiểm tra tên
        client_socket.send("NAME".encode('utf-8'))
        name = client_socket.recv(1024).decode('utf-8').strip()

        # [FIX] Kiểm tra trùng tên
        if any(info['name'] == name for info in clients_data.values()):
            print(f"[REJECT] Tu choi ket noi: Ten '{name}' da ton tai.")
            client_socket.send("[ERROR] Ten da duoc su dung. Vui long chon ten khac.\n".encode('utf-8'))
            client_socket.close()
            return

        # [FIX] Cấm ký tự đặc biệt (để tránh lỗi split sau này)
        if ":" in name or " " in name:
             client_socket.send("[ERROR] Ten khong duoc chua khoang trang hoac dau hai cham (:).\n".encode('utf-8'))
             client_socket.close()
             return

        client_socket.send("PUBKEY_REQ".encode('utf-8'))
        pubkey_bytes = client_socket.recv(2048)

        print(f"Dang xu ly ket noi cho {name}...")

        # Gửi danh sách user cũ cho user mới
        for existing_socket, info in clients_data.items():
            existing_name = info["name"]
            existing_pubkey_b64 = base64.b64encode(info["pubkey"]).decode('utf-8')
            message = f"NEW_USER:{existing_name}:{existing_pubkey_b64}\n"
            client_socket.send(message.encode('utf-8'))

        clients_data[client_socket] = {
            "name": name,
            "pubkey": pubkey_bytes
        }

        print(f"{name} da ket noi va gui public key.")

        # Broadcast user mới
        new_user_pubkey_b64 = base64.b64encode(pubkey_bytes).decode('utf-8')
        broadcast_message = f"NEW_USER:{name}:{new_user_pubkey_b64}\n".encode('utf-8')
        broadcast(broadcast_message, client_socket)

        while True:
            message = client_socket.recv(4096) # Tăng buffer lên xíu đề phòng key dài
            if not message:
                raise ConnectionResetError

            decoded_msg = message.decode('utf-8').strip()
            sender_name = clients_data[client_socket]["name"]

            if decoded_msg.lower() in {"quit", "exit"}:
                raise ConnectionResetError # Nhảy xuống except để xử lý thoát

            # --- XỬ LÝ TIN NHẮN ---
            if decoded_msg.startswith("PRIVATE_MSG:"):
                parts = decoded_msg.split(":", 2)
                if len(parts) == 3:
                    _, target_name, content = parts
                    target_socket = next((s for s, info in clients_data.items() if info["name"] == target_name), None)
                    if target_socket:
                        fwd_msg = f"PRIVATE_MSG:{sender_name}:{content}\n".encode('utf-8')
                        target_socket.send(fwd_msg)
                    else:
                        # [FIX] Thông báo lỗi rõ ràng hơn
                        err_msg = f"[SYSTEM] Nguoi dung '{target_name}' khong online.\n"
                        client_socket.send(err_msg.encode('utf-8'))

            elif decoded_msg.startswith("SESSION_OFFER:"):
                # [FIX] Xử lý split an toàn hơn
                parts = decoded_msg.split(":", 3)
                if len(parts) == 4:
                    _, target_name, sender_name_in_offer, content_b64 = parts
                    target_socket = next((s for s, info in clients_data.items() if info["name"] == target_name), None)
                    if target_socket:
                        fwd = f"SESSION_OFFER:{sender_name_in_offer}:{content_b64}\n".encode('utf-8')
                        target_socket.send(fwd)
                    else:
                        client_socket.send(f"[SYSTEM] '{target_name}' khong con online.\n".encode('utf-8'))
                else:
                    print(f"[WARNING] Malformed SESSION_OFFER from {sender_name}")

            else:
                # Chat Broadcast
                broadcast_message = f"<{sender_name}> {decoded_msg}\n".encode('utf-8')
                broadcast(broadcast_message, client_socket)

    except Exception as e:
        # Xử lý ngắt kết nối chung
        if client_socket in clients_data:
            name = clients_data[client_socket]["name"]
            print(f"{name} da ngat ket noi ({e}).")
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
