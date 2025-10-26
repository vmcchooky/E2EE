

import os  # Để kiểm tra file tồn tại
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# client.py
import socket
import threading
import sys

# --- Hàm để nhận tin nhắn từ Server ---
# Hàm này sẽ chạy trên một luồng (thread) riêng
def receive_messages(client_socket):
    while True:
        try:
            # Nhận tin nhắn từ server
            message = client_socket.recv(1024).decode('utf-8')
            
            # Nếu không nhận được gì (server sập), thoát vòng lặp
            if not message:
                print("Mất kết nối với server.")
                break
                
            # In tin nhắn nhận được ra màn hình
            print(message)
        except Exception as e:
            # Xảy ra lỗi (ví dụ: client tự ngắt kết nối)
            print(f"Đã xảy ra lỗi: {e}")
            client_socket.close()
            break


def generate_or_load_keys(name):
    """Tạo cặp khóa RSA mới nếu chưa tồn tại, hoặc nạp khóa từ file nếu đã có."""
    private_key_file = f"private_key_{name}.pem"
    public_key_file = f"public_key_{name}.pem"

    private_key = None
    public_key = None

    try:
        # Nếu file đã tồn tại -> Nạp khóa
        if os.path.exists(private_key_file):
            print("Đang nạp khóa cá nhân...")
            with open(private_key_file, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None  # Dự án này không đặt mật khẩu cho file key
                )

            with open(public_key_file, "rb") as f:
                public_key_bytes = f.read() # Nạp public key dạng bytes để gửi đi
                public_key = serialization.load_pem_public_key(public_key_bytes)

            print("Nạp khóa thành công.")

        # Nếu file không tồn tại -> Tạo khóa mới
        else:
            print("Đang tạo cặp khóa RSA mới (việc này có thể mất vài giây)...")
            # 1. Tạo private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,  # Kích thước khóa 2048-bit là an toàn
            )

            # 2. Lấy public key từ private key
            public_key = private_key.public_key()

            # 3. Lưu private key xuống file
            with open(private_key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # 4. Lưu public key xuống file
            public_key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            with open(public_key_file, "wb") as f:
                f.write(public_key_bytes)

            print(f"Đã tạo và lưu khóa vào {private_key_file} và {public_key_file}.")

        return private_key, public_key_bytes # Trả về private key (object) và public key (bytes)

    except Exception as e:
        print(f"Lỗi khi xử lý khóa: {e}")
        return None, None

# --- Hàm chính để bắt đầu Client ---
def start_client():
    # --- Cấu hình Client ---
    # Phải khớp với cấu hình của server.py
    HOST = '127.0.0.1' 
    PORT = 12345       

    # 1. Tạo socket và kết nối đến Server
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("Không thể kết nối đến server. Server có đang chạy không?")
        return

    # 2. Xử lý yêu cầu nhập tên từ Server
    try:
        message = client_socket.recv(1024).decode('utf-8')
        name = ""
        if message == "NAME":
            name = input("Nhập tên của bạn: ")
            client_socket.send(name.encode('utf-8'))
        else:
            print("Server không yêu cầu tên.")
            return # Thoát nếu server không hỏi tên

        # 3. TẠO HOẶC NẠP KHÓA (Logic mới)
        private_key, public_key_bytes = generate_or_load_keys(name)
        if not private_key:
            print("Không thể xử lý khóa. Đang thoát...")
            client_socket.close()
            return

        # 4. Chờ Server yêu cầu và GỬI PUBLIC KEY (Logic mới)
        message = client_socket.recv(1024).decode('utf-8')
        if message == "PUBKEY_REQ":
            print("Server yêu cầu public key. Đang gửi...")
            client_socket.sendall(public_key_bytes) # Dùng sendall để đảm bảo gửi hết
        else:
            print("Server không yêu cầu public key.")
            return

    except Exception as e:
        print(f"Lỗi trong quá trình thiết lập kết nối: {e}")
        client_socket.close()
        return

    # 5. Tạo và khởi động luồng nhận tin nhắn
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.daemon = True  # Đặt là daemon để thread tự tắt khi chương trình chính tắt
    receive_thread.start()

    # 6. Vòng lặp gửi tin nhắn (chạy trên luồng chính)
    print("Đã kết nối. Gõ tin nhắn của bạn và nhấn Enter để gửi.")
    print("Gõ '/quit' để thoát.")

    try:
        while True:
            # Chờ người dùng nhập tin nhắn
            message = input()
            
            if message.lower() == '/quit':
                break
                
            # Gửi tin nhắn đến server
            if message: # Chỉ gửi nếu tin nhắn không rỗng
                client_socket.send(message.encode('utf-8'))
                
    except KeyboardInterrupt:
        print("\nĐang thoát...")
    finally:
        # Dọn dẹp và đóng kết nối
        client_socket.close()
        print("Đã ngắt kết nối khỏi server.")
        sys.exit(0)


# --- Chạy Client ---
if __name__ == "__main__":
    start_client()