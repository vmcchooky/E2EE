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
    # (Dựa trên logic của server.py ở Tuần 2)
    try:
        message = client_socket.recv(1024).decode('utf-8')
        if message == "NAME":
            name = input("Nhập tên của bạn: ")
            client_socket.send(name.encode('utf-8'))
        else:
            print("Server không yêu cầu tên.")
    except Exception as e:
        print(f"Lỗi khi nhận yêu cầu tên: {e}")
        client_socket.close()
        return

    # 3. Tạo và khởi động luồng nhận tin nhắn
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.daemon = True  # Đặt là daemon để thread tự tắt khi chương trình chính tắt
    receive_thread.start()

    # 4. Vòng lặp gửi tin nhắn (chạy trên luồng chính)
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