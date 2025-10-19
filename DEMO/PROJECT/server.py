# server.py
import socket
import threading
import sys # Thêm thư viện để xử lý hệ thống

# --- Cấu hình Server ---
HOST = '127.0.0.1'  # IP của máy chủ. 127.0.0.1 là localhost (chạy trên chính máy mình)
PORT = 12345        # Port để lắng nghe. Chọn một port chưa được sử dụng.

# --- Biến cờ để kiểm soát việc chạy của server ---
server_running = True

# --- Quản lý Client ---
clients = [] # Danh sách lưu các kết nối của client
client_names = {} # Dictionary để lưu tên của client, key là object socket

# --- Khởi tạo server socket ở phạm vi toàn cục ---
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Dòng này cho phép tái sử dụng địa chỉ IP và port ngay lập tức, tránh lỗi "Address already in use"
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# --- Hàm gửi tin nhắn cho tất cả client ---
def broadcast(message, _client_socket):
    for client_socket in clients:
        # Gửi cho tất cả client trừ người gửi
        if client_socket != _client_socket:
            try:
                client_socket.send(message)
            except:
                # Nếu có lỗi (ví dụ: client đã ngắt kết nối), đóng và xóa client đó đi
                client_socket.close()
                # Dùng list comprehension để xóa client một cách an toàn
                clients[:] = [c for c in clients if c != client_socket]


# --- Hàm xử lý cho từng client ---
def handle_client(client_socket):
    try:
        # Yêu cầu client nhập tên
        client_socket.send("NAME".encode('utf-8'))
        name = client_socket.recv(1024).decode('utf-8')
        
        # Nếu client ngắt kết nối ngay khi được hỏi tên
        if not name:
            return

        client_names[client_socket] = name
        clients.append(client_socket)
        print(f"{name} đã tham gia phòng chat!")
        broadcast(f"{name} đã tham gia phòng chat!".encode('utf-8'), client_socket)

        # Thay vòng lặp vô tận bằng vòng lặp có điều kiện
        while server_running:
            try:
                # Nhận tin nhắn từ client
                message = client_socket.recv(1024)
                if message:
                    # Gửi tin nhắn này cho tất cả các client khác
                    broadcast_message = f"<{name}> {message.decode('utf-8')}".encode('utf-8')
                    print(broadcast_message.decode('utf-8'))
                    broadcast(broadcast_message, client_socket)
                else:
                    # Nếu không nhận được message, client đã ngắt kết nối
                    break
            except:
                break
    finally:
        # Xử lý khi client ngắt kết nối (dù vì lý do gì)
        if client_socket in clients:
            clients.remove(client_socket)
            name = client_names.pop(client_socket, 'Ai đó') # Lấy tên và xóa khỏi dictionary
            print(f"{name} đã rời phòng chat.")
            broadcast(f"{name} đã rời phòng chat.".encode('utf-8'), client_socket)
            client_socket.close()


# --- Hàm chính để khởi động Server ---
def start_server():
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Server đang lắng nghe trên {HOST}:{PORT}")
    print("Gõ 'quit' hoặc 'exit' và nhấn Enter để tắt server.")

    while server_running:
        try:
            # Đặt timeout để lệnh accept() không bị treo vô hạn
            # Nó sẽ cho phép vòng lặp kiểm tra biến server_running mỗi giây
            server_socket.settimeout(1.0)
            client_socket, address = server_socket.accept()
            print(f"Kết nối mới từ {str(address)}")

            # Tạo một luồng (thread) mới để xử lý client này
            # Điều này cho phép server xử lý nhiều client cùng lúc
            thread = threading.Thread(target=handle_client, args=(client_socket,))
            thread.daemon = True # Luồng sẽ tự tắt khi chương trình chính kết thúc
            thread.start()
        except socket.timeout:
            # Hết thời gian chờ, không có kết nối mới, tiếp tục vòng lặp
            continue
        except OSError:
            # Xảy ra lỗi khi socket đã bị đóng bởi luồng khác
            break

# --- Hàm mới: Lắng nghe lệnh thoát từ người dùng ---
def command_input():
    global server_running
    while server_running:
        command = input()
        if command.lower() in ["quit", "exit"]:
            print("Đang tắt server...")
            server_running = False
            # Đóng socket server để vòng lặp accept() thoát ngay lập tức
            server_socket.close()
            break

# --- Chạy Server ---
if __name__ == "__main__":
    # Tạo luồng riêng để nhận lệnh từ bàn phím
    input_thread = threading.Thread(target=command_input)
    input_thread.daemon = True
    input_thread.start()
    
    # Chạy server ở luồng chính
    start_server()

    print("Server đã tắt.")