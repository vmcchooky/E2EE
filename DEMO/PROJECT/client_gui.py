import socket
import threading
import customtkinter as ctk
import base64
from datetime import datetime
from tkinter import messagebox

# Import các hàm mã hóa của bạn
from crypto_utils import (
    generate_aes_key, 
    rsa_encrypt, rsa_decrypt,
    aes_encrypt, aes_decrypt,
    load_public_key_from_bytes
)

from crypto_utils import generate_or_load_keys

# Cấu hình giao diện chung
ctk.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

class ChatApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # 1. Cấu hình cửa sổ chính
        self.title("Secure Chat E2EE")
        self.geometry("900x600")

        # 2. Layout: Chia lưới 2 cột (1 cột danh sách user, 1 cột chat)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- CỘT TRÁI: DANH SÁCH USER ---
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="DANH BẠ", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Nơi chứa các nút bấm chọn người chat
        self.scrollable_user_list = ctk.CTkScrollableFrame(self.sidebar_frame, label_text="Online Users")
        self.scrollable_user_list.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")
                # Nút cố định để quay lại chat chung (Broadcast)
        self.broadcast_button = ctk.CTkButton(
            self.scrollable_user_list,
            text="Broadcast (All)",
            command=self.select_broadcast  # gọi hàm riêng, KHÔNG handshake
        )
        self.broadcast_button.pack(pady=5, padx=5, fill="x")

        # Nút kết nối thủ công (tạm thời)
        self.connect_btn = ctk.CTkButton(self.sidebar_frame, text="Connect Server", command=self.connect_server_dialog)
        self.connect_btn.grid(row=2, column=0, padx=20, pady=10)

        # --- CỘT PHẢI: KHUNG CHAT ---
        # Khu vực hiển thị tin nhắn
        self.chat_display = ctk.CTkTextbox(self, width=250)
        self.chat_display.grid(row=0, column=1, padx=(20, 20), pady=(20, 0), sticky="nsew")
        self.chat_display.configure(state="disabled") # Chỉ đọc, không cho gõ trực tiếp vào đây

        # Khu vực nhập tin nhắn
        self.entry_message = ctk.CTkEntry(self, placeholder_text="Nhập tin nhắn...")
        self.entry_message.grid(row=1, column=1, padx=(20, 20), pady=(20, 20), sticky="ew")

        # Nút gửi và Nút chọn chế độ
        self.send_button = ctk.CTkButton(self, text="Gửi", command=self.send_message_event)
        self.send_button.grid(row=1, column=1, padx=(20, 20), pady=(20, 20), sticky="e") # Căn phải đè lên entry

        # Biến trạng thái
        self.username = ""
        self.client_socket = None
        
        # Thêm các biến quản lý logic E2EE
        self.user_directory = {} # {name: public_key}
        self.session_keys = {}   # {name: aes_key}
        self.my_private_key = None
        
        # Biến chọn người đang chat
        self.current_chat_partner = "Broadcast" # Mặc định chat chung
        self.user_buttons = {} # [FIX] Thêm dictionary để quản lý nút bấm

    def connect_server_dialog(self):
        dialog = ctk.CTkInputDialog(text="Nhập tên của bạn:", title="Đăng nhập")
        name = dialog.get_input()
        if not name:
            return

        # Hỏi password (tạm thời dùng InputDialog, password lộ nhưng chấp nhận cho demo)
        pwd_dialog = ctk.CTkInputDialog(
            text="Nhập mật khẩu bảo vệ private key (tạo mới hoặc dùng lại):",
            title="Mật khẩu"
        )
        password = pwd_dialog.get_input()
        if not password:
            messagebox.showerror("Lỗi", "Mật khẩu không được rỗng.")
            return

        self.username = name
        self.title(f"Secure Chat - {self.username}")

        # 1. Logic tạo/nạp khóa RSA (có password)
        self.my_private_key, public_key_bytes = generate_or_load_keys(name, password)
        if not self.my_private_key:
            self.display_message("[ERROR] Không thể xử lý khóa (sai mật khẩu?).")
            return

        # 2. Kết nối Socket (Chạy ngầm)
        threading.Thread(target=self.start_socket, args=(name, public_key_bytes), daemon=True).start()
        self.connect_btn.configure(state="disabled")
    
    def start_socket(self, name, public_key_bytes):
        HOST = '127.0.0.1'
        PORT = 12345
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))
            
            # Logic xác thực với server (Tuần 4)
            # Nhận yêu cầu tên
            msg = self.client_socket.recv(1024).decode('utf-8')
            if msg == "NAME":
                self.client_socket.send((name + "\n").encode('utf-8'))
            
            msg = self.client_socket.recv(1024).decode('utf-8')
            if msg.startswith("[ERROR]"):
                self.display_message(msg.strip())
                self.client_socket.close()
                return

            if msg == "PUBKEY_REQ":
                self.client_socket.sendall(public_key_bytes)
                self.display_message("[SYSTEM] Đã kết nối thành công!")
            else:
                self.display_message(f"[ERROR] Handshake thất bại: {msg}")
                self.client_socket.close()
                return

            
            # Bắt đầu lắng nghe tin nhắn
            self.receive_messages()
            
        except Exception as e:
            self.display_message(f"[ERROR] Không thể kết nối: {e}")

    def receive_messages(self):
        buffer = ""
        while True:
            try:
                data = self.client_socket.recv(2048).decode('utf-8')
                if not data: break
                buffer += data
                
                while "\n" in buffer:
                    message, buffer = buffer.split("\n", 1)
                    # Xử lý tin nhắn (Logic Tuần 5 & 6)
                    self.process_incoming_message(message)
                    
            except Exception as e:
                print(e)
                break

    def process_incoming_message(self, message):
        # Khi cần in ra màn hình, dùng self.display_message()
        if not message:
            return

        if message.startswith("NEW_USER:"):
            _, name, pubkey_b64 = message.split(":", 2)
            if name != self.username:
                pubkey_bytes = base64.b64decode(pubkey_b64)
                self.user_directory[name] = load_public_key_from_bytes(pubkey_bytes)
                self.display_message(f"[INFO] {name} vừa online.")
                self.add_user_button(name)

        # SERVER đã chuẩn hóa format:
        #   SESSION_OFFER:<sender_name_thực>:<encrypted_key_b64>
        # nên GUI không cần quan tâm client khác gửi gì lên server,
        # chỉ cần tin sender_name và content từ server.

        elif message.startswith("SESSION_OFFER:"):
            try:
                _, sender_name, encrypted_key_b64 = message.split(":", 2)
                encrypted_key_bytes = base64.b64decode(encrypted_key_b64)
                aes_key = rsa_decrypt(encrypted_key_bytes, self.my_private_key)
                self.session_keys[sender_name] = aes_key
                self.display_message(f"[SECURE] Đã thiết lập khóa E2EE với {sender_name}.")
                
                # [UX UPDATE] Nếu đang mở cửa sổ chat với người này, cập nhật label
                if self.current_chat_partner == sender_name:
                    self.logo_label.configure(text=f"Chat với: {sender_name} (🔒)", text_color="green")
                    
            except Exception as e:
                self.display_message(f"[ERROR] Lỗi xử lý SESSION_OFFER: {e}")
                
        elif message.startswith("PRIVATE_MSG:"):
            try:
                _, sender_name, encrypted_content_b64 = message.split(":", 2)
                if sender_name not in self.session_keys:
                    self.display_message(f"[INFO] Nhận tin nhắn mã hóa từ {sender_name} nhưng chưa có khóa. Hãy kết nối trước.")
                    return
                session_key = self.session_keys[sender_name]
                encrypted_bytes = base64.b64decode(encrypted_content_b64)
                decrypted_text = aes_decrypt(encrypted_bytes, session_key)
                if decrypted_text:
                    self.display_message(f"[E2EE] <{sender_name}>: {decrypted_text.decode('utf-8')}")
                else:
                    self.display_message(f"[ERROR] Không thể giải mã tin nhắn từ {sender_name}.")
            except Exception as e:  # noqa: BLE001
                self.display_message(f"[ERROR] Lỗi xử lý PRIVATE_MSG: {e}")

        elif message.startswith("<"): # Chat thường
            self.display_message(message)
        
        else:
            self.display_message(f"[UNKNOWN] {message}")
            
    def send_message_event(self):
        msg = self.entry_message.get()
        if not msg: return
        
        target = self.current_chat_partner
        
        if target == "Broadcast":
            # Gửi tin nhắn công khai
            try:
                self.client_socket.send((msg + "\n").encode("utf-8"))
            except Exception as e:  # noqa: BLE001
                self.display_message(f"[ERROR] Lỗi khi gửi tin nhắn broadcast: {e}")
        else:
            # Gửi mã hóa (Logic Tuần 6)
            if target in self.session_keys:
                try:
                    session_key = self.session_keys[target]
                    encrypted_bytes = aes_encrypt(msg.encode('utf-8'), session_key)
                    if encrypted_bytes is None:
                        self.display_message("[ERROR] Mã hóa thất bại, không gửi tin nhắn.")
                        return
                    encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
                    final_msg = f"PRIVATE_MSG:{target}:{encrypted_b64}\n"
                    self.client_socket.send(final_msg.encode('utf-8'))
                    self.display_message(f"Me (to {target}) 🔒: {msg}")
                except Exception as e:  # noqa: BLE001
                    self.display_message(f"[ERROR] Lỗi khi gửi tin nhắn: {e}")
            else:
                self.display_message(f"[ERROR] Chưa có khóa với {target}. Đang yêu cầu kết nối...")
                # Tự động gửi yêu cầu kết nối (/connect logic)
                self.perform_handshake(target)

        self.entry_message.delete(0, "end")
    
    # [FIX] Sửa lại hàm thêm nút user
    def add_user_button(self, name):
        if name in self.user_buttons:
            return # Đã có nút này rồi thì bỏ qua

        btn = ctk.CTkButton(
            self.scrollable_user_list, 
            text=name,
            command=lambda n=name: self.select_chat_partner(n)
        )
        btn.pack(pady=5, padx=5, fill="x")
        self.user_buttons[name] = btn # Lưu lại nút

    # [FIX] Cập nhật hàm chọn chat partner
    def select_chat_partner(self, name):
        self.current_chat_partner = name
        
        if name not in self.session_keys:
            self.logo_label.configure(text=f"Đang kết nối: {name}...", text_color="orange")
            self.display_message(f"[SYSTEM] Đang thiết lập mã hóa E2EE với {name}...")
            self.perform_handshake(name)
        else:
            self.logo_label.configure(text=f"Chat với: {name} (🔒)", text_color="green")
            self.display_message(f"--- Đã chuyển sang chế độ chat an toàn với {name} ---")
     
    def select_broadcast(self):
        """Chuyển về phòng chat chung (Broadcast), không mã hóa E2EE."""
        self.current_chat_partner = "Broadcast"
        # Cập nhật tiêu đề bên trái cho dễ nhìn
        self.logo_label.configure(text="DANH BẠ - Chat chung", text_color="white")
        self.display_message("--- Đã chuyển sang phòng chat chung (Broadcast) ---")
               
    def perform_handshake(self, target_name):
        """Tạo AES key, mã hóa bằng RSA của target và gửi SESSION_OFFER."""
        if target_name == self.username:
            self.display_message("[ERROR] Không thể kết nối với chính mình.")
            return
        if target_name not in self.user_directory:
            self.display_message(f"[ERROR] Không tìm thấy người dùng: {target_name}.")
            return
        if target_name in self.session_keys:
            self.display_message(f"[INFO] Đã có khóa với {target_name}.")
            return

        try:
            target_pubkey_obj = self.user_directory[target_name]
            aes_key = generate_aes_key()
            encrypted_aes_key = rsa_encrypt(aes_key, target_pubkey_obj)
            self.session_keys[target_name] = aes_key

            encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
            offer_message = f"SESSION_OFFER:{target_name}:{self.username}:{encrypted_key_b64}\n"
            self.client_socket.sendall(offer_message.encode('utf-8'))
            self.display_message(f"[SYSTEM] Đã gửi lời mời E2EE đến {target_name}.")
        except Exception as e:  # noqa: BLE001
            self.display_message(f"[ERROR] Lỗi khi bắt tay với {target_name}: {e}")
      
    # Trong client_gui.py -> class ChatApp

    def display_message(self, text):
        # Dùng self.after để đẩy việc cập nhật UI về luồng chính
        self.after(0, self._safe_display_message, text)

    def _safe_display_message(self, text):
        """Hàm nội bộ thực sự thực hiện việc in tin nhắn"""
        self.chat_display.configure(state="normal")
        self.chat_display.insert("end", text + "\n")
        self.chat_display.configure(state="disabled")
        self.chat_display.see("end")

if __name__ == "__main__":
    app = ChatApp()
    app.mainloop()
