import socket
import threading
import customtkinter as ctk
import base64
from datetime import datetime
from tkinter import messagebox

import os
import json

# Import các hàm mã hóa của bạn
from crypto_utils import (
    generate_aes_key, 
    rsa_encrypt, rsa_decrypt,
    aes_encrypt, aes_decrypt,
    load_public_key_from_bytes,
    public_key_fingerprint,
    generate_or_load_keys
)

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
        self.connect_btn.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

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
        self.server_password = None
        
        # Thêm các biến quản lý logic E2EE
        self.user_directory = {} # {name: public_key}
        self.session_keys = {}   # {name: aes_key}
        self.my_private_key = None
        
        # Biến chọn người đang chat
        self.current_chat_partner = "Broadcast" # Mặc định chat chung
        self.user_buttons = {} # [FIX] Thêm dictionary để quản lý nút bấm
        
        self.known_keys = {}  # {name: fingerprint}
        self.known_keys_file = "FingerPrint/known_keys_gui.json"
        self.load_known_keys()
        
        # Khung bảo mật (chứa các nút fingerprint) - ẨN LÚC ĐẦU
        self.security_frame = ctk.CTkFrame(self.sidebar_frame)
        self.security_frame.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="ew")
        self.security_frame.grid_remove()  # ẩn đi cho tới khi connect xong

        security_label = ctk.CTkLabel(
            self.security_frame,
            text="Bảo mật / Fingerprint",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        security_label.pack(pady=(5, 5))

        # Nút xem fingerprint của chính mình
        self.view_self_fp_btn = ctk.CTkButton(
            self.security_frame,
            text="Fingerprint của tôi",
            command=self.show_self_fingerprint
        )
        self.view_self_fp_btn.pack(fill="x", pady=(0, 5))

        # Nút xem fingerprint của người đang chọn
        self.view_partner_fp_btn = ctk.CTkButton(
            self.security_frame,
            text="Fingerprint người đang chọn",
            command=self.show_partner_fingerprint
        )
        self.view_partner_fp_btn.pack(fill="x", pady=(0, 5))

    def format_fingerprint(self, fp: str) -> str:
        """Định dạng fingerprint thành nhóm 4 ký tự: xxxx xxxx xxxx xxxx."""
        if not fp:
            return ""
        raw = fp.replace(" ", "").strip()
        return " ".join(raw[i:i+4] for i in range(0, len(raw), 4))

    def show_fingerprint_popup(self, title: str, name: str, fp: str):
        """Hiển thị popup fingerprint với dạng 4-4-4-4 và nút Copy clipboard."""
        grouped = self.format_fingerprint(fp)

        win = ctk.CTkToplevel(self)
        win.title(title)
        win.geometry("420x180")
        win.resizable(False, False)
        win.grab_set()  # khóa focus vào popup

        label_title = ctk.CTkLabel(
            win,
            text=f"Fingerprint của {name}:",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        label_title.pack(pady=(15, 5))

        label_fp = ctk.CTkLabel(
            win,
            text=grouped,
            font=ctk.CTkFont(size=18, weight="bold")
        )
        label_fp.pack(pady=(0, 15))

        def copy_to_clipboard():
            # Copy fingerprint "thô" (không cách) để paste dễ dùng
            self.clipboard_clear()
            self.clipboard_append(fp)
            self.display_message(f"[INFO] Đã copy fingerprint của {name} vào clipboard.")

        btn_frame = ctk.CTkFrame(win)
        btn_frame.pack(pady=5)

        copy_btn = ctk.CTkButton(btn_frame, text="Copy fingerprint", command=copy_to_clipboard)
        copy_btn.grid(row=0, column=0, padx=5)

        close_btn = ctk.CTkButton(btn_frame, text="Đóng", command=win.destroy)
        close_btn.grid(row=0, column=1, padx=5)

    def load_known_keys(self):
        """Nạp danh sách fingerprint đã từng lưu (TOFU)."""
        try:
            if os.path.exists(self.known_keys_file):
                with open(self.known_keys_file, "r", encoding="utf-8") as f:
                    self.known_keys = json.load(f)
            else:
                self.known_keys = {}
        except Exception:
            # Nếu file lỗi format thì bỏ qua
            self.known_keys = {}

    def save_known_keys(self):
        """Lưu danh sách fingerprint ra file."""
        try:
            folder = os.path.dirname(self.known_keys_file)
            if folder:
                os.makedirs(folder, exist_ok=True)
            with open(self.known_keys_file, "w", encoding="utf-8") as f:
                json.dump(self.known_keys, f, indent=2)
        except Exception as e:
            self.display_message(f"[ERROR] Lỗi khi lưu known_keys: {e}")

    def show_self_fingerprint(self):
        """Hiển thị fingerprint public key của chính client (popup + chat log)."""
        if not hasattr(self, "my_public_key_bytes") or self.my_public_key_bytes is None:
            self.display_message("[INFO] Bạn chưa kết nối nên chưa có fingerprint của chính mình.")
            messagebox.showinfo("Fingerprint của bạn", "Bạn chưa kết nối nên chưa có fingerprint.")
            return

        fp = getattr(self, "my_fingerprint", None)
        if not fp:
            fp = public_key_fingerprint(self.my_public_key_bytes)
            self.my_fingerprint = fp

        grouped = self.format_fingerprint(fp)
        self.display_message(
            f"[INFO] Fingerprint của bạn ({self.username}): {grouped}"
        )

        self.show_fingerprint_popup("Fingerprint của bạn", self.username, fp)

    def show_partner_fingerprint(self):
        """Hiển thị fingerprint của người dùng đang được chọn trong danh bạ."""
        name = self.current_chat_partner

        if not name or name == "Broadcast":
            messagebox.showinfo(
                "Fingerprint",
                "Hãy chọn một người dùng cụ thể trong danh bạ (không phải Broadcast)."
            )
            return

        fp = self.known_keys.get(name)
        if not fp:
            self.display_message(
                f"[INFO] Chưa có fingerprint đã lưu cho {name}. Có thể họ chưa online hoặc dữ liệu đã bị xóa."
            )
            messagebox.showinfo(
                "Fingerprint",
                f"Chưa có fingerprint đã lưu cho {name}."
            )
            return

        grouped = self.format_fingerprint(fp)
        self.display_message(
            f"[INFO] Fingerprint đã tin cậy của {name}: {grouped}"
        )

        self.show_fingerprint_popup(f"Fingerprint của {name}", name, fp)

    def connect_server_dialog(self):
        dialog = ctk.CTkInputDialog(text="Nhập tên của bạn:", title="Đăng nhập")
        name = dialog.get_input()
        if not name:
            return

        # Hỏi password đăng nhập server
        server_pwd_dialog = ctk.CTkInputDialog(
            text="Nhập mật khẩu đăng nhập server\n(Nếu là lần đầu, mật khẩu này sẽ dùng để đăng ký):",
            title="Mật khẩu server"
        )
        server_password = server_pwd_dialog.get_input()
        if not server_password:
            messagebox.showerror("Lỗi", "Mật khẩu server không được rỗng.")
            return

        # Hỏi password bảo vệ private key
        key_pwd_dialog = ctk.CTkInputDialog(
            text="Nhập mật khẩu bảo vệ private key (tạo mới hoặc dùng lại):",
            title="Mật khẩu private key"
        )
        key_password = key_pwd_dialog.get_input()
        if not key_password:
            messagebox.showerror("Lỗi", "Mật khẩu private key không được rỗng.")
            return

        self.username = name
        self.server_password = server_password
        self.title(f"Secure Chat - {self.username}")

        # 1. Logic tạo/nạp khóa RSA (có password)
        self.my_private_key, public_key_bytes = generate_or_load_keys(name, key_password)
        if not self.my_private_key:
            self.display_message("[ERROR] Không thể xử lý khóa (sai mật khẩu?).")
            return

        # Lưu lại public key & fingerprint của chính mình để sau xem lại
        self.my_public_key_bytes = public_key_bytes
        self.my_fingerprint = public_key_fingerprint(public_key_bytes)

        # 2. Kết nối Socket (Chạy ngầm)
        threading.Thread(
            target=self.start_socket,
            args=(name, public_key_bytes),
            daemon=True
        ).start()

        # Disable nút Connect, khung fingerprint sẽ hiện sau khi kết nối OK
        self.connect_btn.configure(state="disabled")

    def start_socket(self, name, public_key_bytes):
        HOST = '127.0.0.1'
        PORT = 12345
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))
            
            # Nhận yêu cầu tên
            msg = self.client_socket.recv(1024).decode('utf-8').strip()
            if msg == "NAME":
                self.client_socket.send((name + "\n").encode('utf-8'))
            else:
                self.display_message(f"[ERROR] Server không yêu cầu NAME mà gửi: {msg}")
                self.client_socket.close()
                return

            # Nhận phản hồi sau khi gửi tên: hoặc [ERROR] hoặc AUTH_REQ
            msg = self.client_socket.recv(1024).decode('utf-8').strip()
            if msg.startswith("[ERROR]"):
                self.display_message(msg)
                self.client_socket.close()
                return

            if msg == "AUTH_REQ":
                # Gửi mật khẩu server
                if not self.server_password:
                    self.display_message("[ERROR] Chưa có mật khẩu server.")
                    self.client_socket.close()
                    return
                self.client_socket.send(self.server_password.encode("utf-8"))

                auth_resp = self.client_socket.recv(1024).decode("utf-8").strip()
                if auth_resp.startswith("[ERROR]"):
                    self.display_message(f"[ERROR] Xác thực thất bại: {auth_resp}")
                    self.client_socket.close()
                    return
                if auth_resp != "AUTH_OK":
                    self.display_message(f"[ERROR] Handshake AUTH không hợp lệ: {auth_resp}")
                    self.client_socket.close()
                    return

                self.display_message("[SYSTEM] Xác thực với server thành công.")
            else:
                self.display_message(f"[ERROR] Mong đợi AUTH_REQ nhưng nhận: {msg}")
                self.client_socket.close()
                return

            # Yêu cầu public key
            msg = self.client_socket.recv(1024).decode('utf-8').strip()
            if msg.startswith("[ERROR]"):
                self.display_message(msg)
                self.client_socket.close()
                return

            if msg == "PUBKEY_REQ":
                self.client_socket.sendall(public_key_bytes)
                self.display_message("[SYSTEM] Đã kết nối thành công!")

                # Hiện khung fingerprint
                def show_security():
                    self.security_frame.grid()
                self.after(0, show_security)
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

                # Tính fingerprint hiện tại của public key mới nhận
                fp = public_key_fingerprint(pubkey_bytes)

                # Trường hợp 1: lần đầu thấy user này -> TOFU, tự tin lần đầu
                if name not in self.known_keys:
                    self.known_keys[name] = fp
                    self.save_known_keys()
                    # Cảnh báo nhẹ: cho user biết fingerprint để có thể tự check
                    self.display_message(f"[INFO] {name} vừa online. Fingerprint key: {fp}")
                    self.display_message(">> Nếu cần an toàn cao, hãy xác minh fingerprint bằng kênh khác.")
                else:
                    # Trường hợp 2: đã từng thấy user này trước đây -> kiểm tra fingerprint
                    old_fp = self.known_keys[name]
                    if old_fp != fp:
                        # 1) CẢNH BÁO TRƯỚC ĐÓ: ghi rõ vào khung chat
                        self.display_message(f"[WARNING] Public key của {name} đã thay đổi!")
                        self.display_message(f"  - Fingerprint cũ : {old_fp}")
                        self.display_message(f"  - Fingerprint mới: {fp}")
                        self.display_message(">> Có thể là tấn công MITM hoặc người đó vừa đổi thiết bị / cài lại app.")

                        # 2) POP-UP HỎI CÓ ACCEPT KEY MỚI KHÔNG
                        accept = messagebox.askyesno(
                            "Cảnh báo bảo mật",
                            (
                                f"Fingerprint của {name} đã thay đổi.\n\n"
                                f"Cũ : {old_fp}\nMới: {fp}\n\n"
                                "Nếu bạn ĐÃ xác minh qua kênh khác rằng đây thật sự là key mới của họ,\n"
                                "hãy chọn 'Yes' để chấp nhận key mới.\n\n"
                                "Nếu không chắc chắn, hãy chọn 'No' để từ chối (giữ key cũ)."
                            )
                        )

                        if accept:
                            # Người dùng CHỦ ĐỘNG chấp nhận: cập nhật fingerprint + public key
                            self.known_keys[name] = fp
                            self.save_known_keys()
                            self.user_directory[name] = load_public_key_from_bytes(pubkey_bytes)
                            self.display_message(f"[INFO] Bạn đã chấp nhận public key mới của {name}.")
                            self.add_user_button(name)
                        else:
                            # Từ chối key mới: KHÔNG update public key, không thêm nút chat
                            self.display_message(f"[INFO] Bạn đã từ chối public key mới của {name}.")
                        return  # Quan trọng: kết thúc xử lý NEW_USER ở đây

                # Nếu fingerprint ổn (lần đầu hoặc khớp fingerprint cũ) -> lưu public key, thêm vào danh bạ
                self.user_directory[name] = load_public_key_from_bytes(pubkey_bytes)
                self.display_message(f"[INFO] {name} vừa online.")
                self.add_user_button(name)


        # SERVER đã chuẩn hóa format:~
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
