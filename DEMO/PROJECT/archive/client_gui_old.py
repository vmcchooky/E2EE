import socket
import threading
import customtkinter as ctk
import base64
from datetime import datetime
from tkinter import messagebox

import os
import json
import uuid
import ssl
import time

# Import các hàm mã hóa của bạn
from crypto_utils import (
    generate_aes_key, 
    rsa_encrypt, rsa_decrypt,
    aes_encrypt, aes_decrypt,
    load_public_key_from_bytes,
    public_key_fingerprint,
    generate_or_load_keys,
    session_confirm_token,
    build_session_offer_sig_bytes,
    rsa_sign_pss_sha256,
    rsa_verify_pss_sha256,
    b64e,
    b64d,
)

from protocol import (
    TYPE_NAME_REQ, TYPE_AUTH_REQ, TYPE_AUTH_OK, TYPE_ERROR, TYPE_PUBKEY_REQ,
    TYPE_USER_ANNOUNCE, TYPE_SESSION_OFFER, TYPE_SESSION_ACK, TYPE_PRIVATE_MSG, TYPE_BROADCAST
)

from transport import ProtoClient

REKEY_INTERVAL_SEC = 20 * 60   # 20 phút
REKEY_AFTER_MSGS = 50          # sau 50 tin nhắn outbound với 1 peer thì re-key

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
        # Hàng 0: header chat (không mở rộng)
        self.grid_rowconfigure(0, weight=0)
        # Hàng 1: khung chat (mở rộng theo chiều dọc)
        self.grid_rowconfigure(1, weight=1)
        # Hàng 2: input (không mở rộng)
        self.grid_rowconfigure(2, weight=0)

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

        # Thanh tiêu đề khung chat (hiển thị partner + nút Re-key)
        self.chat_header_frame = ctk.CTkFrame(self)
        self.chat_header_frame.grid(
            row=0, column=1,
            padx=(20, 20), pady=(20, 0),
            sticky="ew"
        )
        self.chat_header_frame.grid_columnconfigure(0, weight=1)

        self.chat_title_label = ctk.CTkLabel(
            self.chat_header_frame,
            text="Chat chung (Broadcast)",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.chat_title_label.grid(row=0, column=0, sticky="w")

        # Nút Re-key: chỉ enable khi đang chat riêng và đã có E2EE
        self.rekey_button = ctk.CTkButton(
            self.chat_header_frame,
            text="Re-key",
            width=80,
            command=self.rekey_current_session
        )
        self.rekey_button.grid(row=0, column=1, padx=(10, 0))
        self.rekey_button.configure(state="disabled")

        # --- CỘT PHẢI: KHUNG CHAT ---
        # Khu vực hiển thị tin nhắn
        self.chat_display = ctk.CTkTextbox(self, width=250)
        self.chat_display.grid(
            row=1, column=1,
            padx=(20, 20), pady=(10, 0),
            sticky="nsew"
        )

        self.chat_display.configure(state="disabled") # Chỉ đọc, không cho gõ trực tiếp vào đây

        # Khung chứa ô nhập và nút gửi
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.grid(
            row=2, column=1,
            padx=(20, 20), pady=(10, 20),
            sticky="ew"
        )
        self.input_frame.grid_columnconfigure(0, weight=1)

        # Khu vực nhập tin nhắn
        self.entry_message = ctk.CTkEntry(self.input_frame, placeholder_text="Nhập tin nhắn...")
        self.entry_message.grid(row=0, column=0, padx=(0, 10), pady=0, sticky="ew")

        # Nút gửi
        self.send_button = ctk.CTkButton(self.input_frame, text="Gửi", command=self.send_message_event, width=80)
        self.send_button.grid(row=0, column=1, pady=0, sticky="e")

        # Biến trạng thái
        self.username = ""
        self.client_socket = None
        self.server_password = None
        
        # Thêm các biến quản lý logic E2EE
        self.user_directory = {} # {name: public_key}
        self.session_keys = {}   # {name: aes_key}
        self.session_confirmed = {}  # {name: bool}
        self.pending_session_acks = {}  # {(name, session_id): aes_key}
        # Anti-replay + auto rekey state
        self.send_ctr = {}         # {peer: last_sent_ctr}
        self.recv_ctr = {}         # {peer: last_recv_ctr}
        self.out_msg_count = {}    # {peer: outbound_count_since_rekey}
        self.last_rekey_time = {}  # {peer: unix_ts}
        self.my_private_key = None

        # Biến chọn người đang chat
        self.current_chat_partner = "Broadcast" # Mặc định chat chung
        self.user_buttons = {} # [FIX] Thêm dictionary để quản lý nút bấm
        # Cập nhật header chat ban đầu
        self.ui(self.update_chat_header)

        
        # Biến quản lý fingerprint đã biết (TOFU)
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

    def remove_user_button(self, name: str) -> None:
        """Xóa nút user khỏi sidebar (PHẢI gọi qua self.ui)."""
        btn = self.user_buttons.pop(name, None)
        if btn is not None:
            try:
                btn.destroy()
            except Exception:
                # Tránh crash nếu widget đã bị destroy ở nơi khác
                pass

    def ui(self, fn, *args, **kwargs):
        try:
            self.after(0, lambda: fn(*args, **kwargs))
        except Exception:
            pass

    def ask_yesno_threadsafe(self, title: str, message: str) -> bool:
        """
        Hiển thị messagebox.askyesno an toàn thread.
        Thread receive sẽ chờ kết quả, UI không bị crash.
        """
        import threading
        from tkinter import messagebox

        event = threading.Event()
        result = {"value": False}

        def _ask():
            try:
                result["value"] = messagebox.askyesno(title, message)
            except Exception:
                result["value"] = False
            finally:
                event.set()

        self.ui(_ask)
        event.wait()
        return result["value"]

    def update_chat_header(self):
        """Cập nhật tiêu đề khung chat và trạng thái nút Re-key."""
        partner = self.current_chat_partner

        if partner == "Broadcast":
            self.chat_title_label.configure(text="Chat chung (Broadcast)")
            self.rekey_button.configure(state="disabled")
            return

        # Đang chat riêng
        if partner in self.session_keys:
            confirmed = self.session_confirmed.get(partner, False)
            if confirmed:
                self.chat_title_label.configure(text=f"Chat với: {partner} (🔒)")
            else:
                self.chat_title_label.configure(text=f"Chat với: {partner} (🔒 chưa ACK)")
            self.rekey_button.configure(state="normal")
        else:
            # Chưa có khóa / đang thiết lập
            self.chat_title_label.configure(text=f"Chat với: {partner} (đang thiết lập khóa...)")
            self.rekey_button.configure(state="disabled")

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
        HOST = "127.0.0.1"
        PORT = 12345
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # TLS verify server cert
            context = ssl.create_default_context(cafile="../certs/server_cert.pem")
            # (mặc định check_hostname=True trong create_default_context)
            tls_sock = context.wrap_socket(raw, server_hostname="SecureChatDev")
            tls_sock.connect((HOST, PORT))

            # Lưu socket đúng biến, dùng thống nhất
            self.client_socket = tls_sock
            self.proto = ProtoClient(self.client_socket)

            # Handshake theo protocol
            m = self.proto.recv()
            if m["type"] != TYPE_NAME_REQ:
                self.display_message(f"[ERROR] Expected NAME_REQ, got {m}")
                self.client_socket.close()
                return
            self.proto.send_name(name)

            m = self.proto.recv()
            if m["type"] == TYPE_ERROR:
                self.display_message(f"[ERROR] {m['payload']['message']}")
                self.client_socket.close()
                return
            if m["type"] != TYPE_AUTH_REQ:
                self.display_message(f"[ERROR] Expected AUTH_REQ, got {m}")
                self.client_socket.close()
                return
            self.proto.send_auth(self.server_password)

            m = self.proto.recv()
            if m["type"] == TYPE_ERROR:
                self.display_message(f"[ERROR] Auth failed: {m['payload']['message']}")
                self.client_socket.close()
                return
            if m["type"] != TYPE_AUTH_OK:
                self.display_message(f"[ERROR] Expected AUTH_OK, got {m}")
                self.client_socket.close()
                return

            m = self.proto.recv()
            if m["type"] == TYPE_ERROR:
                self.display_message(f"[ERROR] {m['payload']['message']}")
                self.client_socket.close()
                return
            if m["type"] != TYPE_PUBKEY_REQ:
                self.display_message(f"[ERROR] Expected PUBKEY_REQ, got {m}")
                self.client_socket.close()
                return

            pubkey_b64 = base64.b64encode(public_key_bytes).decode("utf-8")
            self.proto.send_pubkey(pubkey_b64)

            self.display_message("[SYSTEM] Đã kết nối thành công!")
            self.ui(self.security_frame.grid)

            self.receive_messages()

        except Exception as e:
            self.display_message(f"[ERROR] Không thể kết nối: {e}")
            try:
                if getattr(self, "client_socket", None):
                    self.client_socket.close()
            except Exception:
                pass

    def receive_messages(self):
        while True:
            try:
                m = self.proto.recv()
                self.process_incoming_message(m)
            except Exception as e:
                self.display_message(f"[ERROR] Receive loop stopped: {e}")
                break

    def process_incoming_message(self, m: dict):
        """Process incoming message based on message type."""
        if not m or "type" not in m:
            return

        msg_type = m["type"]
        payload = m.get("payload", {})

        if msg_type == TYPE_USER_ANNOUNCE:
            name = payload.get("name")
            pubkey_b64 = payload.get("pubkey_b64")

            if name == self.username:
                return

            if pubkey_b64 is None:
                # User offline: remove from directory and UI (thread-safe)
                self.display_message(f"[INFO] {name} vừa offline.")

                # Xóa dữ liệu liên quan
                self.user_directory.pop(name, None)
                self.session_keys.pop(name, None)
                self.session_confirmed.pop(name, None)
                self.send_ctr.pop(name, None)
                self.recv_ctr.pop(name, None)
                self.out_msg_count.pop(name, None)
                self.last_rekey_time.pop(name, None)

                # Drop pending ACKs liên quan
                for k in list(self.pending_session_acks.keys()):
                    if k[0] == name:
                        self.pending_session_acks.pop(k, None)

                # Xóa nút UI trên main thread
                self.ui(self.remove_user_button, name)

                # Nếu đang chat với user vừa offline -> quay về Broadcast để UI không “đụng” session cũ
                if self.current_chat_partner == name:
                    self.current_chat_partner = "Broadcast"
                    self.ui(self.update_chat_header)

                return

            # User online: TOFU fingerprint logic
            pubkey_bytes = base64.b64decode(pubkey_b64)
            fp = public_key_fingerprint(pubkey_bytes)

            if name not in self.known_keys:
                # First time seeing this user
                self.known_keys[name] = fp
                self.save_known_keys()
                self.display_message(f"[INFO] {name} vừa online. Fingerprint key: {fp}")
                self.display_message(">> Nếu cần an toàn cao, hãy xác minh fingerprint bằng kênh khác.")
            else:
                # Check if fingerprint matches
                old_fp = self.known_keys[name]
                if old_fp != fp:
                    self.display_message(f"[WARNING] Public key của {name} đã thay đổi!")
                    self.display_message(f"  - Fingerprint cũ : {old_fp}")
                    self.display_message(f"  - Fingerprint mới: {fp}")
                    self.display_message(">> Có thể là tấn công MITM hoặc người đó vừa đổi thiết bị / cài lại app.")

                    accept = self.ask_yesno_threadsafe(
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
                        self.known_keys[name] = fp
                        self.save_known_keys()
                        self.user_directory[name] = load_public_key_from_bytes(pubkey_bytes)
                        self.display_message(f"[INFO] Bạn đã chấp nhận public key mới của {name}.")
                        self.ui(self.add_user_button, name)
                    else:
                        self.display_message(f"[INFO] Bạn đã từ chối public key mới của {name}.")
                    return

            # Save public key and add to user list
            self.user_directory[name] = load_public_key_from_bytes(pubkey_bytes)
            self.display_message(f"[INFO] {name} vừa online.")
            self.ui(self.add_user_button, name)

        elif msg_type == TYPE_SESSION_OFFER:
            try:
                sender_name = payload.get("from")
                session_id = payload.get("session_id")
                encrypted_key_b64 = payload.get("encrypted_key_b64")
                sig_b64 = payload.get("sig_b64")

                if not sender_name or not session_id or not encrypted_key_b64 or not sig_b64:
                    self.display_message(f"[ERROR] SESSION_OFFER không hợp lệ: {m}")
                    return

                sender_pub = self.user_directory.get(sender_name)
                if sender_pub is None:
                    self.display_message(f"[ERROR] Chưa có public key của {sender_name} -> bỏ qua SESSION_OFFER.")
                    return

                signed = build_session_offer_sig_bytes(sender_name, self.username, session_id, encrypted_key_b64)
                if not rsa_verify_pss_sha256(sender_pub, b64d(sig_b64), signed):
                    self.display_message(f"[WARNING] SESSION_OFFER từ {sender_name} có signature KHÔNG hợp lệ -> bỏ qua.")
                    return

                encrypted_key_bytes = base64.b64decode(encrypted_key_b64)
                aes_key = rsa_decrypt(encrypted_key_bytes, self.my_private_key)

                self.session_keys[sender_name] = aes_key
                self.send_ctr[sender_name] = 0
                self.recv_ctr[sender_name] = 0
                self.out_msg_count[sender_name] = 0
                self.last_rekey_time[sender_name] = time.time()
                self.session_confirmed[sender_name] = True

                confirm_hex = session_confirm_token(aes_key, session_id)
                self.proto.send_session_ack(sender_name, session_id, confirm_hex)

                self.display_message(f"[SYSTEM] Đã thiết lập E2EE với {sender_name} (session_id={session_id}) và gửi ACK.")
                self.ui(self.update_chat_header)

            except Exception as e:
                self.display_message(f"[ERROR] Lỗi xử lý SESSION_OFFER: {e}")

        elif msg_type == TYPE_SESSION_ACK:
            try:
                sender_name = payload.get("from")
                session_id = payload.get("session_id")
                confirm_hex = payload.get("confirm_hex")

                if not sender_name or not session_id or not confirm_hex:
                    self.display_message(f"[ERROR] SESSION_ACK không hợp lệ: {m}")
                    return

                key = self.pending_session_acks.pop((sender_name, session_id), None)
                if key is None:
                    self.display_message(
                        f"[INFO] Nhận ACK từ {sender_name} nhưng không tìm thấy pending session_id={session_id}."
                    )
                    return

                expected = session_confirm_token(key, session_id)
                if expected != confirm_hex:
                    self.display_message(
                        f"[WARNING] ACK của {sender_name} KHÔNG khớp (session_id={session_id})."
                    )
                    return

                # Commit key mới + reset state (cực quan trọng cho re-key)
                self.session_keys[sender_name] = key
                self.session_confirmed[sender_name] = True

                # Reset counters để anti-replay đồng bộ với key mới
                self.send_ctr[sender_name] = 0
                self.recv_ctr[sender_name] = 0
                self.out_msg_count[sender_name] = 0
                self.last_rekey_time[sender_name] = time.time()

                self.display_message(
                    f"[SECURE] {sender_name} đã ACK thành công. Kênh E2EE được xác nhận (session_id={session_id})."
                )
                self.ui(self.update_chat_header)

            except Exception as e:
                self.display_message(f"[ERROR] Lỗi xử lý SESSION_ACK: {e}")

        elif msg_type == TYPE_PRIVATE_MSG:
            try:
                sender_name = payload.get("from")
                ciphertext_b64 = payload.get("ciphertext_b64")
                ctr = payload.get("ctr")

                if not sender_name or not ciphertext_b64 or ctr is None:
                    self.display_message(f"[ERROR] PRIVATE_MSG không hợp lệ: {m}")
                    return

                if sender_name not in self.session_keys:
                    self.display_message(f"[INFO] Nhận tin mã hóa từ {sender_name} nhưng chưa có khóa.")
                    return

                ctr = int(ctr)
                last = self.recv_ctr.get(sender_name, 0)
                if ctr <= last:
                    self.display_message(f"[WARNING] Replay/Out-of-order từ {sender_name}: ctr={ctr} <= last={last} -> drop")
                    return

                session_key = self.session_keys[sender_name]
                encrypted_bytes = base64.b64decode(ciphertext_b64)

                aad = f"{sender_name}|{self.username}|{ctr}".encode("utf-8")
                decrypted_text = aes_decrypt(encrypted_bytes, session_key, associated_data=aad)

                if decrypted_text:
                    self.recv_ctr[sender_name] = ctr
                    self.display_message(f"[E2EE] <{sender_name}>: {decrypted_text.decode('utf-8')}")
                else:
                    self.display_message(f"[ERROR] Không thể giải mã tin nhắn từ {sender_name} (ctr={ctr}).")
            except Exception as e:
                self.display_message(f"[ERROR] Lỗi xử lý PRIVATE_MSG: {e}")

        elif msg_type == TYPE_BROADCAST:
            try:
                sender_name = payload.get("from")
                text = payload.get("text")
                self.display_message(f"<{sender_name}>: {text}")
            except Exception as e:
                self.display_message(f"[ERROR] Lỗi xử lý BROADCAST: {e}")

        else:
            self.display_message(f"[UNKNOWN] Loại tin nhắn không xác định: {msg_type}")
            
    def send_message_event(self):
        msg = self.entry_message.get()
        if not msg: return
        
        target = self.current_chat_partner
        
        if target == "Broadcast":
            # Gửi tin nhắn công khai
            try:
                self.proto.send_broadcast(msg)
            except Exception as e:  # noqa: BLE001
                self.display_message(f"[ERROR] Lỗi khi gửi tin nhắn broadcast: {e}")
        else:
            # Nếu đang handshake/rekey (chưa ACK) thì block để tránh lệch key
            if not self.session_confirmed.get(target, False):
                self.display_message(f"[INFO] Đang (re)key với {target}, vui lòng đợi ACK rồi gửi lại.")
                self.entry_message.delete(0, "end")
                return

            if target in self.session_keys:
                try:
                    session_key = self.session_keys[target]

                    # ctr tăng dần cho anti-replay
                    ctr = self.send_ctr.get(target, 0) + 1
                    self.send_ctr[target] = ctr

                    aad = f"{self.username}|{target}|{ctr}".encode("utf-8")
                    encrypted_bytes = aes_encrypt(msg.encode("utf-8"), session_key, associated_data=aad)
                    if encrypted_bytes is None:
                        self.display_message("[ERROR] Mã hóa thất bại, không gửi tin nhắn.")
                        return

                    encrypted_b64 = base64.b64encode(encrypted_bytes).decode("utf-8")

                    # Gửi kèm ctr
                    self.proto.send_private_msg(target, encrypted_b64, ctr)

                    self.display_message(f"Me (to {target}) 🔒: {msg}")

                    # track count cho auto rekey
                    self.out_msg_count[target] = self.out_msg_count.get(target, 0) + 1

                    # gọi auto rekey sau khi gửi (không phá message hiện tại)
                    self.maybe_auto_rekey(target)

                except Exception as e:
                    self.display_message(f"[ERROR] Lỗi khi gửi tin nhắn: {e}")
            else:
                self.display_message(f"[ERROR] Chưa có khóa với {target}. Đang yêu cầu kết nối...")
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
            self.display_message(f"[SYSTEM] Đang thiết lập mã hóa E2EE với {name}...")
            self.perform_handshake(name)
        else:
            self.display_message(f"--- Đã chuyển sang chế độ chat an toàn với {name} ---")

        # Chỉ cập nhật header bên phải
        self.ui(self.update_chat_header)


    def select_broadcast(self):
        """Chuyển về phòng chat chung (Broadcast), không mã hóa E2EE."""
        self.current_chat_partner = "Broadcast"
        # Cập nhật tiêu đề bên trái cho dễ nhìn
        # self.logo_label.configure(text="DANH BẠ - Chat chung", text_color="white")
        self.display_message("--- Đã chuyển sang phòng chat chung (Broadcast) ---")
        self.ui(self.update_chat_header)

               
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
            self.ui(self.update_chat_header)

            return

        try:
            target_pubkey_obj = self.user_directory[target_name]
            aes_key = generate_aes_key()
            encrypted_aes_key = rsa_encrypt(aes_key, target_pubkey_obj)

            # Lưu key local trước (để bạn có thể mã hóa ngay lập tức nếu muốn)
            self.session_keys[target_name] = aes_key

            encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode("utf-8")
            session_id = uuid.uuid4().hex
            self.pending_session_acks[(target_name, session_id)] = aes_key
            self.session_confirmed[target_name] = False
            sig_bytes = build_session_offer_sig_bytes(self.username, target_name, session_id, encrypted_key_b64)
            sig_b64 = b64e(rsa_sign_pss_sha256(self.my_private_key, sig_bytes))

            self.proto.send_session_offer(target_name, session_id, encrypted_key_b64, sig_b64)
            self.display_message(f"[SYSTEM] Đã gửi lời mời E2EE đến {target_name}.")
            # FIX: cập nhật header + enable Re-key nếu đang chat với user này
            self.ui(self.update_chat_header)


        except Exception as e:  # noqa: BLE001
            self.display_message(f"[ERROR] Lỗi khi bắt tay với {target_name}: {e}")

    def maybe_auto_rekey(self, target: str) -> None:
        """
        Auto re-key theo timer / message-count.
        Nhẹ: gửi SESSION_OFFER để đổi key cho các tin nhắn tiếp theo.
        Không block gửi tin nhắn hiện tại (vẫn dùng key cũ).
        """
        if not target or target in ("Broadcast", self.username):
            return
        if target not in self.session_keys:
            return
        if not self.session_confirmed.get(target, False):
            return
        if target not in self.user_directory:
            return
        if not self.proto:
            return

        now = time.time()
        last = self.last_rekey_time.get(target, 0)
        out_n = self.out_msg_count.get(target, 0)

        due_time = (last > 0) and ((now - last) >= REKEY_INTERVAL_SEC)
        due_msgs = out_n >= REKEY_AFTER_MSGS

        if not (due_time or due_msgs):
            return

        try:
            target_pubkey_obj = self.user_directory[target]
            aes_key = generate_aes_key()
            encrypted_aes_key = rsa_encrypt(aes_key, target_pubkey_obj)

            encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode("utf-8")
            session_id = uuid.uuid4().hex

            self.pending_session_acks[(target, session_id)] = aes_key
            self.session_confirmed[target] = False

            # Nếu bạn đã áp dụng patch SIGNATURE cho SESSION_OFFER:
            sig_bytes = build_session_offer_sig_bytes(self.username, target, session_id, encrypted_key_b64)
            sig_b64 = b64e(rsa_sign_pss_sha256(self.my_private_key, sig_bytes))
            self.proto.send_session_offer(target, session_id, encrypted_key_b64, sig_b64)

            self.display_message(f"[SYSTEM] Auto re-key triggered for {target} (time={due_time}, msgs={due_msgs}).")
        except Exception as e:
            self.display_message(f"[ERROR] Auto re-key failed for {target}: {e}")

    def rekey_current_session(self):
        """Đổi lại AES key cho phiên chat hiện tại (GUI-only)."""
        target = self.current_chat_partner

        if target == "Broadcast":
            self.display_message("[INFO] Không thể Re-key trong phòng Broadcast.")
            return

        if target == self.username:
            self.display_message("[ERROR] Không thể Re-key với chính mình.")
            return

        if target not in self.user_directory:
            self.display_message(f"[ERROR] Không tìm thấy public key của {target}.")
            return

        if not self.client_socket:
            self.display_message("[ERROR] Chưa kết nối server.")
            return

        try:
            target_pubkey_obj = self.user_directory[target]
            aes_key = generate_aes_key()
            encrypted_aes_key = rsa_encrypt(aes_key, target_pubkey_obj)
            self.session_keys[target] = aes_key  # cập nhật key mới

            encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode("utf-8")
            session_id = uuid.uuid4().hex
            self.pending_session_acks[(target, session_id)] = aes_key
            self.session_confirmed[target] = False
            sig_bytes = build_session_offer_sig_bytes(self.username, target, session_id, encrypted_key_b64)
            sig_b64 = b64e(rsa_sign_pss_sha256(self.my_private_key, sig_bytes))
            self.proto.send_session_offer(target, session_id, encrypted_key_b64, sig_b64)

            self.display_message(f"[SYSTEM] Đã Re-key E2EE với {target}.")
            # Sau khi re-key, chắc chắn đang có khóa
            self.ui(self.update_chat_header)


        except Exception as e:  # noqa: BLE001
            self.display_message(f"[ERROR] Lỗi khi Re-key với {target}: {e}")

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
