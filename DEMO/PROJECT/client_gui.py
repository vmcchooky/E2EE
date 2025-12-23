import socket
import threading
import customtkinter as ctk
import base64
from datetime import datetime
from tkinter import messagebox
from protocol import ProtoError

import queue

import os
import json
import uuid
import ssl
import time
from typing import Optional, Dict, Any, List, Tuple

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
    TYPE_USER_ANNOUNCE, TYPE_SESSION_OFFER, TYPE_SESSION_ACK, TYPE_PRIVATE_MSG, TYPE_DIRECT_MSG, TYPE_BROADCAST
)

from transport import ProtoClient

REKEY_INTERVAL_SEC = 20 * 60   # 20 phút
REKEY_AFTER_MSGS = 50          # sau 50 tin nhắn outbound với 1 peer thì re-key

# Cấu hình giao diện chung
ctk.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

def _err_text(m: dict) -> str:
    payload = (m or {}).get("payload") or {}
    return payload.get("message") or payload.get("reason") or str(payload) or "Unknown error"

class ChatApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")  # "dark" | "light" | "system"
        ctk.set_default_color_theme("blue")

        self.title("Secure Chat E2EE")
        self.geometry("1100x720")
        self.minsize(980, 640)

        # ===== State =====
        self.username = ""
        self.client_socket = None
        self.server_password = None

        # E2EE state
        self.user_directory = {}            # {name: public_key_bytes}
        self.session_keys = {}              # {name: aes_key}
        self.session_confirmed = {}         # {name: bool}
        self.pending_session_acks = {}     # {(name, session_id): aes_key}
        self.session_ids = {}               # {name: session_id}
        self.pending_session_keys = {}      # {name: aes_key}
        self.pending_session_ids = {}       # {name: session_id}
        self.session_offers = {}            # {name: {session_id, aes_key, timestamp}}
        self.known_keys = {}                # {name: fingerprint_str}
        self.peer_trust = {}
        self.pending_key_changes = {}  # peer -> {old_fp,new_fp,pubkey_bytes}
        self.pending_notices = {}      # peer -> [system message dict]
        self.notice_flags = set()      # peers with pending notices
        self.e2ee_enabled = {}         # peer -> bool (default False)
                # {name: "TOFU"|"VERIFIED"|"CHANGED"}

        self.send_ctr = {}                  # {name: int}
        self.recv_ctr = {}                  # {name: int}
        self.out_msg_count = {}             # {name: int}
        self.last_rekey_time = {}           # {name: float}

        self.current_chat_partner = "Broadcast"
        # ===== Thread-safe event queue (network thread -> UI thread) =====
        self._event_q: "queue.Queue[tuple[str, object]]" = queue.Queue()
        self._event_pump_ms = 60  # UI polling interval
        self.after(self._event_pump_ms, self._pump_events)
        # ===== UI state =====

        # UI conversation state
        self.chat_history = {"Broadcast": []}   # {conv_id: [message_dict]}
        self.unread = {"Broadcast": 0}
        self.conversation_widgets = {}          # {conv_id: {"root": frame, ...}}
        self.user_buttons = {}                  # kept for compatibility; maps to root frames

        # Known key cache
        self.known_keys_file = "FingerPrint/known_keys_gui.json"
        self.load_known_keys()

        # ===== Layout grid =====
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0)  # sidebar
        self.grid_columnconfigure(1, weight=1)  # main center
        self.grid_columnconfigure(2, weight=0)  # right info panel

        # ===== Sidebar =====
        self.sidebar = ctk.CTkFrame(self, width=320, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(3, weight=1)  # conversation list expands
        self.sidebar.grid_columnconfigure(0, weight=1)

        # Top user strip
        self.sb_top = ctk.CTkFrame(self.sidebar)
        self.sb_top.grid(row=0, column=0, padx=14, pady=(14, 10), sticky="ew")
        self.sb_top.grid_columnconfigure(0, weight=1)

        self.self_name_label = ctk.CTkLabel(
            self.sb_top,
            text="Chưa đăng nhập",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.self_name_label.grid(row=0, column=0, sticky="w")

        self.conn_status_label = ctk.CTkLabel(
            self.sb_top,
            text="Disconnected",
            font=ctk.CTkFont(size=12)
        )
        self.conn_status_label.grid(row=1, column=0, sticky="w", pady=(2, 0))

        self.connect_btn = ctk.CTkButton(
            self.sb_top,
            text="Connect",
            width=92,
            command=self.connect_server_dialog
        )
        self.connect_btn.grid(row=0, column=1, rowspan=2, padx=(10, 0), sticky="e")


        # Navigation (UI skeleton - chức năng sẽ bổ sung dần)
        self.nav_var = ctk.StringVar(value="Chats")
        self.nav = ctk.CTkSegmentedButton(
            self.sidebar,
            values=["Chats", "Contacts", "Groups", "Settings"],
            variable=self.nav_var,
            command=lambda _val: self._switch_nav_view()
        )
        self.nav.grid(row=1, column=0, padx=14, pady=(0, 10), sticky="ew")

        # Search
        self.search_var = ctk.StringVar(value="")
        self.search_entry = ctk.CTkEntry(
            self.sidebar,
            textvariable=self.search_var,
            placeholder_text="Tìm kiếm cuộc trò chuyện..."
        )
        self.search_entry.grid(row=2, column=0, padx=14, pady=(0, 10), sticky="ew")
        self.search_var.trace_add("write", lambda *_: self._apply_search_filter())

        # Conversation list
        self.scrollable_user_list = ctk.CTkScrollableFrame(
            self.sidebar,
            label_text="Chats"
        )
        self.scrollable_user_list.grid(row=3, column=0, padx=14, pady=(0, 10), sticky="nsew")

        # Placeholder view for non-chat sections (Contacts/Groups/Settings)
        self.nav_placeholder = ctk.CTkFrame(self.sidebar)
        self.nav_placeholder_label = ctk.CTkLabel(
            self.nav_placeholder,
            text="(Giao diện đã sẵn sàng — chức năng sẽ bổ sung dần)",
            font=ctk.CTkFont(size=12)
        )
        self.nav_placeholder_label.pack(padx=14, pady=14)

        self.nav_placeholder.grid(row=2, column=0, rowspan=2, padx=14, pady=(0, 10), sticky="nsew")
        self.nav_placeholder.grid_remove()  # chỉ hiện khi không ở Chats

        # Broadcast is always present
        self._ensure_conversation_tile("Broadcast", subtitle="Phòng chat chung", trust="")

        # Bottom actions
        self.sb_bottom = ctk.CTkFrame(self.sidebar)
        self.sb_bottom.grid(row=4, column=0, padx=14, pady=(0, 14), sticky="ew")
        self.sb_bottom.grid_columnconfigure((0, 1), weight=1)

        self.btn_my_fp = ctk.CTkButton(
            self.sb_bottom, text="My Fingerprint", command=self.show_self_fingerprint
        )
        self.btn_my_fp.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        self.btn_peer_fp = ctk.CTkButton(
            self.sb_bottom, text="Peer Fingerprint", command=self.show_partner_fingerprint
        )
        self.btn_peer_fp.grid(row=0, column=1, padx=(6, 0), sticky="ew")

        # ===== Main pane =====
        self.main = ctk.CTkFrame(self, corner_radius=0)
        self.main.grid(row=0, column=1, sticky="nsew")
        self.main.grid_rowconfigure(1, weight=1)
        self.main.grid_columnconfigure(0, weight=1)

        # ===== Right info panel (Messenger/Zalo style) =====
        self.right_panel_visible = True
        self.right_panel = ctk.CTkFrame(self, width=360, corner_radius=0)
        self.right_panel.grid(row=0, column=2, sticky="nsew")
        self.right_panel.grid_rowconfigure(1, weight=1)
        self.right_panel.grid_columnconfigure(0, weight=1)

        self.rp_title = ctk.CTkLabel(
            self.right_panel,
            text="Conversation",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.rp_title.grid(row=0, column=0, padx=14, pady=(14, 10), sticky="w")

        self.rp_tabs = ctk.CTkTabview(self.right_panel)
        self.rp_tabs.grid(row=1, column=0, padx=14, pady=(0, 14), sticky="nsew")

        self.tab_info = self.rp_tabs.add("Info")
        self.tab_security = self.rp_tabs.add("Security")
        self.tab_activity = self.rp_tabs.add("Activity")

        # ---- Info tab ----
        self.tab_info.grid_columnconfigure(0, weight=1)

        self.info_peer_name = ctk.CTkLabel(self.tab_info, text="Peer: (none)", font=ctk.CTkFont(size=14, weight="bold"))
        self.info_peer_name.grid(row=0, column=0, sticky="w", padx=10, pady=(10, 4))

        self.info_peer_meta = ctk.CTkLabel(self.tab_info, text="Status: -", font=ctk.CTkFont(size=12))
        self.info_peer_meta.grid(row=1, column=0, sticky="w", padx=10)

        self.info_session = ctk.CTkLabel(self.tab_info, text="E2EE: -", font=ctk.CTkFont(size=12))
        self.info_session.grid(row=2, column=0, sticky="w", padx=10, pady=(4, 0))

        self.info_fingerprint = ctk.CTkLabel(self.tab_info, text="Fingerprint: -", font=ctk.CTkFont(size=12))
        self.info_fingerprint.grid(row=3, column=0, sticky="w", padx=10, pady=(4, 10))

        self.info_actions = ctk.CTkFrame(self.tab_info)
        self.info_actions.grid(row=4, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.info_actions.grid_columnconfigure((0, 1), weight=1)

        self.btn_verify = ctk.CTkButton(self.info_actions, text="Mark Verified", command=self.mark_current_peer_verified)
        self.btn_verify.grid(row=0, column=0, padx=(0, 6), pady=8, sticky="ew")

        self.btn_clear_chat = ctk.CTkButton(self.info_actions, text="Clear Chat", command=self.clear_current_chat_ui)
        self.btn_clear_chat.grid(row=0, column=1, padx=(6, 0), pady=8, sticky="ew")

        self.btn_accept_key = ctk.CTkButton(self.info_actions, text="Accept New Key", command=self.accept_pending_key_for_current_peer)
        self.btn_accept_key.grid(row=1, column=0, columnspan=2, padx=0, pady=(0, 8), sticky="ew")
        self.btn_accept_key.configure(state="disabled")

        self.info_more = ctk.CTkFrame(self.tab_info)
        self.info_more.grid(row=5, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.info_more.grid_columnconfigure((0, 1), weight=1)

        self.btn_rekey_side = ctk.CTkButton(self.info_more, text="Re-key", command=self.rekey_current_session)
        self.btn_rekey_side.grid(row=0, column=0, padx=(0, 6), pady=8, sticky="ew")

        self.btn_export = ctk.CTkButton(self.info_more, text="Export (Soon)", command=lambda: self.log_status("Export: chưa triển khai", level="INFO"))
        self.btn_export.grid(row=0, column=1, padx=(6, 0), pady=8, sticky="ew")

        self.switch_e2ee = ctk.CTkSwitch(self.info_more, text="E2EE (this chat)", command=self.on_toggle_e2ee)
        self.switch_e2ee.grid(row=1, column=0, columnspan=2, padx=6, pady=(0, 8), sticky="w")
        self.switch_e2ee.deselect()

        # ---- Security tab (self-check dashboard) ----
        self.tab_security.grid_columnconfigure(0, weight=1)

        self.sec_summary = ctk.CTkLabel(self.tab_security, text="Self-check: chưa chạy", font=ctk.CTkFont(size=12))
        self.sec_summary.grid(row=0, column=0, sticky="w", padx=10, pady=(10, 6))

        self.sec_checks_frame = ctk.CTkFrame(self.tab_security, fg_color="transparent")
        self.sec_checks_frame.grid(row=1, column=0, sticky="nsew", padx=10)
        self.sec_checks_frame.grid_columnconfigure(0, weight=1)

        self.sec_rows = {}  # key -> (label_name, label_value)
        for i, key in enumerate(["TLS", "Identity", "E2EE", "Anti-replay", "Key store", "Re-key policy"]):
            name_lbl = ctk.CTkLabel(self.sec_checks_frame, text=key, font=ctk.CTkFont(size=12, weight="bold"))
            val_lbl = ctk.CTkLabel(self.sec_checks_frame, text="-", font=ctk.CTkFont(size=12))
            name_lbl.grid(row=i, column=0, sticky="w", pady=4)
            val_lbl.grid(row=i, column=1, sticky="e", pady=4)
            self.sec_rows[key] = (name_lbl, val_lbl)

        self.sec_btn_frame = ctk.CTkFrame(self.tab_security, fg_color="transparent")
        self.sec_btn_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=(10, 10))
        self.sec_btn_frame.grid_columnconfigure((0, 1), weight=1)

        self.btn_run_check = ctk.CTkButton(self.sec_btn_frame, text="Run Self-check", command=self.run_self_check)
        self.btn_run_check.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        self.btn_dev_mode = ctk.CTkButton(self.sec_btn_frame, text="Open Activity", command=lambda: self.rp_tabs.set("Activity"))
        self.btn_dev_mode.grid(row=0, column=1, padx=(6, 0), sticky="ew")

        # ---- Activity tab (status/notifications area) ----
        self.tab_activity.grid_rowconfigure(1, weight=1)
        self.tab_activity.grid_columnconfigure(0, weight=1)

        self.act_hint = ctk.CTkLabel(
            self.tab_activity,
            text="Trạng thái / Thông báo hệ thống (giảm rối trong khung chat)",
            font=ctk.CTkFont(size=12)
        )
        self.act_hint.grid(row=0, column=0, sticky="w", padx=10, pady=(10, 6))

        self.status_text = ctk.CTkTextbox(self.tab_activity, height=260)
        self.status_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.status_text.configure(state="disabled")

        self.act_btns = ctk.CTkFrame(self.tab_activity, fg_color="transparent")
        self.act_btns.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.act_btns.grid_columnconfigure((0, 1), weight=1)

        self.btn_clear_log = ctk.CTkButton(self.act_btns, text="Clear Log", command=self.clear_status_log)
        self.btn_clear_log.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        self.btn_toggle_info = ctk.CTkButton(self.act_btns, text="Hide Panel", command=self.toggle_right_panel)
        self.btn_toggle_info.grid(row=0, column=1, padx=(6, 0), sticky="ew")

        # Header
        self.chat_header_frame = ctk.CTkFrame(self.main)
        self.chat_header_frame.grid(row=0, column=0, padx=16, pady=(14, 10), sticky="ew")
        self.chat_header_frame.grid_columnconfigure(0, weight=1)

        self.chat_title_label = ctk.CTkLabel(
            self.chat_header_frame,
            text="Chat chung (Broadcast)",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.chat_title_label.grid(row=0, column=0, sticky="w")

        self.badges_frame = ctk.CTkFrame(self.chat_header_frame, fg_color="transparent")
        self.badges_frame.grid(row=1, column=0, sticky="w", pady=(6, 0))

        self.badge_tls = ctk.CTkLabel(self.badges_frame, text="TLS: OFF", font=ctk.CTkFont(size=12))
        self.badge_tls.grid(row=0, column=0, padx=(0, 10), sticky="w")

        self.badge_e2ee = ctk.CTkLabel(self.badges_frame, text="E2EE: N/A", font=ctk.CTkFont(size=12))
        self.badge_e2ee.grid(row=0, column=1, padx=(0, 10), sticky="w")

        self.badge_id = ctk.CTkLabel(self.badges_frame, text="Identity: N/A", font=ctk.CTkFont(size=12))
        self.badge_id.grid(row=0, column=2, sticky="w")

        self.rekey_button = ctk.CTkButton(
            self.chat_header_frame,
            text="Re-key",
            width=90,
            command=self.rekey_current_session
        )
        self.rekey_button.grid(row=0, column=1, rowspan=2, padx=(10, 0), sticky="e")
        self.rekey_button.configure(state="disabled")

        # Header actions (UI skeleton)
        self.header_actions = ctk.CTkFrame(self.chat_header_frame, fg_color="transparent")
        self.header_actions.grid(row=0, column=2, rowspan=2, padx=(10, 0), sticky="e")

        self.btn_call = ctk.CTkButton(self.header_actions, text="Call", width=70, command=lambda: self.log_status("Call: chưa triển khai", level="INFO"))
        self.btn_call.grid(row=0, column=0, padx=(0, 6))

        self.btn_video = ctk.CTkButton(self.header_actions, text="Video", width=70, command=lambda: self.log_status("Video: chưa triển khai", level="INFO"))
        self.btn_video.grid(row=0, column=1, padx=(0, 6))

        self.btn_info = ctk.CTkButton(self.header_actions, text="Info", width=70, command=self.toggle_right_panel)
        self.btn_info.grid(row=0, column=2)

        # Messages
        self.message_area = ctk.CTkScrollableFrame(self.main, label_text="")
        self.message_area.grid(row=1, column=0, padx=16, pady=(0, 10), sticky="nsew")
        self.message_area.grid_columnconfigure(0, weight=1)

        self._msg_row = 0

        # Composer
        self.input_frame = ctk.CTkFrame(self.main)
        self.input_frame.grid(row=2, column=0, padx=16, pady=(0, 14), sticky="ew")
        self.input_frame.grid_columnconfigure(1, weight=1)

        self.attach_btn = ctk.CTkButton(self.input_frame, text="+", width=42, command=lambda: None)
        self.attach_btn.grid(row=0, column=0, padx=(10, 8), pady=10)

        self.entry_message = ctk.CTkEntry(self.input_frame, placeholder_text="Nhập tin nhắn...")
        self.entry_message.grid(row=0, column=1, padx=(0, 8), pady=10, sticky="ew")
        self.entry_message.bind("<Return>", lambda e: (self.send_message_event(), "break"))

        self.send_button = ctk.CTkButton(self.input_frame, text="Send", width=90, command=self.send_message_event)
        self.send_button.grid(row=0, column=2, padx=(0, 10), pady=10, sticky="e")

        # First header render
        self.update_chat_header()
        self.update_right_panel()

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
    
    def post_event(self, kind: str, payload: object = None) -> None:
        """Thread-safe: may be called from any thread."""
        try:
            self._event_q.put((kind, payload))
        except Exception:
            pass

    def _pump_events(self) -> None:
        """Runs on UI thread; drains queued events and dispatches handlers."""
        try:
            processed = 0
            max_per_tick = 200  # prevent UI starvation
            while processed < max_per_tick:
                try:
                    kind, payload = self._event_q.get_nowait()
                except queue.Empty:
                    break

                try:
                    if kind == "NET_MSG":
                        # All UI updates now happen on the UI thread.
                        self.process_incoming_message(payload)  # payload is dict
                    elif kind == "NET_ERR":
                        self.log_status(f"Receive loop stopped: {payload}", level="ERROR")
                    elif kind == "CONN_UI":
                        state, detail = payload  # ("CONNECTED"/"DISCONNECTED", str)
                        self._set_connection_ui(state, detail)
                    elif kind == "STATUS":
                        # payload = {"text": str, "level": "..."}
                        if isinstance(payload, dict):
                            self.log_status(str(payload.get("text", "")),
                                            level=str(payload.get("level", "INFO")))
                        else:
                            self.log_status(str(payload), level="INFO")
                    else:
                        self.log_status(f"Unknown event: {kind}", level="WARN")
                except Exception as e:
                    # Never crash the pump
                    try:
                        self.log_status(f"Event handler error ({kind}): {e}", level="ERROR")
                    except Exception:
                        pass

                processed += 1
        finally:
            # Reschedule if window still exists
            try:
                if self.winfo_exists():
                    self.after(self._event_pump_ms, self._pump_events)
            except Exception:
                pass

    def _switch_nav_view(self):
        """UI only: chuyển giữa Chats/Contacts/Groups/Settings (chức năng sẽ bổ sung dần)."""
        mode = (self.nav_var.get() if hasattr(self, "nav_var") else "Chats") or "Chats"
        if mode == "Chats":
            try:
                self.nav_placeholder.grid_remove()
            except Exception:
                pass
            try:
                self.search_entry.grid()
                self.scrollable_user_list.grid()
            except Exception:
                pass
        else:
            # Hide chat widgets to reduce visual noise
            try:
                self.search_entry.grid_remove()
                self.scrollable_user_list.grid_remove()
            except Exception:
                pass
            try:
                self.nav_placeholder_label.configure(
                    text=f"{mode}: giao diện đã sẵn sàng — chức năng sẽ bổ sung dần"
                )
                self.nav_placeholder.grid()
            except Exception:
                pass

    def toggle_right_panel(self):
        """Ẩn/hiện cột phải (Conversation/Info/Security/Activity)."""
        try:
            if self.right_panel_visible:
                self.right_panel.grid_remove()
                self.right_panel_visible = False
                try:
                    self.btn_toggle_info.configure(text="Show Panel")
                except Exception:
                    pass
                try:
                    self.btn_info.configure(text="Info")
                except Exception:
                    pass
            else:
                self.right_panel.grid()
                self.right_panel_visible = True
                try:
                    self.btn_toggle_info.configure(text="Hide Panel")
                except Exception:
                    pass
        except Exception:
            pass

    def clear_status_log(self):
        try:
            self.status_text.configure(state="normal")
            self.status_text.delete("1.0", "end")
            self.status_text.configure(state="disabled")
        except Exception:
            pass

    def log_status(self, text: str, level: str = "INFO"):
        """Ghi thông báo trạng thái vào Activity tab (thread-safe)."""
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {level}: {text}\n"
        self.ui(self._append_status_line, line)

    def _append_status_line(self, line: str):
        try:
            self.status_text.configure(state="normal")
            self.status_text.insert("end", line)
            self.status_text.see("end")
            self.status_text.configure(state="disabled")
        except Exception:
            # Nếu UI chưa dựng xong, fallback: ignore
            pass

    def clear_current_chat_ui(self):
        """Chỉ clear UI history phía client (không ảnh hưởng server)."""
        cid = self.current_chat_partner or "Broadcast"
        self.chat_history[cid] = []
        self.unread[cid] = 0
        self._refresh_conversation_tile(cid)
        if cid == self.current_chat_partner:
            self._render_conversation(cid)
        self.log_status(f"Cleared local chat history: {cid}", level="OK")
        self.update_right_panel()

    def on_toggle_e2ee(self):
        peer = self.current_chat_partner
        if not peer or peer == "Broadcast":
            return
        enabled = bool(self.switch_e2ee.get())
        self.e2ee_enabled[peer] = enabled
        if not enabled:
            self._queue_security_notice(peer, "[SYSTEM] Bạn đang chat plaintext (E2EE OFF).")
            self.update_chat_header()
            self.update_right_panel()
            return

        # Enabling E2EE
        if peer in self.pending_key_changes:
            self._queue_security_notice(
                peer,
                "[SECURITY] Identity của peer đã thay đổi. Hãy Accept New Key sau khi xác minh fingerprint, rồi bật E2EE."
            )
            self.e2ee_enabled[peer] = False
            try:
                self.switch_e2ee.deselect()
            except Exception:
                pass
            self.update_chat_header()
            self.update_right_panel()
            return

        self._queue_security_notice(peer, "[SYSTEM] Đang bật E2EE cho cuộc trò chuyện này…")
        if peer not in self.session_keys or not self.session_confirmed.get(peer, False):
            self.perform_handshake(peer)
        self.update_chat_header()
        self.update_right_panel()

    def mark_current_peer_verified(self):
        """Đánh dấu peer hiện tại là VERIFIED (local trust)."""
        peer = self.current_chat_partner
        if not peer or peer == "Broadcast":
            self.log_status("Không thể verify Broadcast.", level="WARN")
            return
        # Chỉ cho verify khi đã có fingerprint
        fp = self.known_keys.get(peer)
        if not fp:
            self.log_status(f"Chưa có fingerprint cho {peer}.", level="WARN")
            return
        self.peer_trust[peer] = "VERIFIED"
        self._refresh_conversation_tile(peer)
        self.update_chat_header()
        self.update_right_panel()
        self.log_status(f"Marked {peer} as VERIFIED (local).", level="OK")

    def _mask_fp(self, fp: str) -> str:
        if not fp:
            return "-"
        raw = fp.replace(" ", "").strip()
        if len(raw) <= 12:
            return self.format_fingerprint(raw)
        return self.format_fingerprint(raw[:8] + "…" + raw[-8:])


    def update_right_panel(self):
        if threading.current_thread() is not threading.main_thread():
            self.ui(self.update_right_panel)
            return
        """Cập nhật Info/Security panel theo cuộc hội thoại hiện tại."""
        peer = self.current_chat_partner or "Broadcast"
        try:
            self.rp_title.configure(text="Conversation" if peer == "Broadcast" else f"Conversation: {peer}")
        except Exception:
            pass

        if peer == "Broadcast":
            try:
                self.info_peer_name.configure(text="Peer: Broadcast")
                self.info_peer_meta.configure(text="Status: room")
                self.info_session.configure(text="E2EE: OFF")
                self.info_fingerprint.configure(text="Fingerprint: -")
                self.btn_verify.configure(state="disabled")
                self.btn_rekey_side.configure(state="disabled")
                self.btn_accept_key.configure(state="disabled")
                try:
                    self.switch_e2ee.deselect()
                    self.switch_e2ee.configure(state="disabled")
                except Exception:
                    pass
            except Exception:
                pass
            self.run_self_check(silent=True)
            return

        trust = self.peer_trust.get(peer, "TOFU")
        fp = self.known_keys.get(peer)
        enabled = bool(self.e2ee_enabled.get(peer, False))

        if not enabled:
            e2ee = "OFF (Plaintext)"
        else:
            if peer in self.session_keys:
                e2ee = "ON" if self.session_confirmed.get(peer, False) else "NEGOTIATING"
            else:
                e2ee = "SETUP"

        try:
            self.info_peer_name.configure(text=f"Peer: {peer}")
            self.info_peer_meta.configure(text=f"Identity: {trust}")
            self.info_session.configure(text=f"E2EE: {e2ee}")
            self.info_fingerprint.configure(text=f"Fingerprint: {self._mask_fp(fp)}")
            self.btn_verify.configure(state="normal" if fp else "disabled")

            # Re-key only relevant when E2EE enabled and key exists
            self.btn_rekey_side.configure(state="normal" if (enabled and peer in self.session_keys) else "disabled")

            # Switch state
            try:
                if enabled:
                    self.switch_e2ee.select()
                else:
                    self.switch_e2ee.deselect()
                self.switch_e2ee.configure(state="normal")
            except Exception:
                pass

            # Accept key button appears only when pending change exists
            self.btn_accept_key.configure(state="normal" if peer in self.pending_key_changes else "disabled")

        except Exception:
            pass

        self.run_self_check(silent=True)

    def _set_sec_row(self, key: str, value: str):
        row = self.sec_rows.get(key)
        if not row:
            return
        try:
            row[1].configure(text=value)
        except Exception:
            pass

    def _queue_security_notice(self, peer: str, text: str) -> None:
        """Queue a security/system notice for a specific peer.

        Requirement:
        - Do NOT show popups.
        - Only show the notice inside that peer's chat thread.
        - If the user is currently viewing that peer, show immediately.
        - Otherwise, defer until the user opens that conversation.
        """
        if not peer or peer == "Broadcast":
            return

        msg = {"kind": "system", "direction": "in", "text": text, "meta": ""}

        # If the conversation is currently open, render immediately.
        if self.current_chat_partner == peer:
            self._append_message(peer, msg, bump_unread_if_inactive=False)
            self._render_conversation(peer)
            self._refresh_conversation_tile(peer)
            return

        # Otherwise, defer until the user opens that chat.
        self.pending_notices.setdefault(peer, []).append(msg)
        self.notice_flags.add(peer)
        self._refresh_conversation_tile(peer)

    def _flush_security_notices_if_any(self, peer: str) -> None:
        notes = self.pending_notices.get(peer) or []
        if not notes:
            return
        # append to chat history only when user opens that conversation
        for n in notes:
            self._append_message(peer, n, bump_unread_if_inactive=False)
        self.pending_notices[peer] = []
        if peer in self.notice_flags:
            self.notice_flags.remove(peer)
        self._refresh_conversation_tile(peer)
        if self.current_chat_partner == peer:
            self._render_conversation(peer)

    def accept_pending_key_for_current_peer(self):
        peer = self.current_chat_partner
        if not peer or peer == "Broadcast":
            self.log_status("No peer selected.", level="WARN")
            return
        pend = self.pending_key_changes.get(peer)
        if not pend:
            self.log_status("No pending key change for this peer.", level="INFO")
            return
        try:
            pubkey_bytes = pend["pubkey_bytes"]
            new_fp = pend["new_fp"]
            self.known_keys[peer] = new_fp
            self.save_known_keys()
            self.user_directory[peer] = load_public_key_from_bytes(pubkey_bytes)
            # after accepting, treat as TOFU until user verifies out-of-band
            self.peer_trust[peer] = "TOFU"
            self.session_keys.pop(peer, None)
            self.session_confirmed.pop(peer, None)
            self.send_ctr.pop(peer, None)
            self.recv_ctr.pop(peer, None)
            self.out_msg_count.pop(peer, None)
            self.last_rekey_time.pop(peer, None)
            self.pending_key_changes.pop(peer, None)
            self._queue_security_notice(peer, f"[SECURITY] Bạn đã chấp nhận public key mới của {peer}.\n" "Phiên E2EE cũ đã bị hủy.\n" "Hãy xác minh fingerprint ngoài kênh để đánh dấu Verified.")
            self.update_right_panel()
            self.update_chat_header()
            self.log_status(f"Accepted new key for {peer}.", level="OK")
        except Exception as e:
            self.log_status(f"Accept key failed: {e}", level="ERROR")

    def run_self_check(self, silent: bool = False):
        """Self-check nhanh: chỉ hiển thị trạng thái, không lộ key thô."""
        peer = self.current_chat_partner or "Broadcast"
        issues = []

        tls_on = bool(self.client_socket)
        self._set_sec_row("TLS", "ON" if tls_on else "OFF")
        if not tls_on:
            issues.append("TLS is OFF")

        if peer == "Broadcast":
            self._set_sec_row("Identity", "N/A")
            self._set_sec_row("E2EE", "OFF")
            self._set_sec_row("Anti-replay", "N/A")
            self._set_sec_row("Key store", "OK" if isinstance(self.known_keys, dict) else "ERROR")
            self._set_sec_row("Re-key policy", f"{REKEY_INTERVAL_SEC//60}m / {REKEY_AFTER_MSGS} msgs")
        else:
            trust = self.peer_trust.get(peer, "TOFU")
            self._set_sec_row("Identity", trust)
            if trust == "CHANGED":
                issues.append(f"Identity changed for {peer}")

            enabled = self.e2ee_enabled.get(peer, False)
            e2ee_state = "OFF (Plaintext)" if not enabled else "OFF"
            if enabled and peer in self.session_keys:
                e2ee_state = "ON" if self.session_confirmed.get(peer, False) else "NEGOTIATING"
            self._set_sec_row("E2EE", e2ee_state)
            if e2ee_state != "ON":
                issues.append(f"E2EE not confirmed with {peer}")

            # Anti-replay / counters
            sc = int(self.send_ctr.get(peer, 0))
            rc = int(self.recv_ctr.get(peer, 0))
            self._set_sec_row("Anti-replay", f"send_ctr={sc}, recv_ctr={rc}")

            # Key store
            fp = self.known_keys.get(peer)
            self._set_sec_row("Key store", "OK" if fp else "MISSING")
            if not fp:
                issues.append(f"No stored fingerprint for {peer}")

            # Rekey policy status
            last = self.last_rekey_time.get(peer)
            if last:
                age_min = int((time.time() - float(last)) / 60)
                self._set_sec_row("Re-key policy", f"age={age_min}m, out_msgs={int(self.out_msg_count.get(peer, 0))}")
            else:
                self._set_sec_row("Re-key policy", f"out_msgs={int(self.out_msg_count.get(peer, 0))} (no rekey yet)")

        if issues:
            msg = f"Self-check: {len(issues)} cảnh báo"
            try:
                self.sec_summary.configure(text=msg)
            except Exception:
                pass
            if not silent:
                for it in issues[:5]:
                    self.log_status(it, level="WARN")
        else:
            try:
                self.sec_summary.configure(text="Self-check: OK")
            except Exception:
                pass
            if not silent:
                self.log_status("Self-check OK", level="OK")

    # ===== UI helpers (modern layout) =====

    def _set_connection_ui(self, status: str, detail: Optional[str] = None):
        # status: "DISCONNECTED"|"CONNECTING"|"CONNECTED"
        if status == "CONNECTED":
            self.conn_status_label.configure(text="Connected (TLS)")
            self.badge_tls.configure(text="TLS: ON")
            self.connect_btn.configure(state="disabled")
        elif status == "CONNECTING":
            self.conn_status_label.configure(text="Connecting...")
            self.badge_tls.configure(text="TLS: ...")
            self.connect_btn.configure(state="disabled")
        else:
            self.conn_status_label.configure(text=f"Disconnected{': ' + detail if detail else ''}")
            self.badge_tls.configure(text="TLS: OFF")
            self.connect_btn.configure(state="normal")

    def _apply_search_filter(self):
        query = (self.search_var.get() or "").strip().lower()
        for conv_id, w in self.conversation_widgets.items():
            title = (w.get("title_text") or "").lower()
            visible = (query == "") or (query in title)
            try:
                if visible:
                    w["root"].pack(fill="x", padx=6, pady=4)
                else:
                    w["root"].pack_forget()
            except Exception:
                pass

    def _ensure_conversation_tile(self, conv_id: str, subtitle: str = "", trust: str = ""):
        if conv_id not in self.chat_history:
            self.chat_history[conv_id] = []
        if conv_id not in self.unread:
            self.unread[conv_id] = 0

        if conv_id in self.conversation_widgets:
            # update subtitle if provided
            if subtitle:
                self.conversation_widgets[conv_id]["subtitle"].configure(text=subtitle)
            return

        root = ctk.CTkFrame(self.scrollable_user_list)
        root.pack(fill="x", padx=6, pady=4)

        root.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(root, text=conv_id, font=ctk.CTkFont(size=14, weight="bold"))
        title.grid(row=0, column=0, sticky="w", padx=10, pady=(8, 0))

        sub = ctk.CTkLabel(root, text=subtitle, font=ctk.CTkFont(size=12))
        sub.grid(row=1, column=0, sticky="w", padx=10, pady=(0, 8))

        right = ctk.CTkFrame(root, fg_color="transparent")
        right.grid(row=0, column=1, rowspan=2, sticky="e", padx=10)

        badge = ctk.CTkLabel(right, text=trust, font=ctk.CTkFont(size=11))
        badge.grid(row=0, column=0, sticky="e")

        unread = ctk.CTkLabel(right, text="", font=ctk.CTkFont(size=11))
        unread.grid(row=1, column=0, sticky="e", pady=(4, 0))

        def _select(_evt=None, cid=conv_id):
            if cid == "Broadcast":
                self.select_broadcast()
            else:
                self.select_chat_partner(cid)

        for widget in (root, title, sub, right, badge, unread):
            widget.bind("<Button-1>", _select)

        self.conversation_widgets[conv_id] = {
            "root": root,
            "title": title,
            "subtitle": sub,
            "badge": badge,
            "unread": unread,
            "title_text": conv_id,
        }
        # keep compatibility with existing naming
        self.user_buttons[conv_id] = root

        self._refresh_conversation_tile(conv_id)

    def _refresh_conversation_tile(self, conv_id: str):
        w = self.conversation_widgets.get(conv_id)
        if not w:
            return
        # pending security notices indicator
        try:
            w["title"].configure(text=(f"⚠ {conv_id}" if conv_id in self.notice_flags else conv_id))
        except Exception:
            pass
        # subtitle from last message
        hist = self.chat_history.get(conv_id, [])
        if hist:
            last = hist[-1]
            preview = last.get("text", "")
            preview = preview.replace("\n", " ")
            if len(preview) > 40:
                preview = preview[:40] + "…"
            w["subtitle"].configure(text=preview)
        # unread
        u = int(self.unread.get(conv_id, 0))
        w["unread"].configure(text=f"{u} mới" if u > 0 else "")
        # trust badge
        if conv_id not in ("Broadcast", ""):
            t = self.peer_trust.get(conv_id, "TOFU")
            w["badge"].configure(text=t)
        else:
            w["badge"].configure(text="")

    def _clear_message_area(self):
        for child in self.message_area.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        self._msg_row = 0

    def _render_conversation(self, conv_id: str):
        self._clear_message_area()
        for msg in self.chat_history.get(conv_id, []):
            self._render_message_bubble(msg)
        self._scroll_to_bottom()

    def _scroll_to_bottom(self):
        # CustomTkinter internal canvas; best-effort
        try:
            self.update_idletasks()
            canvas = getattr(self.message_area, "_parent_canvas", None)
            if canvas is not None:
                canvas.yview_moveto(1.0)
        except Exception:
            pass

    def _render_message_bubble(self, msg: dict):
        kind = msg.get("kind", "chat")  # "chat"|"system"
        direction = msg.get("direction", "in")  # "in"|"out"
        text = msg.get("text", "")
        meta = msg.get("meta", "")

        row = ctk.CTkFrame(self.message_area, fg_color="transparent")
        row.grid(row=self._msg_row, column=0, sticky="ew", pady=4, padx=6)
        row.grid_columnconfigure(0, weight=1)
        row.grid_columnconfigure(1, weight=1)

        if kind == "system":
            bubble = ctk.CTkFrame(row)
            bubble.grid(row=0, column=0, columnspan=2, sticky="ew", padx=120)
            label = ctk.CTkLabel(bubble, text=text, justify="center", wraplength=600)
            label.pack(padx=12, pady=(8, 2))
            if meta:
                meta_lbl = ctk.CTkLabel(bubble, text=meta, font=ctk.CTkFont(size=11))
                meta_lbl.pack(padx=12, pady=(0, 8))
        else:
            bubble = ctk.CTkFrame(row)
            col = 1 if direction == "out" else 0
            sticky = "e" if direction == "out" else "w"
            bubble.grid(row=0, column=col, sticky=sticky, padx=10)
            label = ctk.CTkLabel(bubble, text=text, justify="left", wraplength=560)
            label.pack(padx=12, pady=(8, 2))
            meta_text = meta
            if meta_text:
                meta_lbl = ctk.CTkLabel(bubble, text=meta_text, font=ctk.CTkFont(size=11))
                meta_lbl.pack(padx=12, pady=(0, 8))

        self._msg_row += 1

    def _append_message(self, conv_id: str, msg: dict, bump_unread_if_inactive: bool = True):
        if conv_id not in self.chat_history:
            self.chat_history[conv_id] = []
        self.chat_history[conv_id].append(msg)

        # Ensure tile exists for peer convs
        if conv_id != "Broadcast":
            self._ensure_conversation_tile(conv_id)

        if conv_id != self.current_chat_partner and bump_unread_if_inactive:
            self.unread[conv_id] = int(self.unread.get(conv_id, 0)) + 1
        else:
            self.unread[conv_id] = 0

        self._refresh_conversation_tile(conv_id)

        if conv_id == self.current_chat_partner:
            self._render_message_bubble(msg)
            self._scroll_to_bottom()

    def add_system_message(self, text: str, conv_id: Optional[str] = None):
        conv = conv_id or self.current_chat_partner
        ts = datetime.now().strftime("%H:%M")

        # marshal về UI thread
        self.ui(self._append_message, conv, {"kind": "system", "text": text, "meta": ts}, False)

    def add_incoming_message(self, sender: str, text: str, encrypted: bool = False, conv_id: Optional[str] = None):
        conv = conv_id or sender
        ts = datetime.now().strftime("%H:%M")
        meta = f"{ts}" + (" • 🔒" if encrypted else "")
        self._append_message(conv, {"kind": "chat", "direction": "in", "text": text, "meta": meta})

    def add_outgoing_message(self, target: str, text: str, encrypted: bool = False, conv_id: Optional[str] = None):
        conv = conv_id or target
        ts = datetime.now().strftime("%H:%M")
        meta = f"{ts}" + (" • 🔒" if encrypted else "")
        self._append_message(conv, {"kind": "chat", "direction": "out", "text": text, "meta": meta},
                            bump_unread_if_inactive=False)

    def ask_yesno_threadsafe(self, title: str, message: str) -> bool:
        """
        Hiển thị messagebox.askyesno an toàn thread.
        Thread receive sẽ chờ kết quả, UI không bị crash.
        """
        # import threading
        # from tkinter import messagebox

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
        if threading.current_thread() is not threading.main_thread():
            self.ui(self.update_chat_header)
            return
        """Cập nhật tiêu đề khung chat + badges + trạng thái nút Re-key."""
        partner = self.current_chat_partner

        # TLS badge
        tls_on = self.client_socket is not None
        self.badge_tls.configure(text=f"TLS: {'ON' if tls_on else 'OFF'}")

        if partner == "Broadcast":
            self.chat_title_label.configure(text="Chat chung (Broadcast)")
            self.rekey_button.configure(state="disabled")
            self.badge_e2ee.configure(text="E2EE: OFF")
            self.badge_id.configure(text="Identity: N/A")
            self.update_right_panel()
            return

        # Private chat
        trust = self.peer_trust.get(partner, "TOFU")
        self.badge_id.configure(text=f"Identity: {trust}")

        if partner in self.session_keys:
            confirmed = self.session_confirmed.get(partner, False)
            if confirmed:
                self.chat_title_label.configure(text=f"Chat với: {partner} (🔒)")
                self.badge_e2ee.configure(text="E2EE: ON")
            else:
                self.chat_title_label.configure(text=f"Chat với: {partner} (🔒 đang xác nhận...)")
                self.badge_e2ee.configure(text="E2EE: NEGOTIATING")
            self.rekey_button.configure(state="normal")
        else:
            self.chat_title_label.configure(text=f"Chat với: {partner} (đang thiết lập khóa...)")
            self.badge_e2ee.configure(text="E2EE: SETUP")
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
            self.ui(self._set_connection_ui, "CONNECTING")
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # TLS verify server cert
            base_dir = os.path.dirname(os.path.abspath(__file__))
            cafile = os.path.normpath(os.path.join(base_dir, "..", "certs", "server_cert.pem"))
            context = ssl.create_default_context(cafile=cafile)
            # (mặc định check_hostname=True trong create_default_context)
            tls_sock = context.wrap_socket(raw, server_hostname="SecureChatDev")
            tls_sock.connect((HOST, PORT))

            # Lưu socket đúng biến, dùng thống nhất
            self.client_socket = tls_sock
            self.proto = ProtoClient(self.client_socket)

            # Handshake theo protocol
            m = self.proto.recv()
            if m["type"] != TYPE_NAME_REQ:
                self.post_event("STATUS", {"text": f"[ERROR] Expected NAME_REQ, got {m}", "level": "ERROR"})
                self.client_socket.close()
                self.post_event("CONN_UI", ("DISCONNECTED", "Auth failed"))
                return
            self.proto.send_name(name)

            m = self.proto.recv()
            if m["type"] == TYPE_ERROR:
                self.display_message(f"[ERROR] {_err_text(m)}")
                self.client_socket.close()
                return
            if m["type"] != TYPE_AUTH_REQ:
                self.display_message(f"[ERROR] Expected AUTH_REQ, got {m}")
                self.client_socket.close()
                return
            self.proto.send_auth(self.server_password)

            m = self.proto.recv()
            if m["type"] == TYPE_ERROR:
                self.display_message(f"[ERROR] Auth failed: {_err_text(m)}")
                self.client_socket.close()
                return
            if m["type"] != TYPE_AUTH_OK:
                self.display_message(f"[ERROR] Expected AUTH_OK, got {m}")
                self.client_socket.close()
                return

            m = self.proto.recv()
            if m["type"] == TYPE_ERROR:
                self.display_message(f"[ERROR] {_err_text(m)}")
                self.client_socket.close()
                return
            if m["type"] != TYPE_PUBKEY_REQ:
                self.display_message(f"[ERROR] Expected PUBKEY_REQ, got {m}")
                self.client_socket.close()
                return

            pubkey_b64 = base64.b64encode(public_key_bytes).decode("utf-8")
            self.proto.send_pubkey(pubkey_b64)

            self.log_status("Đã kết nối thành công (TLS).", level="OK")
            self.ui(self._set_connection_ui, "CONNECTED")
            self.ui(lambda: self.self_name_label.configure(text=self.username or name))

            self.receive_messages()

        except Exception as e:
            self.post_event("STATUS", {"text": f"[ERROR] Không thể kết nối: {e}", "level": "ERROR"})
            self.post_event("CONN_UI", ("DISCONNECTED", str(e)))
            try:
                if getattr(self, "client_socket", None):
                    self.client_socket.close()
            except Exception:
                pass

    def receive_messages(self):
        while True:
            try:
                m = self.proto.recv()
                # Network thread -> UI thread
                self.post_event("NET_MSG", m)
            except Exception as e:
                self.post_event("NET_ERR", str(e))
                break

    # def receive_messages(self):
    #     """Vòng lặp nhận và xử lý tin nhắn từ server."""
    #     while self.client_socket:
    #         try:
    #             m = self.proto.recv()  # recv_msg() -> dict hoặc raise
    #             self.process_incoming_message(m)

    #         except ProtoError as e:
    #             # Server đóng kết nối hoặc frame lỗi
    #             self.log_status(f"Kết nối bị đóng: {e}", level="ERROR")
    #             break

    #         except ssl.SSLError as e:
    #             self.log_status(f"Lỗi TLS: {e}", level="ERROR")
    #             break

    #         except Exception as e:
    #             self.log_status(f"Lỗi receive không xác định: {e}", level="ERROR")
    #             break

    #     # ---- Cleanup tập trung, CHỈ 1 LẦN ----
    #     try:
    #         if self.client_socket:
    #             self.client_socket.close()
    #     except Exception:
    #         pass

    #     self.client_socket = None
    #     self.proto = None
    #     self.ui(self._set_connection_ui, "DISCONNECTED", "Connection closed")

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
                    # Do not popup. Store as pending and warn only when user opens that chat.
                    self.peer_trust[name] = "CHANGED"
                    self.pending_key_changes[name] = {"old_fp": old_fp, "new_fp": fp, "pubkey_bytes": pubkey_bytes}
                    self._refresh_conversation_tile(name)
                    self._ensure_conversation_tile(name)

                    self.log_status(f"Security: identity changed for {name}. Open chat to review.", level="WARN")
                    self._queue_security_notice(
                        name,
                        f"[SECURITY] Public key của {name} đã thay đổi.\n"
                        f"• Cũ: {old_fp}\n"
                        f"• Mới: {fp}\n\n"
                        "Đây có thể là đổi thiết bị hoặc tấn công MITM.\n"
                        "Vào tab Info để 'Accept New Key' nếu bạn đã xác minh fingerprint ngoài kênh."
                    )
                    return

            # Save public key and add to user list
            if name in self.pending_key_changes:
                # awaiting user decision; do not overwrite current directory key
                self.ui(self.add_user_button, name)
                return
            self.user_directory[name] = load_public_key_from_bytes(pubkey_bytes)
            if name not in self.peer_trust:
                self.peer_trust[name] = "TOFU"
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
                    self._queue_security_notice(
                        sender_name,
                        f"[SECURITY] SESSION_OFFER từ {sender_name} có chữ ký KHÔNG hợp lệ. Đã bỏ qua (có thể bị MITM/giả mạo)."
                    )
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
                    self._queue_security_notice(
                        sender_name,
                        f"[SECURITY] Nhận PRIVATE_MSG từ {sender_name} nhưng chưa có session key. Tin nhắn đã bị bỏ qua."
                    )
                    return

                ctr = int(ctr)
                last = self.recv_ctr.get(sender_name, 0)
                if ctr != last + 1:
                    self._queue_security_notice(
                        sender_name,
                        f"[SECURITY] Replay/Out-of-order từ {sender_name}: ctr={ctr} <= last={last}. Tin nhắn đã bị bỏ qua."
                    )
                    return

                session_key = self.session_keys[sender_name]
                encrypted_bytes = base64.b64decode(ciphertext_b64)

                aad = f"{sender_name}|{self.username}|{ctr}".encode("utf-8")
                decrypted_text = aes_decrypt(encrypted_bytes, session_key, associated_data=aad)

                if decrypted_text:
                    self.recv_ctr[sender_name] = ctr
                    self.add_incoming_message(sender_name, decrypted_text.decode("utf-8"), encrypted=True)
                else:
                    self._queue_security_notice(
                        sender_name,
                        f"[SECURITY] Không thể giải mã PRIVATE_MSG từ {sender_name} (ctr={ctr}). Có thể lệch khóa hoặc bị sửa đổi."
                    )

            except Exception as e:
                self.display_message(f"[ERROR] Lỗi xử lý PRIVATE_MSG: {e}")

        elif msg_type == TYPE_DIRECT_MSG:
            try:
                sender_name = payload.get("from")
                text = payload.get("text", "")
                if not sender_name:
                    return
                if sender_name == self.username:
                    return
                # Ensure conversation and append
                self._ensure_conversation_tile(sender_name)
                self.add_incoming_message(sender_name, text, encrypted=False)
            except Exception as e:
                self.display_message(f"[ERROR] Lỗi xử lý DIRECT_MSG: {e}")

        elif msg_type == TYPE_BROADCAST:
            try:
                sender_name = payload.get("from")
                text = payload.get("text")

                if not sender_name:
                    return

                # Broadcast conversation
                self._ensure_conversation_tile("Broadcast", subtitle="Phòng chat chung", trust="")
                if sender_name == self.username:
                    self.add_outgoing_message("Broadcast", text, encrypted=False, conv_id="Broadcast")
                else:
                    self.add_incoming_message(sender_name, text, encrypted=False, conv_id="Broadcast")
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
                self.add_outgoing_message("Broadcast", msg, encrypted=False, conv_id="Broadcast")
            except Exception as e:  # noqa: BLE001
                self.display_message(f"[ERROR] Lỗi khi gửi tin nhắn broadcast: {e}")
        else:
            # Default: plaintext direct message unless E2EE is enabled for this chat
            if not self.e2ee_enabled.get(target, False):
                try:
                    self.proto.send_direct_msg(target, msg)
                    self.add_outgoing_message(target, msg, encrypted=False)
                except Exception as e:
                    self.display_message(f"[ERROR] Lỗi khi gửi DIRECT_MSG: {e}")
            else:
                # If peer identity changed and not accepted, block E2EE until user accepts new key.
                if target in self.pending_key_changes:
                    self._queue_security_notice(
                        target,
                        "[SECURITY] Không thể bật E2EE vì identity của peer đã thay đổi. "
                        "Vào tab Info để Accept New Key sau khi bạn xác minh fingerprint."
                    )
                elif not self.session_confirmed.get(target, False):
                    self._queue_security_notice(target, "[SYSTEM] Đang thiết lập phiên E2EE…")
                    self.perform_handshake(target)
                else:
                    try:
                        aes_key = self.session_keys[target]

                        ctr = self.send_ctr.get(target, 0) + 1
                        self.send_ctr[target] = ctr
                        aad = f"{self.username}|{target}|{ctr}".encode("utf-8")

                        encrypted_bytes = aes_encrypt(
                            msg.encode("utf-8"),
                            aes_key,
                            associated_data=aad
                        )
                        if encrypted_bytes is None:
                            self.display_message("[ERROR] Mã hóa thất bại, không gửi được.")
                            self.entry_message.delete(0, "end")
                            return

                        encrypted_b64 = base64.b64encode(encrypted_bytes).decode("utf-8")

                        self.proto.send_private_msg(target, encrypted_b64, ctr)
                        self.add_outgoing_message(target, msg, encrypted=True)

                        self.out_msg_count[target] = self.out_msg_count.get(target, 0) + 1
                        self.maybe_auto_rekey(target)

                    except Exception as e:
                        self.display_message(f"[ERROR] Lỗi khi gửi PRIVATE_MSG: {e}")

        self.entry_message.delete(0, "end")
    
    # [FIX] Sửa lại hàm thêm nút user

    def add_user_button(self, name):
        # In modern UI, this creates/updates a conversation tile
        if not name or name == self.username:
            return
        self._ensure_conversation_tile(name)
        self._apply_search_filter()

    def select_chat_partner(self, name):
        self.current_chat_partner = name
        self.unread[name] = 0
        self._flush_security_notices_if_any(name)
        self._refresh_conversation_tile(name)
        self._render_conversation(name)

        # Update header + right panel
        self.update_chat_header()
        self.update_right_panel()

        # Auto-handshake only when needed
        if self.e2ee_enabled.get(name, False) and name not in self.session_keys:
            self.log_status(f"Switch to {name}: starting E2EE setup...", level="INFO")
            self.perform_handshake(name)
        else:
            self.log_status(f"Switched to {name}.", level="OK")



    def select_broadcast(self):
        """Chuyển về phòng chat chung (Broadcast), không mã hóa E2EE."""
        self.current_chat_partner = "Broadcast"
        self.unread["Broadcast"] = 0
        self._refresh_conversation_tile("Broadcast")
        self._render_conversation("Broadcast")
        self.update_chat_header()
        self.update_right_panel()
        self.log_status("Switched to Broadcast room.", level="OK")



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
        # Route legacy logs into Activity (status/notifications) to avoid clutter in chat
        self.log_status(str(text), level="INFO")

    def _safe_display_message(self, text):
        self.log_status(str(text), level="INFO")



if __name__ == "__main__":
    app = ChatApp()
    app.mainloop()
