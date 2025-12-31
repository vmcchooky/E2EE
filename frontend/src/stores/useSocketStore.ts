import { useAuthStore } from "./useAuthStore";
import type { SocketState } from "@/types/store";
import { create } from "zustand/react";
import { useChatStore } from "./useChatStore";
import { useE2EEStore } from "./useE2EEStore";
import { e2eeService } from "@/services/e2eeService";
import { getOrCreateDeviceId } from "@/lib/keyStore";

// VITE_WS_URL là URL gốc của FastAPI (ví dụ http://localhost:8000)
const baseHTTP = import.meta.env.VITE_WS_URL || "http://localhost:8000";
const wsURL = baseHTTP.replace(/\/$/, "") + "/ws"; // endpoint WebSocket

// Reconnect state (outside store to persist across reconnects)
let reconnectAttempts = 0;
let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
const MAX_RECONNECT_ATTEMPTS = 10;
const BASE_RECONNECT_DELAY = 1000; // 1 second

export const useSocketStore = create<SocketState>((set, get) => ({
  socket: null,
  onlineUsers: [],

  connectSocket: () => {
    const accessToken = useAuthStore.getState().accessToken;
    const existing = get().socket;

    // Clear any pending reconnect
    if (reconnectTimeout) {
      clearTimeout(reconnectTimeout);
      reconnectTimeout = null;
    }

    if (existing && existing.readyState === WebSocket.OPEN) {
      console.log("[WS] Đã có socket đang mở, bỏ qua");
      return;
    }

    // Close existing socket if it's in a bad state
    if (existing && existing.readyState !== WebSocket.CLOSED) {
      existing.close();
      set({ socket: null });
    }

    if (!accessToken) {
      console.warn("[WS] Không có accessToken, bỏ qua kết nối WebSocket.");
      return;
    }

    const url = `${wsURL}?token=${encodeURIComponent(accessToken)}`;
    console.log("[WS] Đang kết nối tới:", url);
    const ws = new WebSocket(url);

    set({ socket: ws });

    ws.onopen = () => {
      console.log("[WS] Kết nối WebSocket thành công!");
      reconnectAttempts = 0; // Reset reconnect attempts on successful connection
      const payload = { event: "ping", data: {} };
      ws.send(JSON.stringify(payload));
    };

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        const { event, data } = msg ?? {};
        if (event === "pong") {
          console.log("WS pong nhận được");
        } else if (event === "online-users") {
          const users = Array.isArray(data?.users)
            ? data.users
            : Array.isArray(data)
              ? data
              : [];
          set({ onlineUsers: users });

        } else if (event === "new-group") {
          // A group conversation was created and I'm a participant
          const convo = data;
          const chatStore = useChatStore.getState();

          if (convo && convo._id) {
            const existing = chatStore.conversations.find(c => c._id === convo._id);
            if (!existing) {
              // Add placeholder conversation; participants may be minimal, so fetch full data in background
              chatStore.addConvo({
                _id: convo._id,
                type: convo.type || "group",
                name: convo.group?.name || convo.title || "Group",
                participants: Array.isArray(convo.participants) ? convo.participants : [],
                createdAt: convo.createdAt,
                updatedAt: convo.createdAt,
                lastMessage: null,
                lastMessageAt: null,
                unreadCount: {},
              } as any);

              // Fetch full conversation list to hydrate participants/metadata
              chatStore.fetchConversations().catch((err) => {
                console.error("[WS] Không thể fetch conversations sau new-group:", err);
              });
            }
          }
        } else if (event === "group-members-added") {
          // New members were added to a group
          const { conversationId, newMembers } = data ?? {};
          if (conversationId && Array.isArray(newMembers)) {
            console.log(`[WS] New members added to group ${conversationId}:`, newMembers);
            // Refresh conversations to get updated participant list
            const chatStore = useChatStore.getState();
            chatStore.fetchConversations().catch((err) => {
              console.error("[WS] Không thể fetch conversations sau group-members-added:", err);
            });
          }
        } else if (event === "group-members-removed") {
          // Members were removed from a group
          const { conversationId, removedMembers } = data ?? {};
          if (conversationId && Array.isArray(removedMembers)) {
            console.log(`[WS] Members removed from group ${conversationId}:`, removedMembers);
            // Refresh conversations to get updated participant list
            const chatStore = useChatStore.getState();

            // AUTO RE-KEY (Security Hardening Phase 1) - Owner only
            // If I am the owner, I must rotate the key to ensure Forward Secrecy (removed user can't read future messages)
            const e2eeStore = useE2EEStore.getState();
            const conversation = chatStore.conversations.find(c => c._id === conversationId);
            const user = useAuthStore.getState().user;

            if (conversation && conversation.group?.createdBy === user?._id && e2eeStore.groupSessionKeys[conversationId]) {
              console.log("[WS] I am owner, auto re-keying group after member removal...");

              // Calculate remaining participants manually to avoid waiting for fetchConversations
              const currentParticipants = conversation.participants.map(p => String(p._id));
              const removedIds = removedMembers.map((m: any) => String(m._id || m)); // handle object or string ID
              const remainingParticipants = currentParticipants.filter(id => !removedIds.includes(id));

              const currentVersion = e2eeStore.currentGroupKeyVersion[conversationId] || 0;
              const newVersion = currentVersion + 1;

              // Initiate key exchange immediately
              e2eeStore.initiateGroupKeyExchange(conversationId, remainingParticipants, newVersion)
                .then(success => {
                  if (success) console.log("[WS] Auto re-key after removal success");
                  else console.error("[WS] Auto re-key after removal failed");
                });
            }

            chatStore.fetchConversations().catch((err) => {
              console.error("[WS] Không thể fetch conversations sau group-members-removed:", err);
            });
          }

        } else if (event === "session-key-exchange") {
          // E2EE: Nhận session key từ người khác (hỗ trợ đa thiết bị)
          const { senderId, senderUsername, senderDisplayName, encryptedSessionKey, deviceId, recipientDeviceId } = data ?? {};

          const e2eeStore = useE2EEStore.getState();
          const myDeviceId = getOrCreateDeviceId();

          // Kiểm tra xem session key này có dành cho device hiện tại không
          // Nếu có recipientDeviceId và không khớp, bỏ qua (không log error)
          if (recipientDeviceId && recipientDeviceId !== myDeviceId) {
            // Session key này dành cho device khác, bỏ qua
            return;
          }

          // CRITICAL: Kiểm tra E2EE đã init chưa
          // Nếu chưa init, không thể decrypt session key - sẽ fetch lại sau khi init
          if (!e2eeStore.isInitialized) {
            console.warn("[E2EE] Received session-key-exchange but E2EE not initialized yet. Will fetch via HTTP after init.");
            // Don't return - still try to process, but it will likely fail
            // The fetchPendingKeys() will handle it properly after E2EE init
          }

          // Bước 1: Lấy và lưu public key của người gửi để có fingerprint
          (async () => {
            // Check if this is a group key (has conversationId)
            const conversationId = data?.conversationId;
            const isGroupKey = !!conversationId;
            
            try {
              // Thử lấy public key với deviceId cụ thể trước
              let publicKeys = await e2eeService.getUserPublicKeys(senderId, deviceId);

              // Nếu không tìm thấy với deviceId, thử lấy tất cả keys
              if (publicKeys.length === 0) {
                publicKeys = await e2eeService.getUserPublicKeys(senderId);
              }

              const publicKeyResponse = publicKeys.length > 0 ? publicKeys[0] : null;

              if (publicKeyResponse && publicKeyResponse.public_key) {
                // Đăng ký public key của người gửi (TOFU)
                // Skip warning for group key exchange to avoid unnecessary prompts
                await e2eeStore.registerUserPublicKey(
                  senderId,
                  senderDisplayName || senderUsername || senderId,
                  publicKeyResponse.public_key,
                  isGroupKey // skipWarning = true for group
                );
              } else {
                console.warn(`[E2EE] Không tìm thấy public key từ người gửi: ${senderId} (deviceId: ${deviceId || 'any'})`);
              }
            } catch (err) {
              console.error(`[E2EE] Lỗi khi lấy public key của người gửi:`, err);
            }

            // Bước 2: Giải mã session key
            // Chỉ thử decrypt nếu deviceId khớp hoặc không có deviceId (backward compatibility)
            if (!deviceId || deviceId === myDeviceId) {
              try {
                // Check if this is a group key (has conversationId)
                const conversationId = data?.conversationId;
                const keyVersion = data?.keyVersion;

                if (conversationId) {
                  // Group session key - keyVersion is required
                  const version = keyVersion || 1; // Fallback to 1 for backward compatibility
                  const success = await e2eeStore.receiveGroupKeyExchange(conversationId, senderId, encryptedSessionKey, version);
                  if (!success) {
                    console.warn(`[E2EE] Không thể giải mã group session key v${version} từ ${senderUsername} cho conversation ${conversationId}`);
                  } else {
                    console.log(`[E2EE] Nhận group session key v${version} cho conversation ${conversationId} từ ${senderUsername}`);
                  }
                } else {
                  // Direct chat session key - skipWarning=true for automatic WebSocket events
                  const signature = data?.signature;
                  const timestamp = data?.timestamp;
                  const success = await e2eeStore.receiveKeyExchange(senderId, encryptedSessionKey, signature, timestamp, true);
                  if (!success) {
                    console.warn(`[E2EE] Không thể giải mã session key từ ${senderUsername} (có thể key dành cho device khác)`);
                  }
                }
              } catch (err) {
                // Chỉ log error nếu đây là device đích hoặc không có deviceId
                if (!deviceId || deviceId === myDeviceId) {
                  console.error(`[E2EE] Lỗi nhận key exchange từ ${senderUsername}:`, err);
                }
              }
            }
          })();
        } else if (event === "new-message") {
          const { message, conversation, unreadCounts } = data ?? {};
          const chatStore = useChatStore.getState();

          // Xử lý conversation TRƯỚC để đảm bảo conversation có trong danh sách
          if (conversation && conversation._id) {
            const existingConvo = chatStore.conversations.find(c => c._id === conversation._id);

            if (existingConvo) {
              // Cập nhật conversation đã có (bao gồm participants nếu có)
              const updatedConversation: any = {
                _id: conversation._id,
                lastMessage: conversation.lastMessage,
                lastMessageAt: conversation.lastMessageAt,
                unreadCount: unreadCounts || {}
              };
              // Update participants if provided (for group members changes)
              if (conversation.participants && Array.isArray(conversation.participants)) {
                updatedConversation.participants = conversation.participants;
              }
              chatStore.updateConversation(updatedConversation);
            } else {
              // Thêm cuộc trò chuyện mới - đảm bảo participants là mảng
              const participants = Array.isArray(conversation.participants) && conversation.participants.length > 0
                ? conversation.participants
                : [];

              const newConvo = {
                _id: conversation._id,
                type: conversation.type || "direct",
                group: conversation.group,
                participants: participants,
                lastMessage: conversation.lastMessage,
                lastMessageAt: conversation.lastMessageAt,
                unreadCount: unreadCounts || {},
                createdAt: conversation.createdAt,
                updatedAt: conversation.updatedAt,
              };

              // Nếu thiếu participants cho direct conversation, fetch ngay từ server
              if (newConvo.type === "direct" && newConvo.participants.length === 0) {
                console.warn("[WS] Conversation thiếu participants, đang lấy từ server");
                // Fetch ngay lập tức (không đợi) để cập nhật participants
                chatStore.fetchConversations().then(() => {
                  // Sau khi fetch, kiểm tra lại xem conversation đã có trong store chưa
                  const fetchedConvo = chatStore.conversations.find(c => c._id === conversation._id);
                  if (fetchedConvo && fetchedConvo.participants.length >= 2) {
                    // Conversation đã được thêm từ fetchConversations với đầy đủ participants
                    return;
                  }
                  // Nếu vẫn chưa có, thêm conversation với participants rỗng
                  // Component sẽ handle việc này bằng cách return null nếu thiếu otherUser
                  chatStore.addConvo(newConvo as any);
                }).catch((err) => {
                  console.error("[WS] Không lấy được danh sách cuộc trò chuyện:", err);
                  // Nếu fetch thất bại, vẫn thêm conversation nhưng với participants rỗng
                  chatStore.addConvo(newConvo as any);
                });
              } else {
                // Có đủ participants hoặc không phải direct conversation, thêm ngay
                // Đối với direct conversation, cần ít nhất 2 participants
                if (newConvo.type !== "direct" || newConvo.participants.length >= 2) {
                  chatStore.addConvo(newConvo as any);
                } else {
                  console.warn("[WS] Không thêm conversation vì thiếu participants:", newConvo._id);
                }
              }
            }
          } else if (message && message.conversationId) {
            // Nếu thiếu thông tin conversation mà có conversationId, lấy ngay từ server
            const conversationId = message.conversationId;
            const existingConvo = chatStore.conversations.find(c => c._id === conversationId);

            if (!existingConvo) {
              // Lấy conversation từ server ngay lập tức
              console.log("[WS] Thiếu dữ liệu conversation, đang lấy từ server");
              chatStore.fetchConversations().catch((err) => {
                console.error("[WS] Không lấy được conversation sau khi nhận message:", err);
              });
            }
          }

          // Xử lý message sau khi đã đảm bảo có conversation
          if (message) {
            // Skip message from self - already added via optimistic update
            const { user } = useAuthStore.getState();
            const isFromSelf = user && String(message.senderId) === String(user._id);

            if (isFromSelf) {
              // Don't add - already added optimistically when sending
              return;
            }

            // Kiểm tra xem message có được mã hoá E2EE không (format: "E2EE:base64ciphertext")
            const content = message.content || "";
            const isE2EEMessage = content.startsWith("E2EE:");

            if (isE2EEMessage) {
              // Trích xuất ciphertext (bỏ tiền tố "E2EE:")
              const ciphertext = content.substring(5);

              const e2eeStore = useE2EEStore.getState();
              const conversationId = message.conversationId;
              const keyVersion = message.keyVersion; // From backend

              // Determine if this is a group or direct message
              const { conversations } = chatStore;
              const conversation = conversations.find(c => c._id === conversationId);
              const isGroup = conversation?.type === "group";

              // Decrypt based on conversation type
              let decryptPromise: Promise<string | null>;
              if (isGroup) {
                // Group message: use provided keyVersion; if missing, fall back to current known version
                const fallbackVersion = e2eeStore.currentGroupKeyVersion[conversationId] ?? 1;
                const version = (typeof keyVersion === 'number' && keyVersion > 0) ? keyVersion : fallbackVersion;
                decryptPromise = e2eeStore.decryptGroupMessage(conversationId, String(message.senderId), ciphertext, version);
              } else {
                // Direct message: use counter for anti-replay protection
                const counter = message.counter ?? undefined;
                // Since this is an incoming message, sender is message.senderId and receiver is current observer
                decryptPromise = e2eeStore.decryptMessage(message.senderId, String(user?._id), ciphertext, counter);
              }

              decryptPromise.then((decrypted) => {
                if (decrypted) {
                  chatStore.addMessage({
                    ...message,
                    content: decrypted,
                    isE2EE: true,
                  });
                } else {
                  console.warn(`[E2EE] Giải mã tin nhắn thất bại từ ${message.senderId} (${isGroup ? 'group' : 'direct'}, keyVersion: ${keyVersion})`);
                  chatStore.addMessage({
                    ...message,
                    content: `🔒 [Tin nhắn mã hóa - không thể giải mã${keyVersion ? ` (key v${keyVersion})` : ''}]`,
                    isE2EE: true,
                    decryptionFailed: true,
                  });
                }
              });
            } else {
              // Tin nhắn văn bản thuần
              // Check if it's a system message
              const content = message.content || "";
              const isSystemMessage = content.startsWith("SYSTEM:");
              if (isSystemMessage) {
                message.isSystem = true;
              }
              chatStore.addMessage(message);
            }
          }
        }
      } catch (e) {
        console.warn("WS nhận message không phải JSON:", ev.data);
      }
    };

    ws.onerror = (err) => {
      console.error("[WS] Lỗi WebSocket:", err);
      // Don't reconnect here - onclose will handle it
    };

    ws.onclose = (event) => {
      console.log(`[WS] WebSocket đã đóng. Code: ${event.code}, Reason: ${event.reason || 'none'}`);
      set({ socket: null });

      // Auto-reconnect if we have a token and haven't exceeded max attempts
      const accessToken = useAuthStore.getState().accessToken;
      if (accessToken && reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
        // Exponential backoff: 1s, 2s, 4s, 8s, 16s... (max ~17 minutes total)
        const delay = Math.min(BASE_RECONNECT_DELAY * Math.pow(2, reconnectAttempts), 30000);
        reconnectAttempts++;

        console.log(`[WS] Sẽ thử kết nối lại sau ${delay / 1000}s (lần thử ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})`);

        reconnectTimeout = setTimeout(() => {
          console.log(`[WS] Đang thử kết nối lại... (lần ${reconnectAttempts})`);
          get().connectSocket();
        }, delay);
      } else if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        console.error("[WS] Đã hết số lần thử kết nối lại. Vui lòng refresh trang.");
      }
    };
  },

  disconnectSocket: () => {
    // Clear any pending reconnect when manually disconnecting
    if (reconnectTimeout) {
      clearTimeout(reconnectTimeout);
      reconnectTimeout = null;
    }
    reconnectAttempts = MAX_RECONNECT_ATTEMPTS; // Prevent auto-reconnect

    const ws = get().socket;
    if (ws) {
      ws.close();
    }
    set({ socket: null, onlineUsers: [] });
  },

  // Reset reconnect counter (call when user logs in again)
  resetReconnect: () => {
    reconnectAttempts = 0;
    if (reconnectTimeout) {
      clearTimeout(reconnectTimeout);
      reconnectTimeout = null;
    }
  },
}));