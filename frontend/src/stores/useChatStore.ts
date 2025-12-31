import { chatService } from "@/services/chatService";
import type { ChatState } from "@/types/store";
import type { Message } from "@/types/chat";
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { useAuthStore } from "./useAuthStore";
import { useE2EEStore } from "./useE2EEStore";

export const useChatStore = create<ChatState>()(
    persist(
        (set, get) => ({
            conversations: [],
            messages: {},
            activeConversationId: null,
            loading: false,
            messageLoading: false,

            setActiveConversation: async (id) => {
                set({ activeConversationId: id });

                // SUBSCRIPTION: Re-decrypt when E2EE keys change
                // We perform an initial check now
                if (id) {
                    get().triggerRedecryption(id);
                }
            },
            
            triggerRedecryption: async (id) => {
                const e2eeStore = useE2EEStore.getState();
                const { user } = useAuthStore.getState();
                if (e2eeStore.isInitialized && id && user) {
                    const { conversations, messages } = get();
                    const conversation = conversations.find(c => c._id === id);
                    const isDirect = conversation?.type === "direct";
                    const otherUser = isDirect
                        ? conversation.participants.find(p => String(p._id) !== String(user._id))
                        : null;
                    const currentMessages = messages[id]?.items || [];

                    // Check if there are any encrypted messages that need decryption
                    // (either failed before or still have "E2EE:" prefix)
                    const needsDecryption = currentMessages.some(m => {
                        const content = m.content || "";
                        return content.startsWith("E2EE:") || m.decryptionFailed;
                    });

                    if (needsDecryption) {
                        const redecrypted = await Promise.all(currentMessages.map(async (m) => {
                            const content = m.content || "";
                            const isE2EE = content.startsWith("E2EE:");
                            const isOwn = String(m.senderId) === String(user._id);

                            if (isE2EE) {
                                const ciphertext = content.substring(5);

                                let decrypted: string | null = null;

                                if (isDirect) {
                                    // Direct chat: use session key with other user
                                    let decryptUserId: string;
                                    if (isOwn && otherUser) {
                                        decryptUserId = String(otherUser._id);
                                    } else {
                                        decryptUserId = String(m.senderId);
                                    }
                                    const counter = m.counter ?? undefined;
                                    const msgSenderId = String(m.senderId);
                                    const msgReceiverId = (msgSenderId === String(user._id)) ? decryptUserId : String(user._id);
                                    decrypted = await e2eeStore.decryptMessage(msgSenderId, msgReceiverId, ciphertext, counter);
                                } else {
                                    // Group chat: use group session key with specific keyVersion
                                    const keyVersion = m.keyVersion ?? 1;
                                    console.log(`[ChatStore] Re-decrypting group message with keyVersion: ${keyVersion}`);
                                    decrypted = await e2eeStore.decryptGroupMessage(id, String(m.senderId), ciphertext, keyVersion);
                                }

                                if (decrypted) {
                                    return {
                                        ...m,
                                        content: decrypted,
                                        decryptionFailed: false,
                                    };
                                } else {
                                    return {
                                        ...m,
                                        content: "🔒 [Tin nhắn mã hóa - không thể giải mã]",
                                        decryptionFailed: true,
                                    };
                                }
                            }
                            return m;
                        }));

                        set((state) => ({
                            messages: {
                                ...state.messages,
                                [id]: {
                                    ...state.messages[id],
                                    items: redecrypted,
                                }
                            }
                        }));
                    }
                }
            },
            reset: () => {
                set({
                    conversations: [],
                    messages: {},
                    activeConversationId: null,
                    loading: false,
                    messageLoading: false,
                });
            },
            fetchConversations: async () => {
                set({ loading: true });
                try {
                    const { conversations } = await chatService.fetchConversations();
                    set({ conversations, loading: false });
                }
                catch (error) {
                    console.error("Lỗi khi lấy cuộc trò chuyện:", error);
                    set({ loading: false });
                }
            },
            fetchMesssages: async (conversationId) => {
                const { activeConversationId, messages } = get();
                const { user } = useAuthStore.getState();
                const convoId = conversationId ?? activeConversationId;
                if (!convoId || !user) {
                    return;
                }
                const current = messages?.[convoId];
                const nextCursor = current?.nextCursor === undefined ? "" : current?.nextCursor;
                if (nextCursor === null) {
                    return;
                }
                set({ messageLoading: true });

                try {
                    const { messages: fetched, cursor } = await chatService.fetchMessages(convoId, nextCursor);
                    const e2eeStore = useE2EEStore.getState();

                    // E2EE requires PIN to initialize - if not initialized, messages will remain encrypted
                    // User needs to re-login and enter PIN to decrypt E2EE messages

                    // Get conversation to find recipient for E2EE decryption
                    const { conversations } = get();
                    const conversation = conversations.find(c => c._id === convoId);
                    const isDirect = conversation?.type === "direct";
                    const otherUser = isDirect
                        ? conversation.participants.find(p => String(p._id) !== String(user._id))
                        : null;

                    // Process messages and decrypt E2EE ones
                    const processed = await Promise.all(fetched.map(async (m) => {
                        const content = m.content || "";
                        const isE2EE = content.startsWith("E2EE:");
                        const isOwn = String(m.senderId) === String(user._id);

                        if (isE2EE) {
                            const ciphertext = content.substring(5);

                            let decrypted: string | null = null;

                            if (isDirect) {
                                // Direct chat: use session key with other user
                                let decryptUserId: string;
                                if (isOwn && otherUser) {
                                    // My message: was encrypted with recipient's session key
                                    decryptUserId = String(otherUser._id);
                                } else {
                                    // Other's message: was encrypted with my session key (for me)
                                    decryptUserId = String(m.senderId);
                                }

                                const hasSession = e2eeStore.hasSessionWith(decryptUserId);
                                if (!hasSession) {
                                    console.warn(`[ChatStore] No session key available for ${decryptUserId} to decrypt message from ${m.senderId}`);
                                }

                                // Extract counter
                                const counter = m.counter ?? undefined;
                                const msgSenderId = String(m.senderId);
                                const msgReceiverId = (msgSenderId === String(user._id)) ? decryptUserId : String(user._id);
                                decrypted = await e2eeStore.decryptMessage(msgSenderId, msgReceiverId, ciphertext, counter);
                            } else {
                                // Group chat: use group session key with specific keyVersion
                                const keyVersion = m.keyVersion ?? 1; // Fallback to 1 for backward compatibility
                                console.log(`[ChatStore] Decrypting group message with keyVersion: ${keyVersion} (from message: ${m.keyVersion})`);

                                const hasGroupSession = e2eeStore.hasGroupSessionVersion(convoId, keyVersion);
                                if (!hasGroupSession) {
                                    console.warn(`[ChatStore] No group session key v${keyVersion} available for conversation ${convoId}`);
                                    // Try to find any available key version
                                    const availableVersions = Object.keys(e2eeStore.groupSessionKeys[convoId] || {});
                                    console.log(`[ChatStore] Available key versions: ${availableVersions.join(', ') || 'none'}`);
                                }

                                decrypted = await e2eeStore.decryptGroupMessage(convoId, String(m.senderId), ciphertext, keyVersion);
                            }

                            if (!decrypted) {
                                console.warn(`[ChatStore] Failed to decrypt message from ${m.senderId}`);
                            }

                            return {
                                ...m,
                                content: decrypted || "🔒 [Tin nhắn mã hóa - không thể giải mã]",
                                isOwn,
                                isE2EE: true,
                                decryptionFailed: !decrypted,
                            };
                        }

                        return {
                            ...m,
                            isOwn,
                        };
                    }));

                    set((state) => {
                        const prev = state.messages[convoId]?.items || [];
                        const existingIds = new Set(prev.map(m => m._id).filter(Boolean));
                        const newMessages = processed.filter(m => {
                            if (!m._id) return true;
                            return !existingIds.has(m._id);
                        });
                        const merged = prev.length > 0 ? [...prev, ...newMessages] : processed;

                        merged.sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime());

                        return {
                            messages: {
                                ...state.messages,
                                [convoId]: {
                                    items: merged,
                                    hasMore: !!cursor,
                                    nextCursor: cursor ?? null
                                }
                            }
                        }
                    })
                } catch (error) {
                    console.error("Lỗi khi lấy tin nhắn:", error);
                } finally {
                    set({ messageLoading: false });
                }
            },
            sendDirectMessage: async (recepientId, content, imgUrl, originalContent?: string, counter?: number) => {
                try {
                    const { activeConversationId } = get();

                    // Send message to server
                    const messageResponse = await chatService.sendDirectMessage(
                        recepientId,
                        content,
                        imgUrl,
                        activeConversationId || undefined,
                        counter  // Pass counter for anti-replay protection (E2EE messages)
                    );

                    // Optimistic update: Add message to store immediately
                    if (messageResponse) {
                        const conversationId = messageResponse.conversationId;

                        // Set activeConversationId if not set (new conversation)
                        // IMPORTANT: Set this BEFORE addMessage to ensure component re-renders
                        if (!activeConversationId && conversationId) {
                            set({ activeConversationId: conversationId });
                        }

                        const messageContent = messageResponse.content || content;
                        const isE2EE = typeof messageContent === 'string' && messageContent.startsWith("E2EE:");

                        // If E2EE, use originalContent (plaintext) for display
                        // Otherwise use messageContent
                        const displayContent = isE2EE && originalContent
                            ? originalContent
                            : messageContent;

                        // Get user first to determine isOwn
                        const { user } = useAuthStore.getState();

                        const message: Message = {
                            ...messageResponse,
                            content: displayContent,
                            // Determine isOwn by comparing senderId with current user ID (both as strings)
                            isOwn: String(messageResponse.senderId) === String(user?._id),
                            isE2EE: isE2EE,
                        };

                        // Ensure message has _id (required for React key)
                        if (!message._id) {
                            console.warn("[ChatStore] Message missing _id, using temporary ID", messageResponse);
                            message._id = `temp-${Date.now()}-${Math.random()}`;
                        }

                        // Use final conversationId (from response or current active)
                        const finalConversationId = conversationId || activeConversationId;

                        // Add message directly to store (bypass fetchMesssages for optimistic update)
                        if (finalConversationId) {
                            set((state) => {
                                const prevItems = state.messages[finalConversationId]?.items ?? [];

                                // Check for duplicate (only if _id exists)
                                if (message._id && prevItems.some((m) => m._id === message._id)) {
                                    return state;
                                }

                                const existingMessages = state.messages[finalConversationId];
                                return {
                                    messages: {
                                        ...state.messages,
                                        [finalConversationId]: {
                                            items: [...prevItems, message],
                                            hasMore: existingMessages?.hasMore ?? false,
                                            nextCursor: existingMessages?.nextCursor ?? undefined,
                                        }
                                    }
                                };
                            });
                        }

                        // Update conversation seen status
                        if (finalConversationId) {
                            set((state) => ({
                                conversations: state.conversations.map((c) =>
                                    c._id === finalConversationId ? {
                                        ...c,
                                        seenBy: []
                                    } : c
                                ),
                            }));
                        }
                    }

                } catch (error) {
                    console.error("Lỗi khi gửi tin nhắn trực tiếp:", error);
                }
            },
            sendGroupMessage: async (conversationId, content, imgUrl, originalContent) => {
                try {
                    // Determine keyVersion if this is an E2EE message
                    const e2eeStore = useE2EEStore.getState();
                    let keyVersion: number | undefined;

                    if (typeof content === "string" && content.startsWith("E2EE:")) {
                        keyVersion = e2eeStore.currentGroupKeyVersion[conversationId] ?? 1;
                    }

                    // Send message to server
                    const messageResponse = await chatService.sendGroupMessage(
                        conversationId,
                        content,
                        imgUrl || undefined,
                        keyVersion,
                    );

                    // Optimistic update: Add message to store immediately
                    if (messageResponse) {
                        const messageContent = messageResponse.content || content;
                        const isE2EE = typeof messageContent === 'string' && messageContent.startsWith("E2EE:");

                        // If E2EE, use originalContent (plaintext) for display
                        const displayContent = isE2EE && originalContent
                            ? originalContent
                            : messageContent;

                        const { user } = useAuthStore.getState();

                        const message: Message = {
                            ...messageResponse,
                            content: displayContent,
                            isOwn: String(messageResponse.senderId) === String(user?._id),
                            isE2EE: isE2EE,
                        };

                        // Ensure message has _id
                        if (!message._id) {
                            console.warn("[ChatStore] Group message missing _id, using temporary ID", messageResponse);
                            message._id = `temp-${Date.now()}-${Math.random()}`;
                        }

                        // Add message directly to store
                        if (conversationId) {
                            set((state) => {
                                const prevItems = state.messages[conversationId]?.items ?? [];

                                // Check for duplicate
                                if (message._id && prevItems.some((m) => m._id === message._id)) {
                                    return state;
                                }

                                const existingMessages = state.messages[conversationId];
                                return {
                                    messages: {
                                        ...state.messages,
                                        [conversationId]: {
                                            items: [...prevItems, message],
                                            hasMore: existingMessages?.hasMore ?? false,
                                            nextCursor: existingMessages?.nextCursor ?? undefined,
                                        }
                                    },
                                    conversations: state.conversations.map((c) =>
                                        c._id === conversationId ? {
                                            ...c,
                                            seenBy: []
                                        } : c
                                    ),
                                };
                            });
                        }
                    }
                } catch (error) {
                    console.error("Lỗi khi gửi tin nhắn nhóm:", error);
                }
            },
            addMessage: async (message) => {
                try {
                    const { user } = useAuthStore.getState();
                    const { fetchMesssages } = get();

                    // Compare as strings to avoid type mismatch
                    message.isOwn = String(message.senderId) === String(user?._id);

                    const convoId = message.conversationId;

                    let prevItems = get().messages[convoId]?.items ?? [];

                    if (prevItems.length === 0) {
                        await fetchMesssages(convoId);
                        prevItems = get().messages[convoId]?.items ?? [];
                    }

                    set((state) => {
                        // Re-check prevItems from current state to avoid stale data
                        const currentItems = state.messages[convoId]?.items ?? [];

                        // Check for duplicate by _id
                        if (currentItems.some((m) => m._id === message._id)) {
                            return state;
                        }

                        const existingMessages = state.messages[convoId];
                        return {
                            messages: {
                                ...state.messages,
                                [convoId]: {
                                    items: [...currentItems, message],
                                    hasMore: existingMessages?.hasMore ?? false,
                                    nextCursor: existingMessages?.nextCursor ?? undefined,
                                }
                            }
                        }
                    });
                } catch (error) {
                    console.error("Lỗi khi thêm tin nhắn:", error);
                }
            },
            updateConversation: (conversation) => {
                set((state) => ({
                    conversations: state.conversations.map((c) =>
                        c._id === conversation._id ? { ...c, ...conversation } : c
                    ),
                }));
            },
            markAsSeen: async () => {
                try {
                    const { user } = useAuthStore.getState();
                    const { activeConversationId, conversations } = get();

                    if (!activeConversationId || !user) {
                        return;
                    }

                    const convo = conversations.find((c) => c._id === activeConversationId);

                    if (!convo) {
                        return;
                    }

                    if ((convo.unreadCount?.[user._id] ?? 0) === 0) {
                        return;
                    }

                    await chatService.markAsSeen(activeConversationId);

                    set((state) => ({
                        conversations: state.conversations.map((c) =>
                            c._id === activeConversationId && c.lastMessage
                                ? {
                                    ...c,
                                    unreadCount: {
                                        ...c.unreadCount,
                                        [user._id]: 0,
                                    },
                                }
                                : c
                        ),
                    }));
                } catch (error) {
                    console.error("Lỗi xảy ra khi gọi markAsSeen trong store", error);
                }
            },
            addConvo: (convo) => {
                set((state) => {
                    const exists = state.conversations.some((c) => c._id === convo._id);
                    if (exists) {
                        // Don't add duplicate, just return current state
                        return state;
                    }
                    // Add new conversation at the beginning of the list
                    // Don't auto-set as active - let user choose
                    return {
                        conversations: [convo, ...state.conversations],
                    };
                });
            },
            deleteConversation: async (conversationId: string) => {
                try {
                    // Delete from backend
                    await chatService.deleteConversation(conversationId);

                    // Update local state
                    set((state) => {
                        const { [conversationId]: _, ...remainingMessages } = state.messages;
                        return {
                            conversations: state.conversations.filter((c) => c._id !== conversationId),
                            activeConversationId: state.activeConversationId === conversationId ? null : state.activeConversationId,
                            messages: remainingMessages,
                        };
                    });
                } catch (error) {
                    console.error("Lỗi khi xóa cuộc trò chuyện:", error);
                    throw error;
                }
            },
            createConversation: async (type, name, memberIds) => {
                try {
                    set({ loading: true });

                    // For direct conversations, check if conversation already exists
                    if (type === "direct" && memberIds.length === 1) {
                        const { conversations } = get();
                        const { user } = useAuthStore.getState();

                        if (user) {
                            const existingConversation = conversations.find((conv) => {
                                if (conv.type !== "direct") return false;
                                // Check if this friend is a participant and conversation has exactly 2 participants
                                const participantIds = conv.participants.map(p => String(p._id));
                                return participantIds.includes(String(memberIds[0]))
                                    && participantIds.includes(String(user._id))
                                    && participantIds.length === 2;
                            });

                            if (existingConversation) {
                                // Conversation already exists, just set it as active
                                set({ activeConversationId: existingConversation._id });
                                await get().fetchMesssages(existingConversation._id);
                                return;
                            }
                        }
                    }

                    const created = await chatService.createConversation(type, name, memberIds);

                    await get().fetchConversations();

                    if (created?.id) {
                        set({ activeConversationId: created.id });
                        await get().fetchMesssages(created.id);
                        // E2EE for group is NOT automatically enabled
                        // User must manually enable it via the lock button in MessageInput
                    }
                } catch (error) {
                    console.error("Lỗi xảy ra khi gọi createConversation trong store");
                } finally {
                    set({ loading: false });
                }
            },
            addMembersToGroup: async (conversationId, memberIds) => {
                try {
                    set({ loading: true });
                    const response = await chatService.addMembersToGroup(conversationId, memberIds);
                    await get().fetchConversations();

                    // Show success message with details from backend
                    if (response?.data?.message) {
                        const { added_count, already_members_count } = response.data;
                        if (already_members_count > 0) {
                            // Some users were already members
                            console.log(`[Chat] Added ${added_count} members, ${already_members_count} were already members`);
                        }
                    }

                    // AUTO RE-KEY (Security Hardening Phase 1)
                    // If group has E2EE enabled, rotate key so new members get a fresh key
                    // and to ensure all existing members update their key for the new epoch.
                    const e2eeStore = useE2EEStore.getState();
                    const hasGroupKey = e2eeStore.groupSessionKeys[conversationId];
                    
                    if (hasGroupKey) {
                         console.log("[Chat] Auto re-keying group after adding members...");
                         // Need to get updated participant list first
                         // fetchConversations above already updated the list in store
                         const updatedConvo = get().conversations.find(c => c._id === conversationId);
                         if (updatedConvo) {
                             const participantIds = updatedConvo.participants.map(p => String(p._id));
                             const currentVersion = e2eeStore.currentGroupKeyVersion[conversationId] || 0;
                             const newVersion = currentVersion + 1;
                             
                             // Initiate key exchange
                             await e2eeStore.initiateGroupKeyExchange(conversationId, participantIds, newVersion);
                         }
                    }

                    return response;
                } catch (error: any) {
                    console.error("Lỗi khi thêm thành viên:", error);
                    throw error;
                } finally {
                    set({ loading: false });
                }
            },
            createInviteLink: async (conversationId, expiresDays) => {
                try {
                    const response = await chatService.createInviteLink(conversationId, expiresDays);
                    return response.data;
                } catch (error: any) {
                    console.error("Lỗi khi tạo invite link:", error);
                    throw error;
                }
            },
            joinGroupViaInvite: async (inviteCode) => {
                try {
                    set({ loading: true });
                    const response = await chatService.joinGroupViaInvite(inviteCode);
                    await get().fetchConversations();

                    if (response?.data?.id) {
                        set({ activeConversationId: response.data.id });
                        await get().fetchMesssages(response.data.id);
                    }

                    // Return response to allow caller to check message
                    return response;
                } catch (error: any) {
                    console.error("Lỗi khi join group:", error);
                    throw error;
                } finally {
                    set({ loading: false });
                }
            },
            leaveGroup: async (conversationId) => {
                try {
                    set({ loading: true });
                    await chatService.leaveGroup(conversationId);

                    // Remove conversation from local state
                    set((state) => {
                        const { [conversationId]: _, ...remainingMessages } = state.messages;
                        return {
                            conversations: state.conversations.filter((c) => c._id !== conversationId),
                            activeConversationId: state.activeConversationId === conversationId ? null : state.activeConversationId,
                            messages: remainingMessages,
                        };
                    });
                } catch (error: any) {
                    console.error("Lỗi khi rời nhóm:", error);
                    throw error;
                } finally {
                    set({ loading: false });
                }
            },
        }),
        {
            name: "chat-storage",
            partialize: (state) => ({ conversations: state.conversations })
        }
    )
)