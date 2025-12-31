import type { Conversation, Message } from "./chat";
import type { Friend, FriendRequest, User } from "./user";

export interface AuthState {
    accessToken: string | null;
    user: User | null;
    loading: boolean;

    clearState: () => void;
    signUp: (username: string, password: string, email: string, firstname: string, lastname: string) => Promise<void>;
    login: (username: string, password: string) => Promise<void>;
    logout: () => Promise<void>;
    fetchMe: (silent?: boolean) => Promise<void>;
    refreshToken: (silent?: boolean) => Promise<string | null>;
}

export interface ThemeState {
    isDark: boolean;
    toggleTheme: () => void;
    setTheme: (dark: boolean) => void;
}

export interface ChatState {
    conversations: Conversation[];
    messages: Record<string, {
        items: Message[],
        hasMore: boolean,
        nextCursor?: string | null,
    }>;
    activeConversationId: string | null;
    loading: boolean;
    messageLoading: boolean;

    reset: () => void;

    setActiveConversation: (id: string | null) => Promise<void>;
    triggerRedecryption: (id: string) => Promise<void>;

    fetchConversations: () => Promise<void>;
    fetchMesssages: (conversationId?: string) => Promise<void>;
    sendDirectMessage: (
        recepientId: string,
        content: string,
        imgUrl?: string,
        originalContent?: string,
        counter?: number) => Promise<void>;
    sendGroupMessage: (
        conversationId: string,
        content: string,
        imgUrl?: string,
        originalContent?: string) => Promise<void>;
    addMessage: (
        message: Message
    ) => Promise<void>;
    updateConversation: (
        conversation: Conversation
    ) => void;

    markAsSeen: () => Promise<void>;
    addConvo: (convo: Conversation) => void;
    deleteConversation: (conversationId: string) => Promise<void>;
    createConversation: (
        type: "group" | "direct",
        name: string,
        memberIds: string[]
    ) => Promise<void>;
    addMembersToGroup: (conversationId: string, memberIds: string[]) => Promise<void>;
    createInviteLink: (conversationId: string, expiresDays?: number) => Promise<{ invite_code: string; invite_url: string; expires_at: string | null }>;
    joinGroupViaInvite: (inviteCode: string) => Promise<any>;
    leaveGroup: (conversationId: string) => Promise<void>;
}

export interface SocketState {
    socket: WebSocket | null;
    onlineUsers: string[];
    connectSocket: () => void;
    disconnectSocket: () => void;
    resetReconnect: () => void;
}

export interface FriendState {
    friends: Friend[];
    loading: boolean;
    receivedList: FriendRequest[];
    sentList: FriendRequest[];
    searchByUsername: (username: string) => Promise<User | null>;
    addFriend: (to: string, message?: string) => Promise<string>;
    getAllFriendRequests: () => Promise<void>;
    acceptRequest: (requestId: string) => Promise<void>;
    declineRequest: (requestId: string) => Promise<void>;
    getFriends: () => Promise<void>;
}