export interface Participant {
    _id: string;
    displayName?: string;
    avatarUrl?: string;
    joinedAt: string;
}

export interface SeenUser {
    _id: string;
    displayName?: string;
    avatarUrl?: string;
}

export interface Group {
    name: string;
    createdBy: string;
}

export interface LastMessage {
    _id: string;
    content: string;
    createdAt: string;
    sender: {
        _id: string;
        displayName?: string;
        avatarUrl?: string | null;
    };
    counter?: number | null;
    keyVersion?: number | null;
}

export interface Conversation {
    _id: string;
    type: 'direct' | 'group';
    group: Group;
    participants: Participant[];
    lastMessageAt: string;
    seenBy: SeenUser[];
    lastMessage: LastMessage | null;
    unreadCount: Record<string, number>; // key: userId, value: count
    createdAt: string;
    updatedAt: string;
}

export interface ConversationResponse {
    conversations: Conversation[];
}

export interface Message {
    _id: string;
    conversationId: string;
    senderId: string;
    content: string | null;
    imgUrl?: string | null;
    updatedAt?: string | null;
    createdAt: string;
    isOwn?: boolean;
    // E2EE fields
    isE2EE?: boolean;
    ciphertext?: string;
    decryptionFailed?: boolean;
    // Version của group session key dùng để mã hóa message này (null/undefined = không dùng group key)
    keyVersion?: number | null;
    // Counter for anti-replay protection (E2EE direct messages only)
    counter?: number | null;
    // System message flag
    isSystem?: boolean;
}