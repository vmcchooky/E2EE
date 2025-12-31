import api from '@/lib/axios';
import type { Conversation, ConversationResponse, Message } from '@/types/chat';


interface FetchMessagesProps {
    messages: Message[];
    cursor?: string;
}

const pageLimit = 50;

export const chatService = {
    async fetchConversations(): Promise<ConversationResponse> {
        const response = await api.get("/conversations");
        return response.data;
    },
    async fetchMessages(id: string, cursor?: string): Promise<FetchMessagesProps> {
        const res = await api.get(`/conversations/${id}/messages?limit=${pageLimit}&cursor=${cursor}`);

        return { messages: res.data.messages, cursor: res.data.nextCursor };
    },
    async sendDirectMessage(
        recepientId: string,
        content: string = "",
        imgUrl?: string,
        conversationId?: string,
        counter?: number
    ) {
        const res = await api.post("/messages/direct", {
            recipient_id: recepientId,
            content,
            conversation_id: conversationId,
            counter: counter ?? undefined  // Only send counter if provided (E2EE messages)
        });
        return res.data.data;
    },
    async sendGroupMessage(
        groupId: string,
        content: string = "",
        imgUrl?: string,
        keyVersion?: number,
    ) {
        const res = await api.post("/messages/group", {
            conversation_id: groupId,
            content,
            imgUrl,
            key_version: keyVersion ?? null,
        });
        return res.data.data; // Fixed: was res.data.message (string), should be res.data.data (object)
    },

    async createConversation(
        type: "direct" | "group",
        name: string,
        memberIds: string[]
    ) {
        const participant_ids = (memberIds || []).filter((id) => !!id);
        if (participant_ids.length === 0) {
            console.error("createConversation aborted: no participant_ids", memberIds);
            throw new Error("participant_ids is empty");
        }
        const payload = {
            title: type === "group" ? name : null,
            participant_ids,
        };
        console.log("createConversation request", payload);
        const res = await api.post("/conversations", payload);
        return res.data;
    },

    async markAsSeen(conversationId: string) {
        const res = await api.patch(`/conversations/${conversationId}/seen`);
        return res.data;
    },

    async deleteConversation(conversationId: string) {
        const res = await api.delete(`/conversations/${conversationId}`);
        return res.data;
    },

    async addMembersToGroup(conversationId: string, memberIds: string[]) {
        const res = await api.post(`/conversations/${conversationId}/members`, {
            member_ids: memberIds,
        });
        return res.data;
    },

    async createInviteLink(conversationId: string, expiresDays?: number) {
        const params = expiresDays ? `?expires_days=${expiresDays}` : '';
        const res = await api.post(`/conversations/${conversationId}/invite-link${params}`);
        return res.data;
    },

    async joinGroupViaInvite(inviteCode: string) {
        const res = await api.post('/conversations/join-group', {
            invite_code: inviteCode,
        });
        return res.data;
    },

    async leaveGroup(conversationId: string) {
        const res = await api.delete(`/conversations/${conversationId}/leave`);
        return res.data;
    },

}