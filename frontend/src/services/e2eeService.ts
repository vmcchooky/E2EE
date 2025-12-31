/**
 * E2EE Service - API calls for E2EE operations
 */

import api from "@/lib/axios";

export interface PublicKeyResponse {
    user_id: string;
    username: string;
    display_name?: string;
    public_key: string;
    fingerprint: string;
    device_id?: string;
    device_name?: string;
    is_active?: boolean;
    updated_at: string;
}

export interface UserPublicKeyInfo {
    user_id: string;
    username: string;
    display_name?: string;
    fingerprint: string;
    has_public_key: boolean;
}

export interface PendingKeyEnvelope {
    id: string;
    conversation_id?: string | null;
    recipient_user_id: string;
    recipient_device_id?: string | null;
    key_version?: number | null;
    encrypted_session_key: string;
    sender_user_id: string;
    created_at: string;
    signature?: string;
    timestamp?: number;
}

export const e2eeService = {
    /**
     * Register or update my public key (multi-device support)
     */
    async registerPublicKey(publicKey: string, fingerprint: string, deviceId?: string, deviceName?: string): Promise<void> {
        await api.post("/e2ee/keys/register", {
            public_key: publicKey,
            fingerprint: fingerprint,
            device_id: deviceId,
            device_name: deviceName,
        });
    },

    /**
     * Get my public key from server
     */
    async getMyPublicKey(): Promise<PublicKeyResponse | null> {
        const res = await api.get("/e2ee/keys/me");
        return res.data.data;
    },

    /**
     * Get another user's public keys (multi-device support)
     * Returns array of public keys for all active devices
     */
    async getUserPublicKeys(userId: string, deviceId?: string): Promise<PublicKeyResponse[]> {
        const url = deviceId
            ? `/e2ee/keys/${userId}?device_id=${deviceId}`
            : `/e2ee/keys/${userId}`;
        const res = await api.get(url);
        return res.data.data || [];
    },

    /**
     * Get another user's public key (backward compatibility - returns first key)
     */
    async getUserPublicKey(userId: string): Promise<PublicKeyResponse | null> {
        const keys = await this.getUserPublicKeys(userId);
        return keys.length > 0 ? keys[0] : null;
    },

    /**
     * Get all participants' public keys in a conversation
     */
    async getConversationPublicKeys(conversationId: string): Promise<UserPublicKeyInfo[]> {
        const res = await api.get(`/e2ee/keys/conversation/${conversationId}`);
        return res.data.data || [];
    },

    /**
     * Send encrypted session key to another user (multi-device support)
     * @param recipientId - User ID of the recipient
     * @param encryptedSessionKey - Base64 encoded encrypted session key (encrypted with recipient's public key)
     * @param targetDeviceId - Optional device ID to target a specific device
     * @param conversationId - Optional conversation ID (if provided, indicates this is a group session key)
     * @param keyVersion - Optional key version (for group keys, identifies which version this is)
     */
    async exchangeSessionKey(
        recipientId: string,
        encryptedSessionKey: string,
        targetDeviceId?: string,
        conversationId?: string,
        keyVersion?: number,
        signature?: string,
        timestamp?: number
    ): Promise<void> {
        await api.post("/e2ee/session/exchange", {
            recipient_id: recipientId,
            encrypted_session_key: encryptedSessionKey,
            target_device_id: targetDeviceId,
            conversation_id: conversationId,
            key_version: keyVersion,
            signature,
            timestamp,
        });
    },

    /**
     * Fetch pending (offline) session/group keys for current user/device
     */
    async fetchPendingKeys(deviceId?: string): Promise<PendingKeyEnvelope[]> {
        const url = deviceId ? `/e2ee/pending-keys?device_id=${deviceId}` : "/e2ee/pending-keys";
        const res = await api.get(url);
        return res.data.data || [];
    },

    /**
     * Ack pending keys after successfully processing
     */
    async ackPendingKeys(ids: string[]): Promise<void> {
        if (!ids.length) return;
        await api.post("/e2ee/pending-keys/ack", { ids });
    },
};

