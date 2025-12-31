/**
 * E2EE Store - Quản lý trạng thái mã hóa end-to-end
 * Tương đương với session_keys, user_directory trong Python DEMO
 */

import { create } from "zustand";
import {
    generateAESKey,
    importPublicKey,
    encryptSessionKey,
    decryptSessionKey,
    aesEncrypt,
    aesDecrypt,
    generateFingerprint,
    hmacSha256,
    importHMACKey,
    importAESKey,
    exportAESKey,
    formatFingerprint,
    type RSAKeyPair,
    rsaSign,
    rsaVerify,
    importPrivateKeyForSigning,
    importPublicKeyForVerifying,
    exportPrivateKey,
    arrayBufferToBase64,
    base64ToArrayBuffer,
} from "@/lib/crypto";
import {
    getOrLoadMyKeyPair,
    getMyKeyPair,
    generateAndSaveKeyPair,
    saveUserPublicKey,
    saveTrustedFingerprint,
    getTrustedFingerprint,
    verifyFingerprint,
    clearAllE2EEData,
    saveSessionKey,
    getSessionKey,
    getAllSessionKeys,
    getUserPublicKey,
    deleteSessionKey,
    deleteAllSessionKeysForUser,
    saveGroupSessionKey,
    getAllGroupSessionKeys,
    deleteAllGroupSessionKeysForConversation,
    getOrCreateDeviceId,
    getGroupSessionKey,
    incrementSendCounter,
    updateRecvCounter,
    resetMessageCounters,
    getMessageCounters,
} from "@/lib/keyStore";
import { useAuthStore } from "./useAuthStore";
import { e2eeService } from "@/services/e2eeService";

// ==================== TYPES ====================

// (PendingKeyEnvelope is imported from e2eeService)
export interface UserE2EEInfo {
    userId: string;
    username: string;
    publicKeyBase64: string;
    fingerprint: string;
    sessionKey?: CryptoKey;
    isEstablished: boolean;
}

export interface E2EEState {
    // Initialization state
    isInitialized: boolean;
    isInitializing: boolean;

    // My keys
    myPublicKeyBase64: string | null;
    myFingerprint: string | null;
    myKeyPair: RSAKeyPair | null;

    // Other users' E2EE info
    userE2EEInfo: Record<string, UserE2EEInfo>;

    // Group session keys: conversationId -> { keyVersion -> CryptoKey }
    // MULTI-VERSION: giữ tất cả key versions để decrypt lịch sử
    groupSessionKeys: Record<string, Record<number, CryptoKey>>;
    // Current (latest) group key version per conversation (0 = chưa có)
    currentGroupKeyVersion: Record<string, number>;

    // PIN stored temporarily in memory for group key operations
    // SECURITY NOTE: Cleared on logout, never persisted to storage
    _tempPin: string | null;

    // Warning state for key changes
    keyChangeWarning: {
        userId: string;
        username: string;
        oldFingerprint: string;
        newFingerprint: string;
    } | null;

    // Actions
    initialize: (pin: string) => Promise<void>;
    reset: () => Promise<void>;
    // Generate key for new user (only during registration) - requires PIN
    generateKeyForUser: (userId: string, pin: string) => Promise<{ publicKeyBase64: string; fingerprint: string } | null>;

    // Key management
    getMyPublicKey: () => string | null;
    getMyFingerprint: () => string | null;

    // User key management
    registerUserPublicKey: (
        userId: string,
        username: string,
        publicKeyBase64: string,
        skipWarning?: boolean
    ) => Promise<{ status: "new" | "match" | "changed"; fingerprint: string }>;
    acceptNewKey: (userId: string, username: string, publicKeyBase64: string) => Promise<void>;
    dismissKeyWarning: () => Promise<void>;

    // Session key exchange
    establishSession: (userId: string, publicKeys: any[]) => Promise<boolean>;
    // initiateKeyExchange removed in favor of establishSession
    receiveKeyExchange: (senderUserId: string, encryptedKeyBase64: string, signature?: string, timestamp?: number, skipWarning?: boolean) => Promise<boolean>;
    hasSessionWith: (userId: string) => boolean;
    // Manual re-keying for direct chats (user-triggered)
    rekeyDirectChat: (userId: string) => Promise<boolean>;
    // Delete session key (disable E2EE for a user)
    deleteSession: (userId: string) => Promise<void>;

    // Encryption/Decryption
    encryptMessage: (userId: string, plaintext: string) => Promise<{ ciphertext: string; counter: number } | null>;
    decryptMessage: (msgSenderId: string, msgReceiverId: string, ciphertext: string, counter?: number) => Promise<string | null>;

    // Group E2EE (multi-version)
    initiateGroupKeyExchange: (conversationId: string, participantIds: string[], keyVersion: number) => Promise<boolean>;
    receiveGroupKeyExchange: (conversationId: string, senderUserId: string, encryptedKeyBase64: string, keyVersion: number, signature?: string, timestamp?: number) => Promise<boolean>;
    hasGroupSession: (conversationId: string) => boolean;
    hasGroupSessionVersion: (conversationId: string, keyVersion: number) => boolean;
    encryptGroupMessage: (conversationId: string, plaintext: string) => Promise<{ ciphertext: string; keyVersion: number } | null>;
    /**
     * Decrypt group message with Ratchet (Sender Keys)
     * senderId is REQUIRED to find the correct Ratchet Chain
     */
    decryptGroupMessage: (conversationId: string, senderId: string, ciphertext: string, keyVersion: number) => Promise<string | null>;
    // Delete group session keys (Disable E2EE for a group)
    deleteGroupSession: (conversationId: string) => Promise<void>;

    // Offline Key Management
    fetchPendingKeys: () => Promise<void>;

    // ==================== PHASE 2: HASH RATCHET STATE ====================
    // structure: conversationId -> version -> userId -> { chainKey: CryptoKey, step: number }
    groupRatchetState: Record<string, Record<number, Record<string, { chainKey: CryptoKey; step: number }>>>;

    // NOTE: rekeyGroup is now triggered ONLY by backend event, not by client directly

    // Fingerprint
    getUserFingerprint: (userId: string) => string | null;
    getFormattedFingerprint: (fingerprint: string) => string;
}

// ==================== STORE ====================

export const useE2EEStore = create<E2EEState>((set, get) => ({
    // Initial state
    isInitialized: false,
    isInitializing: false,
    myPublicKeyBase64: null,
    myFingerprint: null,
    myKeyPair: null,
    userE2EEInfo: {},
    groupSessionKeys: {}, // conversationId -> { keyVersion -> CryptoKey }
    currentGroupKeyVersion: {},
    groupRatchetState: {}, // Phase 2: Hash Ratchet
    _tempPin: null, // Stored temporarily, cleared on logout
    keyChangeWarning: null,

    /**
     * Initialize E2EE - Load existing key pair (does NOT generate new key)
     * Key should be generated during registration via generateKeyForUser()
     * Requires PIN to decrypt private key
     */
    initialize: async (pin: string) => {
        console.log(`[E2EE] 🛡️ initialize() called. current state: isInitialized=${get().isInitialized}, isInitializing=${get().isInitializing}`);
        if (get().isInitialized || get().isInitializing) {
            console.warn("[E2EE] ⚠️ initialize() aborted - already initialized or initializing");
            return;
        }

        if (!pin) {
            console.error("[E2EE] PIN is required to initialize E2EE");
            set({ isInitializing: false });
            return;
        }

        set({ isInitializing: true });

        try {
            // Get current user ID first
            const currentUser = useAuthStore.getState().user;
            if (!currentUser) {
                console.warn("[E2EE] No current user, cannot initialize E2EE");
                set({ isInitializing: false });
                return;
            }

            const currentUserId = String(currentUser._id);

            // Retry logic for IndexedDB operations in case of connection issues
            let publicKeyBase64: string | undefined;
            let keyPair: RSAKeyPair | undefined;
            let retries = 0;
            const maxRetries = 3;

            while (retries < maxRetries) {
                try {
                    // Try to load existing key
                    const result = await getOrLoadMyKeyPair(currentUserId, pin);

                    if (!result) {
                        // Key doesn't exist - generate new key for new user
                        // PIN is used temporarily to encrypt private key, then cleared
                        console.log(`[E2EE] No key pair found for user ${currentUserId}, generating new key...`);
                        const keyResult = await get().generateKeyForUser(currentUserId, pin);

                        if (!keyResult) {
                            console.error(`[E2EE] Failed to generate key for user ${currentUserId}`);
                            set({ isInitializing: false });
                            return;
                        }

                        // Load the newly generated key
                        const newResult = await getOrLoadMyKeyPair(currentUserId, pin);
                        if (!newResult) {
                            console.error(`[E2EE] Failed to load newly generated key for user ${currentUserId}`);
                            set({ isInitializing: false });
                            return;
                        }

                        publicKeyBase64 = newResult.publicKeyBase64;
                        keyPair = newResult.keyPair;
                    } else {
                        // Key exists - decrypt with PIN
                        publicKeyBase64 = result.publicKeyBase64;
                        keyPair = result.keyPair;
                    }

                    // PIN is automatically cleared after use (not stored anywhere)
                    break;
                } catch (error) {
                    retries++;
                    if (retries >= maxRetries) {
                        console.error("[E2EE] Failed to load/generate key pair after retries:", error);
                        set({ isInitializing: false });
                        return;
                    }
                    // Wait before retrying (exponential backoff)
                    await new Promise(resolve => setTimeout(resolve, 100 * retries));
                }
            }

            // Ensure variables are assigned
            if (!publicKeyBase64 || !keyPair) {
                console.error("[E2EE] Failed to load key pair");
                set({ isInitializing: false });
                return;
            }

            const fingerprint = await generateFingerprint(publicKeyBase64);

            // Load saved session keys from IndexedDB (only for current user)
            const savedSessionKeys = await getAllSessionKeys(currentUserId);
            const userE2EEInfo: Record<string, UserE2EEInfo> = {};

            for (const { otherUserId, sessionKey } of savedSessionKeys) {
                // Normalize userId to string for consistency
                const normalizedOtherUserId = String(otherUserId);

                // Also load user's public key info if available
                const publicKeyData = await getUserPublicKey(normalizedOtherUserId);

                userE2EEInfo[normalizedOtherUserId] = {
                    userId: normalizedOtherUserId,
                    username: publicKeyData?.username || normalizedOtherUserId,
                    publicKeyBase64: publicKeyData?.publicKeyBase64 || "",
                    fingerprint: publicKeyData?.fingerprint || "",
                    sessionKey,
                    isEstablished: true,
                };
            }

            // Load group session keys from IndexedDB (ENCRYPTED, multi-version)
            const savedGroupSessionKeys = await getAllGroupSessionKeys(currentUserId, pin);
            const groupSessionKeys: Record<string, Record<number, CryptoKey>> = {};
            const currentGroupKeyVersion: Record<string, number> = {};

            for (const { conversationId, keyVersion, sessionKey } of savedGroupSessionKeys) {
                // Initialize nested object if needed
                if (!groupSessionKeys[conversationId]) {
                    groupSessionKeys[conversationId] = {};
                }
                groupSessionKeys[conversationId][keyVersion] = sessionKey;

                // Track the latest version for each conversation
                if (!currentGroupKeyVersion[conversationId] || keyVersion > currentGroupKeyVersion[conversationId]) {
                    currentGroupKeyVersion[conversationId] = keyVersion;
                }
            }

            set({
                isInitialized: true,
                isInitializing: false,
                myPublicKeyBase64: publicKeyBase64,
                myFingerprint: fingerprint,
                myKeyPair: keyPair,
                userE2EEInfo,
                groupSessionKeys,
                currentGroupKeyVersion,
                _tempPin: pin, // Store PIN temporarily for group key operations
            });

            console.log("[E2EE] ✅ State updated. Now triggering fetchPendingKeys()...");
            // Fetch offline keys
            get().fetchPendingKeys();
            console.log("[E2EE] 🚀 fetchPendingKeys() triggered (async)");

        } catch (error) {
            console.error("[E2EE] Failed to initialize:", error);
            set({ isInitializing: false });
        }
    },

    /**
     * Generate key pair for a new user (ONLY during registration)
     * This should be called after successful registration, before login
     * Requires PIN to encrypt private key
     */
    generateKeyForUser: async (userId: string, pin: string) => {
        if (!userId) {
            console.error("[E2EE] generateKeyForUser: userId is required");
            return null;
        }

        if (!pin) {
            console.error("[E2EE] generateKeyForUser: PIN is required");
            return null;
        }

        try {
            // Check if key already exists (try to load without PIN check first)
            const stored = await getMyKeyPair(userId);
            if (stored) {
                console.warn(`[E2EE] Key already exists for user ${userId}`);
                const fingerprint = await generateFingerprint(stored.publicKeyBase64);
                return { publicKeyBase64: stored.publicKeyBase64, fingerprint };
            }

            // Generate new key pair and encrypt private key with PIN
            const result = await generateAndSaveKeyPair(userId, pin);
            const fingerprint = await generateFingerprint(result.publicKeyBase64);

            console.log(`[E2EE] Generated key pair for user ${userId} (encrypted with PIN)`);

            return { publicKeyBase64: result.publicKeyBase64, fingerprint };
        } catch (error) {
            console.error(`[E2EE] Failed to generate key for user ${userId}:`, error);
            return null;
        }
    },

    /**
     * Reset E2EE state (logout)
     * NOTE: Does NOT delete MY_KEYS or GROUP_SESSION_KEYS - they persist for key continuity
     * Group keys are encrypted with PIN so they remain safe
     * Only clears direct chat session keys and in-memory state
     */
    reset: async () => {
        try {
            // Get current user ID before clearing
            const currentUser = useAuthStore.getState().user;
            if (currentUser) {
                const currentUserId = String(currentUser._id);
                // Delete only DIRECT session keys for this user
                // DO NOT delete group session keys - they are encrypted and needed for history
                await deleteAllSessionKeysForUser(currentUserId);
                // Note: Group keys stay encrypted in IndexedDB, safe even if attacker reads DB
            }
            // Clear other E2EE data (but NOT MY_KEYS or GROUP_SESSION_KEYS - they persist)
            await clearAllE2EEData();
        } catch (error) {
            console.error("[E2EE] Failed to clear data:", error);
        }

        // Clear in-memory state including PIN (CRITICAL for security)
        set({
            isInitialized: false,
            isInitializing: false,
            myPublicKeyBase64: null,
            myFingerprint: null,
            myKeyPair: null,
            userE2EEInfo: {},
            groupSessionKeys: {},
            currentGroupKeyVersion: {},
            groupRatchetState: {}, // Phase 2: Hash Ratchet
            _tempPin: null, // CRITICAL: Clear PIN from memory on logout
            keyChangeWarning: null,
        });
    },

    getMyPublicKey: () => get().myPublicKeyBase64,
    getMyFingerprint: () => get().myFingerprint,

    /**
     * Register a user's public key (TOFU logic)
     */
    registerUserPublicKey: async (userId, username, publicKeyBase64, skipWarning = false) => {
        // Normalize userId to string for consistency
        const normalizedUserId = String(userId);

        const fingerprint = await generateFingerprint(publicKeyBase64);
        const verifyResult = await verifyFingerprint(normalizedUserId, fingerprint);

        if (verifyResult === "new") {
            // First time - trust on first use
            await saveTrustedFingerprint(normalizedUserId, username, fingerprint);
            await saveUserPublicKey(normalizedUserId, username, publicKeyBase64);

            set((state) => ({
                userE2EEInfo: {
                    ...state.userE2EEInfo,
                    [normalizedUserId]: {
                        userId: normalizedUserId,
                        username,
                        publicKeyBase64,
                        fingerprint,
                        isEstablished: false,
                    },
                },
            }));

        } else if (verifyResult === "match") {
            // Key matches - update if needed
            const existing = get().userE2EEInfo[normalizedUserId];
            if (!existing) {
                set((state) => ({
                    userE2EEInfo: {
                        ...state.userE2EEInfo,
                        [normalizedUserId]: {
                            userId: normalizedUserId,
                            username,
                            publicKeyBase64,
                            fingerprint,
                            isEstablished: false,
                        },
                    },
                }));
            }
        } else if (verifyResult === "changed") {
            // WARNING: Key changed!
            // Only show warning dialog for direct chat (skipWarning=false)
            // Group key exchange skips warning to avoid unnecessary prompts
            if (!skipWarning) {
                const trusted = await getTrustedFingerprint(normalizedUserId);
                set({
                    keyChangeWarning: {
                        userId: normalizedUserId,
                        username,
                        oldFingerprint: trusted?.fingerprint || "",
                        newFingerprint: fingerprint,
                    },
                });
                console.warn(`[E2EE] WARNING: Key changed for ${username}!`);
            } else {
                console.log(`[E2EE] Key changed for ${username} (group context, warning skipped)`);
            }
        }

        return { status: verifyResult, fingerprint };
    },

    /**
     * Accept a new key after warning (user confirmed)
     */
    acceptNewKey: async (userId, username, publicKeyBase64) => {
        const fingerprint = await generateFingerprint(publicKeyBase64);

        await saveTrustedFingerprint(userId, username, fingerprint);
        await saveUserPublicKey(userId, username, publicKeyBase64);

        // Delete old session key from IndexedDB since key changed
        try {
            const currentUser = useAuthStore.getState().user;
            if (currentUser) {
                await deleteSessionKey(String(currentUser._id), userId);
            }
        } catch (error) {
            console.error(`[E2EE] Failed to delete old session key:`, error);
        }

        set((state) => ({
            userE2EEInfo: {
                ...state.userE2EEInfo,
                [userId]: {
                    userId,
                    username,
                    publicKeyBase64,
                    fingerprint,
                    isEstablished: false,
                    sessionKey: undefined, // Clear old session
                },
            },
            keyChangeWarning: null,
        }));

    },

    dismissKeyWarning: async () => {
        const warning = get().keyChangeWarning;
        if (warning) {
            // Delete session key if it exists (user rejected key change)
            try {
                const currentUser = useAuthStore.getState().user;
                if (currentUser) {
                    await deleteSessionKey(String(currentUser._id), warning.userId);
                }

                // Also clear from memory
                set((state) => {
                    const userInfo = state.userE2EEInfo[warning.userId];
                    if (userInfo) {
                        return {
                            userE2EEInfo: {
                                ...state.userE2EEInfo,
                                [warning.userId]: {
                                    ...userInfo,
                                    sessionKey: undefined,
                                    isEstablished: false,
                                },
                            },
                            keyChangeWarning: null,
                        };
                    }
                    return { keyChangeWarning: null };
                });
            } catch (error) {
                console.error(`[E2EE] Failed to delete session key on dismiss:`, error);
                set({ keyChangeWarning: null });
            }
        } else {
            set({ keyChangeWarning: null });
        }
    },

    /**
     * Initiate key exchange with a user
     * Returns encrypted session key to send to recipient
     */
    /**
     * Establish session with a user (Multi-device support)
     * Generates a single session key, then encrypts and signs it for EACH device separately.
     */
    establishSession: async (userId, publicKeys) => {
        const normalizedUserId = String(userId);
        const state = get();

        if (!publicKeys || publicKeys.length === 0) {
            console.error(`[E2EE] No public keys provided for user ${normalizedUserId}`);
            return false;
        }

        try {
            // 1. Generate NEW AES session key (one key for all devices of this user)
            const sessionKey = await generateAESKey();

            // 2. Prepare for signing
            const myKeyPair = state.myKeyPair;
            if (!myKeyPair) throw new Error("My key pair not initialized");

            const privateKeyBase64 = await exportPrivateKey(myKeyPair.privateKey);
            const signingKey = await importPrivateKeyForSigning(privateKeyBase64);

            let successCount = 0;

            // 3. Encrypt and Sign for EACH device
            for (const keyData of publicKeys) {
                try {
                    const devicePublicKey = await importPublicKey(keyData.public_key);
                    const encryptedKey = await encryptSessionKey(sessionKey, devicePublicKey);

                    // SIGNATURE GENERATION
                    // Payload: recipientId|encryptedSessionKey|timestamp
                    // CRITICAL: We sign the SPECIFIC encrypted key for THIS device
                    const timestamp = Date.now();
                    const payloadString = `${normalizedUserId}|${encryptedKey}|${timestamp}`;
                    const payloadBuffer = new TextEncoder().encode(payloadString);

                    const signatureBuffer = await rsaSign(payloadBuffer, signingKey);
                    const signature = arrayBufferToBase64(signatureBuffer);

                    // Send to this specific device
                    await e2eeService.exchangeSessionKey(
                        normalizedUserId,
                        encryptedKey,
                        keyData.device_id,
                        undefined, // conversationId
                        undefined, // keyVersion
                        signature,
                        timestamp
                    );
                    successCount++;
                } catch (deviceError) {
                    console.error(`[E2EE] Failed to establish session with device ${keyData.device_id}:`, deviceError);
                }
            }

            if (successCount === 0) {
                console.error(`[E2EE] Failed to establish session with any device of ${normalizedUserId}`);
                return false;
            }

            // 4. Store session key in memory
            set((state) => ({
                userE2EEInfo: {
                    ...state.userE2EEInfo,
                    [normalizedUserId]: {
                        ...state.userE2EEInfo[normalizedUserId],
                        sessionKey,
                        isEstablished: true,
                    },
                },
            }));

            // 5. Save session key to IndexedDB for persistence
            try {
                const currentUser = useAuthStore.getState().user;
                if (currentUser) {
                    await saveSessionKey(String(currentUser._id), normalizedUserId, sessionKey);

                    // Reset message counters when establishing new session (anti-replay protection)
                    await resetMessageCounters(String(currentUser._id), normalizedUserId);
                    console.log(`[E2EE] Reset message counters for ${normalizedUserId} after establishing new session`);
                }

                // Also update User Info if needed (fingerprint etc) - assume caller handles registerUserPublicKey
            } catch (saveError) {
                console.error(`[E2EE] ❌ Failed to save session key to IndexedDB:`, saveError);
            }

            return true;
        } catch (error) {
            console.error(`[E2EE] Session establishment failed:`, error);
            return false;
        }
    },

    /**
     * Receive key exchange from another user
     */
    receiveKeyExchange: async (senderUserId, encryptedKeyBase64, signature, timestamp, skipWarning = false) => {
        const state = get();
        const myKeyPair = state.myKeyPair;

        if (!myKeyPair) {
            if (state.isInitialized) {
                console.error("[E2EE] My key pair not initialized");
            }
            return false;
        }

        const normalizedSenderId = String(senderUserId);

        // 1. Verify Signature if present (CRITICAL SECURITY CHECK)
        if (signature && timestamp) {
            try {
                // Get sender's public key
                // Get sender's public key
                let userInfo = state.userE2EEInfo[normalizedSenderId];
                let senderPublicKeyBase64 = userInfo?.publicKeyBase64;

                // Attempt to fetch public key if missing
                if (!senderPublicKeyBase64) {
                    console.log(`[E2EE] Public key missing for ${normalizedSenderId} during key exchange. Fetching from server...`);
                    try {
                        const keyData = await e2eeService.getUserPublicKey(normalizedSenderId);
                        if (keyData?.public_key) {
                            console.log(`[E2EE] Fetched public key for ${normalizedSenderId}. Registering...`);
                            // Pass skipWarning to prevent dialog in automatic processing contexts
                            await state.registerUserPublicKey(normalizedSenderId, keyData.username, keyData.public_key, skipWarning);
                            
                            // Refresh userInfo after registration
                            userInfo = get().userE2EEInfo[normalizedSenderId];
                            senderPublicKeyBase64 = userInfo?.publicKeyBase64;
                        }
                    } catch (err) {
                        console.error(`[E2EE] Failed to fetch public key for ${normalizedSenderId}:`, err);
                    }
                }

                if (!senderPublicKeyBase64) {
                    console.error(`[E2EE] Cannot verify signature: No public key for user ${normalizedSenderId}`);
                    // Fail safe: reject if we can't verify signature
                    return false;
                }

                // Import sender's public key for VERIFYING (RSA-PSS)
                const senderPublicKey = await importPublicKeyForVerifying(senderPublicKeyBase64);

                // Reconstruct payload: myUserId|encryptedSessionKey|timestamp
                // Note: The original payload was recipientId|encryptedSessionKey|timestamp. 
                // receiver's "myUserId" IS the sender's "recipientId".
                const myUserId = useAuthStore.getState().user?._id;
                if (!myUserId) return false;

                const payloadString = `${myUserId}|${encryptedKeyBase64}|${timestamp}`;
                const payloadBuffer = new TextEncoder().encode(payloadString);

                // Decode signature
                const signatureBuffer = base64ToArrayBuffer(signature);

                // Verify
                // Verify
                const isValid = await rsaVerify(signatureBuffer, payloadBuffer, senderPublicKey);

                if (!isValid) {
                    console.error(`[E2EE] ❌ SIGNATURE VERIFICATION FAILED from ${normalizedSenderId}`);
                    // Reject the key exchange!
                    return false;
                }

                console.log(`[E2EE] ✅ Signature verified for ${normalizedSenderId}`);

                // Check timestamp to prevent replay attacks (allow 5 minute drift)
                const now = Date.now();
                if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
                    console.warn(`[E2EE] ⚠️ Timestamp too old or in future: ${timestamp} vs ${now}`);
                    // potentially reject? for now just warn in demo
                }

            } catch (verifyError) {
                console.error(`[E2EE] Signature verification error:`, verifyError);
                return false;
            }
        } else {
            console.warn(`[E2EE] ⚠️ Received UNSIGNED key exchange from ${normalizedSenderId} - Allowing for backward compatibility but NOT SECURE`);
        }

        try {
            // Decrypt session key with my private key
            const sessionKey = await decryptSessionKey(encryptedKeyBase64, myKeyPair.privateKey);

            // Get existing user info or create new one
            const existingUserInfo = state.userE2EEInfo[normalizedSenderId];

            // Store session key in memory
            set((state) => ({
                userE2EEInfo: {
                    ...state.userE2EEInfo,
                    [normalizedSenderId]: {
                        userId: normalizedSenderId,
                        username: existingUserInfo?.username || normalizedSenderId,
                        publicKeyBase64: existingUserInfo?.publicKeyBase64 || "",
                        fingerprint: existingUserInfo?.fingerprint || "",
                        sessionKey,
                        isEstablished: true,
                    },
                },
            }));

            // Save session key to IndexedDB for persistence
            try {
                const currentUser = useAuthStore.getState().user;
                if (currentUser) {
                    await saveSessionKey(String(currentUser._id), normalizedSenderId, sessionKey);

                    // Reset message counters when receiving new session key (anti-replay protection)
                    await resetMessageCounters(String(currentUser._id), normalizedSenderId);
                    console.log(`[E2EE] Reset message counters for ${normalizedSenderId} after receiving new session key`);
                }
            } catch (saveError) {
                console.error(`[E2EE] ❌ Failed to save session key to IndexedDB:`, saveError);
                // Continue anyway - session key is in memory
            }

            return true;
        } catch (error) {
            console.error(`[E2EE] Failed to receive key exchange:`, error);
            return false;
        }
    },

    hasSessionWith: (userId) => {
        // Normalize userId to string for consistency
        const normalizedUserId = String(userId);
        const userInfo = get().userE2EEInfo[normalizedUserId];
        return userInfo?.isEstablished === true && userInfo?.sessionKey !== undefined;
    },

    /**
     * Manual re-keying for direct chats (user-triggered)
     * Deletes old session key and creates a new one, sending to all recipient devices
     * 
     * @param userId - The user ID to re-key with
     * @returns true if successful, false otherwise
     */
    rekeyDirectChat: async (userId) => {
        // Normalize userId to string for consistency
        const normalizedUserId = String(userId);
        const state = get();
        const userInfo = state.userE2EEInfo[normalizedUserId];

        if (!userInfo?.publicKeyBase64) {
            console.error(`[E2EE] No public key for user ${normalizedUserId}`);
            return false;
        }

        try {
            // Get all recipient's public keys (multi-device support)
            const publicKeys = await e2eeService.getUserPublicKeys(normalizedUserId);
            if (publicKeys.length === 0) {
                console.error(`[E2EE] No public keys found for user ${normalizedUserId}`);
                return false;
            }

            // Reuse establishSession logic which handles generation, signing, and sending to all devices
            const success = await get().establishSession(normalizedUserId, publicKeys);

            if (success) {
                console.log(`[E2EE] Re-keyed direct chat with ${normalizedUserId} successfully`);
            } else {
                console.error(`[E2EE] Failed to re-key direct chat with ${normalizedUserId}`);
            }

            return success;
        } catch (error) {
            console.error(`[E2EE] Re-keying failed:`, error);
            return false;
        }
    },

    /**
     * Delete session key (Disable E2EE for a user)
     */
    deleteSession: async (userId) => {
        const normalizedUserId = String(userId);

        try {
            const currentUser = useAuthStore.getState().user;
            if (currentUser) {
                await deleteSessionKey(String(currentUser._id), normalizedUserId);
            }
        } catch (error) {
            console.error(`[E2EE] Failed to delete session key from persistence:`, error);
        }

        // Remove from memory
        set((state) => {
            const userInfo = state.userE2EEInfo[normalizedUserId];
            if (!userInfo) return {};

            return {
                userE2EEInfo: {
                    ...state.userE2EEInfo,
                    [normalizedUserId]: {
                        ...userInfo,
                        sessionKey: undefined,
                        isEstablished: false,
                    },
                },
            };
        });

        console.log(`[E2EE] Deleted session with ${normalizedUserId}`);
    },

    /**
     * Encrypt message for a user
     */
    encryptMessage: async (userId, plaintext) => {
        // Normalize userId to string for consistency
        const normalizedUserId = String(userId);
        const userInfo = get().userE2EEInfo[normalizedUserId];

        if (!userInfo?.sessionKey) {
            console.error(`[E2EE] No session key for user ${normalizedUserId}`);
            return null;
        }

        try {
            const currentUser = useAuthStore.getState().user;
            if (!currentUser) {
                console.error(`[E2EE] No current user for encryption`);
                return null;
            }

            const currentUserId = String(currentUser._id);

            // Increment send counter for anti-replay protection
            const sendCtr = await incrementSendCounter(currentUserId, normalizedUserId);

            // Create AAD (Additional Authenticated Data) with counter
            // Format: senderId|receiverId|counter
            const aadString = `${currentUserId}|${normalizedUserId}|${sendCtr}`;
            const aad = new TextEncoder().encode(aadString);

            // Encrypt with AAD containing counter
            const ciphertext = await aesEncrypt(plaintext, userInfo.sessionKey, aad);

            // Return ciphertext and counter
            return {
                ciphertext,
                counter: sendCtr
            };
        } catch (error) {
            console.error(`[E2EE] Encryption failed:`, error);
            return null;
        }
    },

    /**
     * Decrypt message with anti-replay protection.
     * Use original msgSenderId and msgReceiverId to ensure stable AAD.
     */
    decryptMessage: async (msgSenderId, msgReceiverId, ciphertext, counter?) => {
        // Normalize userIds to string for consistency
        const normalizedSenderId = String(msgSenderId);
        const normalizedReceiverId = String(msgReceiverId);

        // Validate ciphertext
        if (!ciphertext || typeof ciphertext !== 'string' || ciphertext.length === 0) {
            console.error(`[E2EE] Invalid ciphertext from ${normalizedSenderId}`);
            return null;
        }

        try {
            const currentUser = useAuthStore.getState().user;
            if (!currentUser) {
                console.error(`[E2EE] No current user for decryption`);
                return null;
            }

            const currentUserId = String(currentUser._id);

            // Determine which shared session key to use
            const otherUserId = (currentUserId === normalizedSenderId) ? normalizedReceiverId : normalizedSenderId;
            
            // Try memory cache first, then IndexedDB
            let userInfo = get().userE2EEInfo[otherUserId];
            let sessionKey: CryptoKey | undefined = userInfo?.sessionKey;

            if (!sessionKey) {
                const loadedKey = await getSessionKey(currentUserId, otherUserId);
                if (loadedKey) {
                    sessionKey = loadedKey;
                    // Update memory cache
                    set((state) => ({
                        userE2EEInfo: {
                            ...state.userE2EEInfo,
                            [otherUserId]: {
                                ...(state.userE2EEInfo[otherUserId] || {
                                    userId: otherUserId,
                                    username: otherUserId,
                                    publicKeyBase64: "",
                                    fingerprint: "",
                                    isEstablished: true
                                }),
                                sessionKey: loadedKey,
                                isEstablished: true
                            }
                        }
                    }));
                }
            }

            if (!sessionKey) {
                console.warn(`[E2EE] No session key found for user ${otherUserId}`);
                return null;
            }

            // Anti-replay protection: validate counter if provided
            if (counter !== undefined && counter !== null) {
                const counters = await getMessageCounters(currentUserId, otherUserId);
                const currentRecvCtr = counters?.recvCtr || 0;

                // Validate counter: check if it's an old message
                if (counter <= currentRecvCtr) {
                    // It's likely an old message (loading history) or a replay.
                    // We allow decryption for history viewing, but we won't update the counter.
                    // Use debug log instead of warning to avoid console spam on generic refresh
                    // console.debug(`[E2EE] Decrypting old message (history): counter=${counter} <= currentRecvCtr=${currentRecvCtr}`);
                }
            }

            // Create AAD if counter is provided
            let aad: ArrayBuffer | undefined;
            if (counter !== undefined && counter !== null) {
                // Format: senderId|receiverId|counter
                const aadString = `${normalizedSenderId}|${normalizedReceiverId}|${counter}`;
                aad = new TextEncoder().encode(aadString).buffer;
            }

            // Decrypt using Web Crypto API
            const decrypted = await aesDecrypt(ciphertext, sessionKey, undefined, aad);

            // Update receive counter ONLY if it's a NEW message (counter > current)
            if (decrypted && counter !== undefined && counter !== null) {
                 const counters = await getMessageCounters(currentUserId, otherUserId);
                 const currentRecvCtr = counters?.recvCtr || 0;
                 if (counter > currentRecvCtr) {
                    await updateRecvCounter(currentUserId, otherUserId, counter);
                 }
            }

            return decrypted;
        } catch (error) {
            console.error(`[E2EE] Decryption failed for message from ${normalizedSenderId}:`, error);
            return null;
        }
    },

    getUserFingerprint: (userId) => {
        // Normalize userId to string for consistency
        const normalizedUserId = String(userId);
        return get().userE2EEInfo[normalizedUserId]?.fingerprint || null;
    },

    getFormattedFingerprint: (fingerprint) => {
        return formatFingerprint(fingerprint);
    },

    // ==================== GROUP E2EE (MULTI-VERSION, ENCRYPTED STORAGE) ====================

    /**
     * Initiate group key exchange - create group session key and send to all participants
     */
    initiateGroupKeyExchange: async (conversationId, participantIds, keyVersion) => {
        const normalizedConversationId = String(conversationId);
        const state = get();
        const myKeyPair = state.myKeyPair;
        const pin = state._tempPin;

        if (!myKeyPair || !pin) {
            console.error("[E2EE] ❌ Key pair or PIN not available");
            return false;
        }

        try {
            // Generate new AES group session key
            const groupSessionKey = await generateAESKey();
            const currentUser = useAuthStore.getState().user;
            if (!currentUser) return false;
            const currentUserId = String(currentUser._id);

            // Store in memory
            set((state) => ({
                groupSessionKeys: {
                    ...state.groupSessionKeys,
                    [normalizedConversationId]: {
                        ...(state.groupSessionKeys[normalizedConversationId] || {}),
                        [keyVersion]: groupSessionKey,
                    },
                },
                currentGroupKeyVersion: {
                    ...state.currentGroupKeyVersion,
                    [normalizedConversationId]: keyVersion,
                },
            }));

            // Save to IndexedDB (ENCRYPTED with PIN)
            await saveGroupSessionKey(currentUserId, normalizedConversationId, keyVersion, groupSessionKey, pin);

            // Send to participants
            const otherParticipantIds = participantIds.filter(id => String(id) !== currentUserId);
            
            // Prepare signing key
            const privateKeyBase64 = await exportPrivateKey(myKeyPair.privateKey);
            const signingKey = await importPrivateKeyForSigning(privateKeyBase64);

            for (const participantId of otherParticipantIds) {
                try {
                    const publicKeys = await e2eeService.getUserPublicKeys(participantId);
                    for (const pkInfo of publicKeys) {
                        try {
                            const publicKey = await importPublicKey(pkInfo.public_key);
                            const encryptedKey = await encryptSessionKey(groupSessionKey, publicKey);
                            // CRITICAL: Use SAME timestamp for signing and for sending
                            const timestamp = Date.now();
                            const signatureBuffer = await rsaSign(new TextEncoder().encode(`${participantId}|${encryptedKey}|${timestamp}`), signingKey);
                            const signature = arrayBufferToBase64(signatureBuffer);

                            await e2eeService.exchangeSessionKey(
                                participantId,
                                encryptedKey,
                                pkInfo.device_id,
                                normalizedConversationId,
                                keyVersion,
                                signature,
                                timestamp
                            );
                        } catch (deviceErr) {
                            console.error(`[E2EE] Failed for device ${pkInfo.device_id}:`, deviceErr);
                        }
                    }
                } catch (err) {
                    console.error(`[E2EE] Failed to send group key to ${participantId}:`, err);
                }
            }

            return true;
        } catch (error) {
            console.error(`[E2EE] Group key exchange failed:`, error);
            return false;
        }
    },

    /**
     * Receive group key exchange from another user
     */
    receiveGroupKeyExchange: async (conversationId, senderUserId, encryptedKeyBase64, keyVersion, signature, timestamp) => {
        const normalizedConversationId = String(conversationId);
        const normalizedSenderId = String(senderUserId);
        const state = get();
        const myKeyPair = state.myKeyPair;
        const pin = state._tempPin;

        if (!myKeyPair || !pin) return false;

        try {
            // 1. Verify Signature
            // 1. Verify Signature
            if (signature && timestamp) {
                let userInfo = state.userE2EEInfo[normalizedSenderId];
                let senderPublicKeyBase64 = userInfo?.publicKeyBase64;

                // Attempt to fetch public key if missing
                if (!senderPublicKeyBase64) {
                    console.log(`[E2EE] Public key missing for ${normalizedSenderId} during group key exchange. Fetching from server...`);
                    try {
                        const keyData = await e2eeService.getUserPublicKey(normalizedSenderId);
                        if (keyData?.public_key) {
                            console.log(`[E2EE] Fetched public key for ${normalizedSenderId}. Registering (group context)...`);
                            // Skip warning for group key exchange to avoid unnecessary prompts
                            await state.registerUserPublicKey(normalizedSenderId, keyData.username, keyData.public_key, true);
                            
                            // Refresh userInfo after registration
                            userInfo = get().userE2EEInfo[normalizedSenderId];
                            senderPublicKeyBase64 = userInfo?.publicKeyBase64;
                        }
                    } catch (err) {
                        console.error(`[E2EE] Failed to fetch public key for ${normalizedSenderId}:`, err);
                    }
                }

                if (!senderPublicKeyBase64) {
                    console.error(`[E2EE] Cannot verify signature for group key: No public key for user ${normalizedSenderId}`);
                    // Fail safe: reject if we can't verify signature
                    return false;
                }

                const senderPublicKey = await importPublicKeyForVerifying(senderPublicKeyBase64);
                const myUserId = useAuthStore.getState().user?._id;
                if (myUserId) {
                    const payloadString = `${myUserId}|${encryptedKeyBase64}|${timestamp}`;
                    const payloadBuffer = new TextEncoder().encode(payloadString);
                    const signatureBuffer = base64ToArrayBuffer(signature);
                    const isValid = await rsaVerify(signatureBuffer, payloadBuffer, senderPublicKey);
                    if (!isValid) {
                        console.error("[E2EE] ❌ Invalid signature for group key!");
                        return false;
                    }
                }
            }

            // 2. Decrypt Key
            const sessionKey = await decryptSessionKey(encryptedKeyBase64, myKeyPair.privateKey);

            // 3. Store Key
            const currentUser = useAuthStore.getState().user;
            if (!currentUser) return false;
            const currentUserId = String(currentUser._id);

            set((state) => ({
                groupSessionKeys: {
                    ...state.groupSessionKeys,
                    [normalizedConversationId]: {
                        ...(state.groupSessionKeys[normalizedConversationId] || {}),
                        [keyVersion]: sessionKey,
                    },
                },
                currentGroupKeyVersion: {
                    ...state.currentGroupKeyVersion,
                    [normalizedConversationId]: Math.max(
                        state.currentGroupKeyVersion[normalizedConversationId] || 0,
                        keyVersion
                    ),
                },
            }));

            await saveGroupSessionKey(currentUserId, normalizedConversationId, keyVersion, sessionKey, pin);
            return true;
        } catch (error) {
            console.error(`[E2EE] receiveGroupKeyExchange failed:`, error);
            return false;
        }
    },

    deleteGroupSession: async (conversationId) => {
        const normalizedConversationId = String(conversationId);
        const currentUser = useAuthStore.getState().user;
        if (!currentUser) return;

        try {
            // 1. Delete from memory
            set((state) => {
                const newKeys = { ...state.groupSessionKeys };
                delete newKeys[normalizedConversationId];
                const newVersions = { ...state.currentGroupKeyVersion };
                delete newVersions[normalizedConversationId];
                const newRatchets = { ...state.groupRatchetState };
                delete newRatchets[normalizedConversationId];
                return {
                    groupSessionKeys: newKeys,
                    currentGroupKeyVersion: newVersions,
                    groupRatchetState: newRatchets
                };
            });

            // 2. Delete from IDB (all versions)
            await deleteAllGroupSessionKeysForConversation(normalizedConversationId);
        } catch (error) {
            console.error("[E2EE] deleteGroupSession failed:", error);
        }
    },

    /**
     * Fetch pending (offline) keys from server
     * Call this after initialization
     */
    fetchPendingKeys: async () => {
        console.log("[E2EE] 🛰️ fetchPendingKeys() execution started");
        try {
            // Check if E2EE is initialized
            const state = get();
            if (!state.isInitialized) {
                console.warn("[E2EE] ⚠️ Cannot fetch pending keys: E2EE not initialized yet");
                return;
            }

            // 1. Fetch pending keys from server (with deviceId for multi-device support)
            const myDeviceId = getOrCreateDeviceId();
            console.log("[E2EE] ⏳ Checking for pending (offline) keys on server (deviceId:", myDeviceId, ")...");
            const pendingKeys = await e2eeService.fetchPendingKeys(myDeviceId);

            if (pendingKeys.length === 0) {
                console.log("[E2EE] ✨ No pending keys found on server.");
                return;
            }

            console.log(`[E2EE] 🔍 Found ${pendingKeys.length} pending keys on server. Starting processing...`);

            // Get my private key (state already declared above)
            const privateKey = state.myKeyPair?.privateKey;
            if (!privateKey) {
                console.error("[E2EE] ❌ Private key not available! Cannot decrypt pending keys. Please ensure you are logged in with PIN.");
                return;
            }

            const processedIds: string[] = [];

            for (const envelope of pendingKeys) {
                try {
                    const type = envelope.conversation_id ? "group" : "direct";
                    const sender = envelope.sender_user_id;
                    console.log(`[E2EE] 📦 Processing ${type} key from ${sender}...`);

                    let success = false;
                    if (envelope.conversation_id) {
                        // Group Key
                        const version = envelope.key_version || 1;
                        success = await state.receiveGroupKeyExchange(
                            envelope.conversation_id,
                            envelope.sender_user_id,
                            envelope.encrypted_session_key,
                            version,
                            envelope.signature,
                            envelope.timestamp
                        );
                    } else {
                        // Direct Key - skipWarning=true for automatic processing
                        success = await state.receiveKeyExchange(
                            envelope.sender_user_id,
                            envelope.encrypted_session_key,
                            envelope.signature,
                            envelope.timestamp,
                            true // skipWarning for automatic fetchPendingKeys
                        );
                    }

                    if (success) {
                        processedIds.push(envelope.id);
                        console.log(`[E2EE] ✅ Successfully processed key ${envelope.id}`);
                    } else {
                        console.warn(`[E2EE] ⚠️ Skipping ACK for key ${envelope.id} because processing failed.`);
                    }
                } catch (err) {
                    console.error(`[E2EE] ❌ Error processing pending key ${envelope.id}:`, err);
                }
            }

            // Ack processed keys
            if (processedIds.length > 0) {
                console.log(`[E2EE] 📤 Sending ACK for ${processedIds.length} keys to server...`);
                await e2eeService.ackPendingKeys(processedIds);
                console.log(`[E2EE] ✅ Acknowledged all ${processedIds.length} keys.`);
            }

        } catch (error) {
            console.error("[E2EE] ❌ Failed to fetch/process pending keys:", error);
            if (error instanceof Error) {
                console.error("[E2EE] Error stack:", error.stack);
            }
        }
    },

    /**
     * Check if group has any session key (any version)
     */
    hasGroupSession: (conversationId) => {
        const normalizedConversationId = String(conversationId);
        const keyVersions = get().groupSessionKeys[normalizedConversationId];
        return keyVersions !== undefined && Object.keys(keyVersions).length > 0;
    },

    /**
     * Check if group has a specific key version
     */
    hasGroupSessionVersion: (conversationId, keyVersion) => {
        const normalizedConversationId = String(conversationId);
        const keyVersions = get().groupSessionKeys[normalizedConversationId];
        return keyVersions !== undefined && keyVersions[keyVersion] !== undefined;
    },

    /**
     * Decrypt group message with Ratchet (Sender Keys)
     */
    decryptGroupMessage: async (conversationId, senderId, ciphertext, keyVersion) => {
        const normalizedConversationId = String(conversationId);
        const state = get();

        // Parse format
        let msgStep = 0;
        let realCiphertext = ciphertext;

        if (ciphertext.startsWith("STEP:")) {
            const parts = ciphertext.split(":"); // STEP:step:ciphertext
            if (parts.length >= 3) {
                msgStep = parseInt(parts[1], 10);
                realCiphertext = parts.slice(2).join(":");
            }
        } else {
            // Legacy message (AES Root Key)
            let groupSessionKey = state.groupSessionKeys[normalizedConversationId]?.[keyVersion];

            // If key not in memory, try to restore from IndexedDB
            if (!groupSessionKey) {
                console.log(`[E2EE] Key v${keyVersion} not in memory, attempting to restore from IndexedDB...`);
                const currentUser = useAuthStore.getState().user;
                const pin = state._tempPin;

                if (currentUser && pin) {
                    try {
                        const restoredKey = await getGroupSessionKey(
                            String(currentUser._id),
                            normalizedConversationId,
                            keyVersion,
                            pin
                        );
                        if (restoredKey) {
                            // Restore to memory for future use
                            set((state) => {
                                const existingKeys = state.groupSessionKeys[normalizedConversationId] || {};
                                return {
                                    groupSessionKeys: {
                                        ...state.groupSessionKeys,
                                        [normalizedConversationId]: {
                                            ...existingKeys,
                                            [keyVersion]: restoredKey,
                                        },
                                    },
                                };
                            });
                            groupSessionKey = restoredKey;
                            console.log(`[E2EE] ✅ Successfully restored key v${keyVersion} from IndexedDB`);
                        } else {
                            console.warn(`[E2EE] Key v${keyVersion} not found in IndexedDB`);
                        }
                    } catch (error) {
                        console.error(`[E2EE] Failed to restore key v${keyVersion} from IndexedDB:`, error);
                    }
                } else {
                    console.warn(`[E2EE] Cannot restore key: missing user or PIN`);
                }
            }

            if (groupSessionKey) {
                return aesDecrypt(ciphertext, groupSessionKey);
            }
            return null;
        }

        try {
            // 1. Get ROOT Key
            let groupSessionKey = state.groupSessionKeys[normalizedConversationId]?.[keyVersion];

            // If key not in memory, try to restore from IndexedDB
            if (!groupSessionKey) {
                console.log(`[E2EE] Root key v${keyVersion} not in memory, attempting to restore from IndexedDB...`);
                const currentUser = useAuthStore.getState().user;
                const pin = state._tempPin;

                if (currentUser && pin) {
                    try {
                        const restoredKey = await getGroupSessionKey(
                            String(currentUser._id),
                            normalizedConversationId,
                            keyVersion,
                            pin
                        );
                        if (restoredKey) {
                            // Restore to memory for future use
                            set((state) => {
                                const existingKeys = state.groupSessionKeys[normalizedConversationId] || {};
                                return {
                                    groupSessionKeys: {
                                        ...state.groupSessionKeys,
                                        [normalizedConversationId]: {
                                            ...existingKeys,
                                            [keyVersion]: restoredKey,
                                        },
                                    },
                                };
                            });
                            groupSessionKey = restoredKey;
                            console.log(`[E2EE] ✅ Successfully restored root key v${keyVersion} from IndexedDB`);
                        } else {
                            console.warn(`[E2EE] Root key v${keyVersion} not found in IndexedDB`);
                        }
                    } catch (error) {
                        console.error(`[E2EE] Failed to restore root key v${keyVersion} from IndexedDB:`, error);
                    }
                } else {
                    console.warn(`[E2EE] Cannot restore root key: missing user or PIN`);
                }
            }

            if (!groupSessionKey) {
                console.warn(`[E2EE] Root key v${keyVersion} missing for decryption`);
                return null;
            }
            const rootKey = groupSessionKey as unknown as CryptoKey;
            // Derive HMAC key from AES root to match WebCrypto algorithm requirements
            const rootKeyRaw = await exportAESKey(rootKey);
            const rootHmacKey = await importHMACKey(rootKeyRaw);

            // 2. Get/Initialize Sender Ratchet Chain
            let ratchet = state.groupRatchetState[normalizedConversationId]?.[keyVersion]?.[senderId];

            if (!ratchet) {
                console.log(`[E2EE] Initializing Ratchet Chain for sender ${senderId}...`);
                const chainKeyBuffer = await hmacSha256(rootHmacKey, senderId);
                const chainKey = await importHMACKey(chainKeyBuffer);
                ratchet = { chainKey, step: 0 };
            }

            // 3. Fast-Forward (Ratchet) to Message Step
            let currentChainKey = ratchet.chainKey;
            let currentStep = ratchet.step;

            // Limit fast-forward to avoid DOS (e.g., 2000 steps)
            const MAX_SKIP = 2000;
            if (msgStep < currentStep) {
                console.warn(`[E2EE] Message step ${msgStep} < current ${currentStep}. Replay or old message?`);
                // TODO: Handle late arrival messages (needs "Skipped Keys" storage)
                return null;
            }
            if (msgStep - currentStep > MAX_SKIP) {
                console.error(`[E2EE] Message step ${msgStep} too far ahead of ${currentStep}.`);
                return null;
            }

            while (currentStep < msgStep) {
                // Ratchet forward: Chain -> NextChain
                const nextChainBuffer = await hmacSha256(currentChainKey, "CHAIN_KEY");
                currentChainKey = await importHMACKey(nextChainBuffer);
                currentStep++;
            }

            // 4. Derive Message Key
            const messageKeyBuffer = await hmacSha256(currentChainKey, "MESSAGE_KEY");
            const messageKey = await importAESKey(messageKeyBuffer);

            // 5. Decrypt
            const decrypted = await aesDecrypt(realCiphertext, messageKey);

            if (decrypted) {
                // 6. Update State (only if decryption success)
                // We need to advance the chain to the NEXT step (msgStep + 1)
                // because we just used the key for msgStep.
                // Wait, for future messages we need the chain key for (msgStep + 1).
                // Currently `currentChainKey` corresponds to `msgStep`.
                // So we need one more ratchet to store the *future* chain key.

                const nextChainBuffer = await hmacSha256(currentChainKey, "CHAIN_KEY");
                const nextChainKey = await importHMACKey(nextChainBuffer);

                set((state) => ({
                    groupRatchetState: {
                        ...state.groupRatchetState,
                        [normalizedConversationId]: {
                            ...state.groupRatchetState[normalizedConversationId],
                            [keyVersion]: {
                                ...state.groupRatchetState[normalizedConversationId]?.[keyVersion],
                                [senderId]: {
                                    chainKey: nextChainKey,
                                    step: msgStep + 1
                                }
                            }
                        }
                    }
                }));
            }

            return decrypted;

        } catch (error) {
            console.error(`[E2EE] Failed to decrypt group message:`, error);
            return null;
        }
    },

    /**
     * Encrypt group message with Ratchet (Sender Keys)
     */
    encryptGroupMessage: async (conversationId, plaintext) => {
        const normalizedConversationId = String(conversationId);
        const state = get();

        // Check for PIN
        if (!state._tempPin) {
            console.error("[E2EE] encryptGroupMessage: PIN not available");
            return null;
        }

        // Get current key version
        const keyVersion = state.currentGroupKeyVersion[normalizedConversationId] || 0;
        if (keyVersion < 1) {
            console.warn(`[E2EE] encryptGroupMessage: No E2EE key for group ${conversationId}`);
            return null;
        }

        const currentUser = useAuthStore.getState().user;
        if (!currentUser) return null;
        const currentUserId = String(currentUser._id);

        try {
            // 1. Get ROOT Key
            const encryptedRootKey = state.groupSessionKeys[normalizedConversationId]?.[keyVersion];
            if (!encryptedRootKey) {
                console.error("[E2EE] Root key not found in memory");
                // TODO: Restore from IDB
                return null;
            }

            // 2. Get/Initialize My Ratchet State
            let ratchet = state.groupRatchetState[normalizedConversationId]?.[keyVersion]?.[currentUserId];

            if (!ratchet) {
                console.log("[E2EE] Initializing My Ratchet Chain...");
                const rootKey = encryptedRootKey as unknown as CryptoKey;
                // Derive a HMAC key from the AES root key to satisfy WebCrypto algorithm checks
                const rootKeyRaw = await exportAESKey(rootKey);
                const rootHmacKey = await importHMACKey(rootKeyRaw);
                const chainKeyBuffer = await hmacSha256(rootHmacKey, currentUserId);
                const chainKey = await importHMACKey(chainKeyBuffer);
                ratchet = { chainKey, step: 0 };
            }

            // 3. Ratchet Step
            const currentChainKey = ratchet.chainKey;

            // Derive Message Key
            const messageKeyBuffer = await hmacSha256(currentChainKey, "MESSAGE_KEY");
            const messageKey = await importAESKey(messageKeyBuffer);

            // Derive Next Chain Key
            const nextChainBuffer = await hmacSha256(currentChainKey, "CHAIN_KEY");
            const nextChainKey = await importHMACKey(nextChainBuffer);

            // 4. Encrypt Message
            const ciphertext = await aesEncrypt(plaintext, messageKey);

            // 5. Update State
            set((state) => ({
                groupRatchetState: {
                    ...state.groupRatchetState,
                    [normalizedConversationId]: {
                        ...state.groupRatchetState[normalizedConversationId],
                        [keyVersion]: {
                            ...state.groupRatchetState[normalizedConversationId]?.[keyVersion],
                            [currentUserId]: {
                                chainKey: nextChainKey,
                                step: ratchet.step + 1
                            }
                        }
                    }
                }
            }));

            // 6. Format Return
            const packedCiphertext = `STEP:${ratchet.step}:${ciphertext}`;
            console.log(`[E2EE] Encrypted group message (step ${ratchet.step})`);

            return {
                ciphertext: packedCiphertext,
                keyVersion: keyVersion
            };

        } catch (error) {
            console.error("[E2EE] encryptGroupMessage failed:", error);
            return null;
        }
    },

    // NOTE: rekeyGroup has been REMOVED
    // Re-keying should ONLY be triggered by backend event (group-membership-changed)
    // This prevents client-side re-key attacks and ensures version consistency
}));
