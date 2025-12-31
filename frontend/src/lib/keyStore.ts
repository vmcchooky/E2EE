/**
 * KeyStore - Lưu trữ keys trong IndexedDB
 * Tương đương với việc lưu keys vào file trong Python DEMO
 */

import {
    generateRSAKeyPair,
    exportPublicKey,
    exportPrivateKey,
    importPublicKey,
    importPrivateKey,
    generateFingerprint,
    exportAESKey,
    importAESKey,
    type RSAKeyPair,
} from "./crypto";

// ==================== DEVICE ID ====================

const DEVICE_ID_KEY = "e2ee_device_id";
const DEVICE_NAME_KEY = "e2ee_device_name";

/**
 * Generate or retrieve device ID (unique per browser/device)
 */
export function getOrCreateDeviceId(): string {
    let deviceId = localStorage.getItem(DEVICE_ID_KEY);

    if (!deviceId) {
        // Generate a unique device ID based on browser fingerprint
        const userAgent = navigator.userAgent;
        const language = navigator.language;
        const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        const screenSize = `${window.screen.width}x${window.screen.height}`;

        // Create a simple hash-like identifier
        const fingerprint = `${userAgent}-${language}-${timezone}-${screenSize}`;
        deviceId = btoa(fingerprint).substring(0, 32).replace(/[^a-zA-Z0-9]/g, '');

        localStorage.setItem(DEVICE_ID_KEY, deviceId);
    }

    return deviceId;
}

/**
 * Get or create device name (human-readable)
 */
export function getOrCreateDeviceName(): string {
    let deviceName = localStorage.getItem(DEVICE_NAME_KEY);

    if (!deviceName) {
        // Generate device name from user agent
        const ua = navigator.userAgent;
        let name = "Unknown Device";

        if (ua.includes("Chrome")) {
            name = "Chrome";
        } else if (ua.includes("Firefox")) {
            name = "Firefox";
        } else if (ua.includes("Safari")) {
            name = "Safari";
        } else if (ua.includes("Edge")) {
            name = "Edge";
        }

        if (ua.includes("Windows")) {
            name += " on Windows";
        } else if (ua.includes("Mac")) {
            name += " on macOS";
        } else if (ua.includes("Linux")) {
            name += " on Linux";
        } else if (ua.includes("Android")) {
            name += " on Android";
        } else if (ua.includes("iOS")) {
            name += " on iOS";
        }

        deviceName = name;
        localStorage.setItem(DEVICE_NAME_KEY, deviceName);
    }

    return deviceName;
}

const DB_NAME = "e2ee_keystore";
const DB_VERSION = 7; // Incremented for message counters (anti-replay protection)

// Store names
const STORES = {
    MY_KEYS: "my_keys",
    PUBLIC_KEYS: "public_keys",
    KNOWN_FINGERPRINTS: "known_fingerprints",
    SESSION_KEYS: "session_keys", // Direct chat session keys
    GROUP_SESSION_KEYS: "group_session_keys", // Group chat session keys
    MESSAGE_COUNTERS: "message_counters", // Anti-replay counters: send_ctr and recv_ctr per user
} as const;

// ==================== DATABASE SETUP ====================

let dbPromise: Promise<IDBDatabase> | null = null;

function getDB(): Promise<IDBDatabase> {
    if (dbPromise) {
        // Check if existing promise is still valid
        return dbPromise.then(db => {
            // Check if database is still open
            if (db.objectStoreNames.length === 0) {
                // Database was closed, reset promise and create new connection
                dbPromise = null;
                return getDB();
            }
            return db;
        }).catch(() => {
            // If promise rejected, reset and try again
            dbPromise = null;
            return getDB();
        });
    }

    dbPromise = new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onerror = () => {
            dbPromise = null; // Reset promise on error
            reject(new Error("Failed to open IndexedDB"));
        };

        request.onsuccess = () => {
            const db = request.result;

            // Handle database close event
            db.onclose = () => {
                dbPromise = null; // Reset promise when database closes
            };

            db.onerror = () => {
                dbPromise = null; // Reset promise on error
            };

            resolve(db);
        };

        request.onupgradeneeded = (event) => {
            const db = (event.target as IDBOpenDBRequest).result;

            // Create stores if they don't exist
            if (!db.objectStoreNames.contains(STORES.MY_KEYS)) {
                db.createObjectStore(STORES.MY_KEYS, { keyPath: "id" });
            }
            if (!db.objectStoreNames.contains(STORES.PUBLIC_KEYS)) {
                db.createObjectStore(STORES.PUBLIC_KEYS, { keyPath: "userId" });
            }
            if (!db.objectStoreNames.contains(STORES.KNOWN_FINGERPRINTS)) {
                db.createObjectStore(STORES.KNOWN_FINGERPRINTS, { keyPath: "userId" });
            }
            // Session keys store (composite key: currentUserId_otherUserId)
            if (!db.objectStoreNames.contains(STORES.SESSION_KEYS)) {
                const sessionKeysStore = db.createObjectStore(STORES.SESSION_KEYS, { keyPath: "id" });
                // Create index for querying by currentUserId
                sessionKeysStore.createIndex("currentUserId", "currentUserId", { unique: false });
            } else {
                // Migration: Always recreate store when upgrading to ensure new schema
                // This will clear old data but ensures consistency with new composite key format
                try {
                    db.deleteObjectStore(STORES.SESSION_KEYS);
                } catch (e) {
                    // Store might not exist or already deleted, ignore
                }
                const newSessionKeysStore = db.createObjectStore(STORES.SESSION_KEYS, { keyPath: "id" });
                newSessionKeysStore.createIndex("currentUserId", "currentUserId", { unique: false });
            }
            // Group session keys store (composite key: conversationId_keyVersion)
            // Supports multi-version keys for history decryption
            if (!db.objectStoreNames.contains(STORES.GROUP_SESSION_KEYS)) {
                const groupSessionKeysStore = db.createObjectStore(STORES.GROUP_SESSION_KEYS, { keyPath: "id" });
                groupSessionKeysStore.createIndex("currentUserId", "currentUserId", { unique: false });
                groupSessionKeysStore.createIndex("conversationId", "conversationId", { unique: false });
            } else {
                // Migration: Recreate store with new schema (composite key)
                try {
                    db.deleteObjectStore(STORES.GROUP_SESSION_KEYS);
                } catch (e) {
                    // Ignore if store doesn't exist
                }
                const newGroupSessionKeysStore = db.createObjectStore(STORES.GROUP_SESSION_KEYS, { keyPath: "id" });
                newGroupSessionKeysStore.createIndex("currentUserId", "currentUserId", { unique: false });
                newGroupSessionKeysStore.createIndex("conversationId", "conversationId", { unique: false });
            }

            // Message counters store for anti-replay protection (send_ctr and recv_ctr per user)
            if (!db.objectStoreNames.contains(STORES.MESSAGE_COUNTERS)) {
                const countersStore = db.createObjectStore(STORES.MESSAGE_COUNTERS, { keyPath: "id" });
                countersStore.createIndex("userId_otherUserId", ["userId", "otherUserId"], { unique: true });
            }
        };
    });

    return dbPromise;
}

// ==================== MY KEYS ====================

export interface KDFParams {
    algorithm: "PBKDF2";
    hash: "SHA-256";
    iterations: number;
    saltLength: number;
    keyLength: number;
}

export interface StoredKeyPair {
    id: string; // userId (key is per user, not per device)
    publicKeyBase64: string;
    // Private key is now encrypted with PIN
    encryptedPrivateKeyBase64: string; // Base64(ciphertext + auth tag)
    ivBase64: string; // Base64(IV / nonce used for AES-GCM)
    saltBase64: string; // Base64(salt used for PBKDF2)
    kdfParams: KDFParams; // KDF parameters for PBKDF2 (documented)
    createdAt: string;
}

/**
 * Save my key pair to IndexedDB (per user)
 * Private key is stored encrypted with PIN
 */
export async function saveMyKeyPair(
    userId: string,
    publicKeyBase64: string,
    encryptedPrivateKeyBase64: string,
    ivBase64: string,
    saltBase64: string
): Promise<void> {
    if (!userId) {
        throw new Error("saveMyKeyPair: userId is required");
    }

    const db = await getDB();
    const tx = db.transaction(STORES.MY_KEYS, "readwrite");
    const store = tx.objectStore(STORES.MY_KEYS);

    const keyData: StoredKeyPair = {
        id: String(userId), // Use userId as key
        publicKeyBase64,
        encryptedPrivateKeyBase64,
        ivBase64,
        saltBase64,
        kdfParams: {
            algorithm: "PBKDF2",
            hash: "SHA-256",
            iterations: 100_000,
            saltLength: 16,
            keyLength: 256,
        },
        createdAt: new Date().toISOString(),
    };

    await new Promise<void>((resolve, reject) => {
        const request = store.put(keyData);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}

/**
 * Get my key pair from IndexedDB (per user)
 */
export async function getMyKeyPair(userId: string): Promise<StoredKeyPair | null> {
    if (!userId) {
        console.warn("[KeyStore] getMyKeyPair: userId is required");
        return null;
    }

    try {
        const db = await getDB();

        // Check if database is still open and valid
        if (!db || db.objectStoreNames.length === 0) {
            throw new Error("Database connection is closed or invalid");
        }

        const tx = db.transaction(STORES.MY_KEYS, "readonly");
        const store = tx.objectStore(STORES.MY_KEYS);

        return new Promise((resolve, reject) => {
            const request = store.get(String(userId));
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => reject(request.error);

            // Handle transaction errors
            tx.onerror = () => {
                reject(tx.error || new Error("Transaction failed"));
            };
        });
    } catch (error) {
        console.error("[KeyStore] Error in getMyKeyPair:", error);
        // Reset dbPromise to force reconnect on next call if connection was closed
        if (error instanceof Error && (error.message.includes("closing") || error.message.includes("closed"))) {
            dbPromise = null;
        }
        throw error;
    }
}

/**
 * Generate new key pair and save to IndexedDB (per user)
 * Private key is encrypted with PIN before saving
 * This should ONLY be called during registration or first-time setup
 */
export async function generateAndSaveKeyPair(
    userId: string,
    pin: string
): Promise<{
    publicKeyBase64: string;
    encryptedPrivateKeyBase64: string;
    saltBase64: string;
    keyPair: RSAKeyPair;
}> {
    if (!userId) {
        throw new Error("generateAndSaveKeyPair: userId is required");
    }
    if (!pin) {
        throw new Error("generateAndSaveKeyPair: PIN is required");
    }

    // Check if key already exists for this user
    const existing = await getMyKeyPair(userId);
    if (existing) {
        throw new Error(`Key pair already exists for user ${userId}. Use getOrLoadMyKeyPair() instead.`);
    }

    // Generate RSA key pair
    const keyPair = await generateRSAKeyPair();
    const publicKeyBase64 = await exportPublicKey(keyPair.publicKey);
    const privateKeyBase64 = await exportPrivateKey(keyPair.privateKey);

    // Encrypt private key with PIN
    const { encryptPrivateKeyWithPIN } = await import("./crypto");
    const { encryptedPrivateKey, iv, salt } = await encryptPrivateKeyWithPIN(
        privateKeyBase64,
        pin,
    );

    // Save encrypted private key
    await saveMyKeyPair(userId, publicKeyBase64, encryptedPrivateKey, iv, salt);

    return {
        publicKeyBase64,
        encryptedPrivateKeyBase64: encryptedPrivateKey,
        saltBase64: salt,
        keyPair,
    };
}

/**
 * Load my key pair as CryptoKey objects (per user)
 * Requires PIN to decrypt private key
 */
export async function loadMyKeyPair(
    userId: string,
    pin: string
): Promise<RSAKeyPair | null> {
    const stored = await getMyKeyPair(userId);
    if (!stored) return null;

    if (!pin) {
        throw new Error("PIN is required to decrypt private key");
    }

    try {
        // Import public key (not encrypted)
        const publicKey = await importPublicKey(stored.publicKeyBase64);

        // Decrypt private key with PIN
        const { decryptPrivateKeyWithPIN } = await import("./crypto");
        const decryptedPrivateKeyBase64 = await decryptPrivateKeyWithPIN(
            stored.encryptedPrivateKeyBase64,
            pin,
            stored.ivBase64,
            stored.saltBase64,
        );

        if (!decryptedPrivateKeyBase64) {
            console.error("Failed to decrypt private key - wrong PIN?");
            return null;
        }

        // Import decrypted private key
        const privateKey = await importPrivateKey(decryptedPrivateKeyBase64);

        return { publicKey, privateKey };
    } catch (error) {
        console.error("Failed to load key pair:", error);
        return null;
    }
}

/**
 * Get or load my key pair (ONLY loads, does NOT generate new key)
 * This is used during login - key should already exist from registration
 * Requires PIN to decrypt private key
 * Returns null if key doesn't exist or PIN is wrong
 */
export async function getOrLoadMyKeyPair(
    userId: string,
    pin: string
): Promise<{
    publicKeyBase64: string;
    keyPair: RSAKeyPair;
} | null> {
    if (!userId) {
        console.warn("[KeyStore] getOrLoadMyKeyPair: userId is required");
        return null;
    }

    if (!pin) {
        console.warn("[KeyStore] getOrLoadMyKeyPair: PIN is required");
        return null;
    }

    const stored = await getMyKeyPair(userId);

    if (stored) {
        const keyPair = await loadMyKeyPair(userId, pin);
        if (keyPair) {
            return { publicKeyBase64: stored.publicKeyBase64, keyPair };
        }
        // If keyPair is null, PIN might be wrong
        return null;
    }

    // Key doesn't exist - return null (don't generate new key)
    // This should only happen if user registered before E2EE was implemented
    // or if user is logging in on a new device without key backup
    console.warn(`[KeyStore] No key pair found for user ${userId}. Key should be generated during registration.`);
    return null;
}

// ==================== OTHER USERS' PUBLIC KEYS ====================

export interface StoredPublicKey {
    userId: string;
    username: string;
    publicKeyBase64: string;
    fingerprint: string;
    updatedAt: string;
}

/**
 * Save another user's public key
 */
export async function saveUserPublicKey(
    userId: string,
    username: string,
    publicKeyBase64: string
): Promise<StoredPublicKey> {
    if (!userId) {
        throw new Error("saveUserPublicKey: userId is required");
    }

    // Generate fingerprint BEFORE creating transaction
    const fingerprint = await generateFingerprint(publicKeyBase64);

    const keyData: StoredPublicKey = {
        userId,
        username,
        publicKeyBase64,
        fingerprint,
        updatedAt: new Date().toISOString(),
    };

    // Create transaction AFTER all async operations are done
    const db = await getDB();
    const tx = db.transaction(STORES.PUBLIC_KEYS, "readwrite");
    const store = tx.objectStore(STORES.PUBLIC_KEYS);

    await new Promise<void>((resolve, reject) => {
        const request = store.put(keyData);
        request.onsuccess = () => resolve();
        request.onerror = () => {
            console.error("[KeyStore] Failed to save public key:", request.error);
            reject(request.error);
        };
    });

    return keyData;
}

/**
 * Get a user's public key
 */
export async function getUserPublicKey(userId: string): Promise<StoredPublicKey | null> {
    const db = await getDB();
    const tx = db.transaction(STORES.PUBLIC_KEYS, "readonly");
    const store = tx.objectStore(STORES.PUBLIC_KEYS);

    return new Promise((resolve, reject) => {
        const request = store.get(userId);
        request.onsuccess = () => resolve(request.result || null);
        request.onerror = () => reject(request.error);
    });
}

/**
 * Get all stored public keys
 */
export async function getAllUserPublicKeys(): Promise<StoredPublicKey[]> {
    const db = await getDB();
    const tx = db.transaction(STORES.PUBLIC_KEYS, "readonly");
    const store = tx.objectStore(STORES.PUBLIC_KEYS);

    return new Promise((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => resolve(request.result || []);
        request.onerror = () => reject(request.error);
    });
}

// ==================== KNOWN FINGERPRINTS (TOFU) ====================

export interface KnownFingerprint {
    userId: string;
    fingerprint: string;
    trustedAt: string;
    username: string;
}

/**
 * Save a trusted fingerprint (TOFU - Trust On First Use)
 */
export async function saveTrustedFingerprint(
    userId: string,
    username: string,
    fingerprint: string
): Promise<void> {
    if (!userId) {
        throw new Error("saveTrustedFingerprint: userId is required");
    }

    const db = await getDB();
    const tx = db.transaction(STORES.KNOWN_FINGERPRINTS, "readwrite");
    const store = tx.objectStore(STORES.KNOWN_FINGERPRINTS);

    const data: KnownFingerprint = {
        userId,
        username,
        fingerprint,
        trustedAt: new Date().toISOString(),
    };

    await new Promise<void>((resolve, reject) => {
        const request = store.put(data);
        request.onsuccess = () => resolve();
        request.onerror = () => {
            console.error("[KeyStore] Failed to save fingerprint:", request.error);
            reject(request.error);
        };
    });
}

/**
 * Get trusted fingerprint for a user
 */
export async function getTrustedFingerprint(userId: string): Promise<KnownFingerprint | null> {
    const db = await getDB();
    const tx = db.transaction(STORES.KNOWN_FINGERPRINTS, "readonly");
    const store = tx.objectStore(STORES.KNOWN_FINGERPRINTS);

    return new Promise((resolve, reject) => {
        const request = store.get(userId);
        request.onsuccess = () => resolve(request.result || null);
        request.onerror = () => reject(request.error);
    });
}

/**
 * Check if a fingerprint matches the trusted one
 * Returns: 'match' | 'new' | 'changed'
 */
export async function verifyFingerprint(
    userId: string,
    newFingerprint: string
): Promise<"match" | "new" | "changed"> {
    const trusted = await getTrustedFingerprint(userId);

    if (!trusted) {
        return "new"; // First time seeing this user
    }

    if (trusted.fingerprint === newFingerprint) {
        return "match"; // Fingerprint matches
    }

    return "changed"; // WARNING: Fingerprint changed!
}

/**
 * Get all trusted fingerprints
 */
export async function getAllTrustedFingerprints(): Promise<KnownFingerprint[]> {
    const db = await getDB();
    const tx = db.transaction(STORES.KNOWN_FINGERPRINTS, "readonly");
    const store = tx.objectStore(STORES.KNOWN_FINGERPRINTS);

    return new Promise((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => resolve(request.result || []);
        request.onerror = () => reject(request.error);
    });
}

// ==================== SESSION KEYS ====================

export interface StoredSessionKey {
    id: string; // Composite key: `${currentUserId}_${otherUserId}`
    currentUserId: string; // Current user's ID (for filtering)
    otherUserId: string; // Other user's ID
    keyBase64: string; // Base64 encoded AES key
    createdAt: string;
}

/**
 * Save a session key for a user (with current user context)
 */
export async function saveSessionKey(
    currentUserId: string,
    otherUserId: string,
    sessionKey: CryptoKey
): Promise<void> {
    if (!currentUserId || !otherUserId) {
        throw new Error("saveSessionKey: currentUserId and otherUserId are required");
    }

    // Normalize userIds to string to ensure consistency
    const normalizedCurrentUserId = String(currentUserId);
    const normalizedOtherUserId = String(otherUserId);

    // Create composite key
    const compositeKey = `${normalizedCurrentUserId}_${normalizedOtherUserId}`;

    // Export AES key to base64 BEFORE creating transaction
    const keyBytes = await exportAESKey(sessionKey);
    const keyBase64 = btoa(String.fromCharCode(...new Uint8Array(keyBytes)));

    const data: StoredSessionKey = {
        id: compositeKey,
        currentUserId: normalizedCurrentUserId,
        otherUserId: normalizedOtherUserId,
        keyBase64,
        createdAt: new Date().toISOString(),
    };

    // Create transaction AFTER all async operations are done
    const db = await getDB();
    const tx = db.transaction(STORES.SESSION_KEYS, "readwrite");
    const store = tx.objectStore(STORES.SESSION_KEYS);

    await new Promise<void>((resolve, reject) => {
        const request = store.put(data);
        request.onsuccess = () => resolve();
        request.onerror = () => {
            console.error("[KeyStore] Failed to save session key:", request.error);
            reject(request.error);
        };
    });
}

/**
 * Get a session key for a user (with current user context)
 */
export async function getSessionKey(currentUserId: string, otherUserId: string): Promise<CryptoKey | null> {
    if (!currentUserId || !otherUserId) {
        console.warn("[KeyStore] getSessionKey: currentUserId or otherUserId is empty");
        return null;
    }

    const db = await getDB();
    const tx = db.transaction(STORES.SESSION_KEYS, "readonly");
    const store = tx.objectStore(STORES.SESSION_KEYS);

    // Normalize userIds to string
    const normalizedCurrentUserId = String(currentUserId);
    const normalizedOtherUserId = String(otherUserId);

    // Create composite key
    const compositeKey = `${normalizedCurrentUserId}_${normalizedOtherUserId}`;

    const data = await new Promise<StoredSessionKey | null>((resolve, reject) => {
        const request = store.get(compositeKey);
        request.onsuccess = () => {
            resolve(request.result || null);
        };
        request.onerror = () => {
            console.error("[KeyStore] Error querying session key:", request.error);
            reject(request.error);
        };
    });

    if (!data) {
        console.warn("[KeyStore] ❌ No session key found in IndexedDB for currentUser:", normalizedCurrentUserId, "otherUser:", normalizedOtherUserId);
        return null;
    }

    try {
        // Import AES key from base64
        const keyBytes = Uint8Array.from(atob(data.keyBase64), c => c.charCodeAt(0));
        const sessionKey = await importAESKey(keyBytes.buffer);
        return sessionKey;
    } catch (error) {
        console.error("[KeyStore] Failed to import session key:", error);
        return null;
    }
}

/**
 * Get all stored session keys for current user
 */
export async function getAllSessionKeys(currentUserId: string): Promise<{ otherUserId: string; sessionKey: CryptoKey }[]> {
    if (!currentUserId) {
        return [];
    }

    const db = await getDB();
    const tx = db.transaction(STORES.SESSION_KEYS, "readonly");
    const store = tx.objectStore(STORES.SESSION_KEYS);
    const index = store.index("currentUserId");

    // Normalize userId to string
    const normalizedCurrentUserId = String(currentUserId);

    const allData = await new Promise<StoredSessionKey[]>((resolve, reject) => {
        const request = index.getAll(normalizedCurrentUserId);
        request.onsuccess = () => resolve(request.result || []);
        request.onerror = () => reject(request.error);
    });

    const results: { otherUserId: string; sessionKey: CryptoKey }[] = [];

    for (const data of allData) {
        try {
            const keyBytes = Uint8Array.from(atob(data.keyBase64), c => c.charCodeAt(0));
            const sessionKey = await importAESKey(keyBytes.buffer);
            results.push({ otherUserId: data.otherUserId, sessionKey });
        } catch (error) {
            console.error("[KeyStore] Failed to import session key for", data.otherUserId, error);
        }
    }

    return results;
}

/**
 * Delete a session key for a user (with current user context)
 */
export async function deleteSessionKey(currentUserId: string, otherUserId: string): Promise<void> {
    if (!currentUserId || !otherUserId) {
        return;
    }

    const normalizedCurrentUserId = String(currentUserId);
    const normalizedOtherUserId = String(otherUserId);
    const compositeKey = `${normalizedCurrentUserId}_${normalizedOtherUserId}`;

    const db = await getDB();
    const tx = db.transaction(STORES.SESSION_KEYS, "readwrite");
    const store = tx.objectStore(STORES.SESSION_KEYS);

    await new Promise<void>((resolve, reject) => {
        const request = store.delete(compositeKey);
        request.onsuccess = () => resolve();
        request.onerror = () => {
            console.error("[KeyStore] Failed to delete session key:", request.error);
            reject(request.error);
        };
    });
}

/**
 * Delete all session keys for a current user (on logout)
 */
export async function deleteAllSessionKeysForUser(currentUserId: string): Promise<void> {
    if (!currentUserId) {
        return;
    }

    const db = await getDB();
    const tx = db.transaction(STORES.SESSION_KEYS, "readwrite");
    const store = tx.objectStore(STORES.SESSION_KEYS);
    const index = store.index("currentUserId");

    const normalizedCurrentUserId = String(currentUserId);

    const allData = await new Promise<StoredSessionKey[]>((resolve, reject) => {
        const request = index.getAll(normalizedCurrentUserId);
        request.onsuccess = () => resolve(request.result || []);
        request.onerror = () => reject(request.error);
    });

    for (const data of allData) {
        await new Promise<void>((resolve, reject) => {
            const request = store.delete(data.id);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
}

// ==================== GROUP SESSION KEYS (ENCRYPTED + MULTI-VERSION) ====================

/**
 * SECURITY: Group session keys are NEVER stored in plaintext.
 * They are encrypted with a PIN-derived key before storage.
 * 
 * Structure:
 * - id: conversationId_keyVersion (composite key)
 * - Encrypted with AES-GCM using PIN-derived key
 * - Multiple versions can exist per conversation (for history decryption)
 */
export interface StoredGroupSessionKey {
    id: string; // conversationId_keyVersion (composite key)
    conversationId: string;
    currentUserId: string;
    keyVersion: number;
    encryptedKeyBase64: string; // ENCRYPTED with PIN-derived key
    ivBase64: string; // IV for AES-GCM decryption
    saltBase64: string; // Salt for PBKDF2 key derivation
    createdAt: string;
}

/**
 * Save a group session key for a conversation (ENCRYPTED)
 * 
 * SECURITY: Group session key is encrypted with PIN-derived key before storage.
 * PIN is used temporarily and never stored.
 * 
 * @param currentUserId - Current user's ID
 * @param conversationId - Conversation ID
 * @param keyVersion - Version of the key (1, 2, 3, ...)
 * @param sessionKey - The AES group session key to save
 * @param pin - User's PIN (used temporarily to derive encryption key)
 */
export async function saveGroupSessionKey(
    currentUserId: string,
    conversationId: string,
    keyVersion: number,
    sessionKey: CryptoKey,
    pin: string
): Promise<void> {
    if (!currentUserId || !conversationId || !pin) {
        throw new Error("saveGroupSessionKey: currentUserId, conversationId and pin are required");
    }

    if (keyVersion < 1) {
        throw new Error("saveGroupSessionKey: keyVersion must be >= 1");
    }

    const normalizedCurrentUserId = String(currentUserId);
    const normalizedConversationId = String(conversationId);
    const compositeKey = `${normalizedConversationId}_${keyVersion}`;

    // Export AES key to base64
    const { exportAESKey, encryptPrivateKeyWithPIN } = await import("./crypto");
    const keyBytes = await exportAESKey(sessionKey);
    const keyBase64 = btoa(String.fromCharCode(...new Uint8Array(keyBytes)));

    // ENCRYPT the group session key with PIN-derived key
    // This ensures the key is never stored in plaintext
    const encrypted = await encryptPrivateKeyWithPIN(keyBase64, pin);

    const data: StoredGroupSessionKey = {
        id: compositeKey,
        conversationId: normalizedConversationId,
        currentUserId: normalizedCurrentUserId,
        keyVersion,
        encryptedKeyBase64: encrypted.encryptedPrivateKey,
        ivBase64: encrypted.iv,
        saltBase64: encrypted.salt,
        createdAt: new Date().toISOString(),
    };

    const db = await getDB();
    const tx = db.transaction(STORES.GROUP_SESSION_KEYS, "readwrite");
    const store = tx.objectStore(STORES.GROUP_SESSION_KEYS);

    await new Promise<void>((resolve, reject) => {
        const request = store.put(data);
        request.onsuccess = () => resolve();
        request.onerror = () => {
            console.error("[KeyStore] Failed to save group session key:", request.error);
            reject(request.error);
        };
    });
}

/**
 * Get a group session key for a specific version (DECRYPTED)
 * 
 * @param currentUserId - Current user's ID
 * @param conversationId - Conversation ID
 * @param keyVersion - Version of the key to retrieve
 * @param pin - User's PIN (used temporarily to derive decryption key)
 */
export async function getGroupSessionKey(
    currentUserId: string,
    conversationId: string,
    keyVersion: number,
    pin: string
): Promise<CryptoKey | null> {
    if (!currentUserId || !conversationId || !pin) {
        console.warn("[KeyStore] getGroupSessionKey: missing required parameters");
        return null;
    }

    const normalizedConversationId = String(conversationId);
    const compositeKey = `${normalizedConversationId}_${keyVersion}`;

    const db = await getDB();
    const tx = db.transaction(STORES.GROUP_SESSION_KEYS, "readonly");
    const store = tx.objectStore(STORES.GROUP_SESSION_KEYS);

    const data = await new Promise<StoredGroupSessionKey | null>((resolve, reject) => {
        const request = store.get(compositeKey);
        request.onsuccess = () => resolve(request.result || null);
        request.onerror = () => {
            console.error("[KeyStore] Error querying group session key:", request.error);
            reject(request.error);
        };
    });

    if (!data) {
        return null;
    }

    try {
        // DECRYPT the group session key with PIN-derived key
        const { decryptPrivateKeyWithPIN, importAESKey } = await import("./crypto");
        const decryptedKeyBase64 = await decryptPrivateKeyWithPIN(
            data.encryptedKeyBase64,
            pin,
            data.ivBase64,
            data.saltBase64
        );

        if (!decryptedKeyBase64) {
            console.error("[KeyStore] Failed to decrypt group session key (wrong PIN?)");
            return null;
        }

        // Import AES key from base64
        const keyBytes = Uint8Array.from(atob(decryptedKeyBase64), c => c.charCodeAt(0));
        const sessionKey = await importAESKey(keyBytes.buffer);
        return sessionKey;
    } catch (error) {
        console.error("[KeyStore] Failed to decrypt/import group session key:", error);
        return null;
    }
}

/**
 * Delete a group session key for a specific version (for rollback on failure)
 * 
 * @param currentUserId - Current user's ID
 * @param conversationId - Conversation ID
 * @param keyVersion - Version of the key to delete
 */
export async function deleteGroupSessionKey(
    currentUserId: string,
    conversationId: string,
    keyVersion: number
): Promise<void> {
    if (!currentUserId || !conversationId || keyVersion < 1) {
        console.warn("[KeyStore] deleteGroupSessionKey: missing required parameters");
        return;
    }

    const normalizedConversationId = String(conversationId);
    const compositeKey = `${normalizedConversationId}_${keyVersion}`;

    try {
        const db = await getDB();
        const tx = db.transaction(STORES.GROUP_SESSION_KEYS, "readwrite");
        const store = tx.objectStore(STORES.GROUP_SESSION_KEYS);

        await new Promise<void>((resolve, reject) => {
            const request = store.delete(compositeKey);
            request.onsuccess = () => resolve();
            request.onerror = () => {
                console.error("[KeyStore] Failed to delete group session key:", request.error);
                reject(request.error);
            };
        });

        console.log(`[KeyStore] Deleted group session key v${keyVersion} for conversation ${normalizedConversationId}`);
    } catch (error) {
        console.error("[KeyStore] Error deleting group session key:", error);
    }
}

/**
 * Get all versions of group session keys for a conversation
 * Returns array of { keyVersion, sessionKey } sorted by version ascending
 */
export async function getAllGroupSessionKeysForConversation(
    currentUserId: string,
    conversationId: string,
    pin: string
): Promise<{ keyVersion: number; sessionKey: CryptoKey }[]> {
    if (!currentUserId || !conversationId || !pin) {
        return [];
    }

    const db = await getDB();
    const tx = db.transaction(STORES.GROUP_SESSION_KEYS, "readonly");
    const store = tx.objectStore(STORES.GROUP_SESSION_KEYS);

    const normalizedConversationId = String(conversationId);

    // Get all records and filter by conversationId
    const allData = await new Promise<StoredGroupSessionKey[]>((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => {
            const filtered = (request.result || []).filter(
                (d: StoredGroupSessionKey) => d.conversationId === normalizedConversationId
            );
            resolve(filtered);
        };
        request.onerror = () => reject(request.error);
    });

    const results: { keyVersion: number; sessionKey: CryptoKey }[] = [];

    for (const data of allData) {
        try {
            const { decryptPrivateKeyWithPIN, importAESKey } = await import("./crypto");
            const decryptedKeyBase64 = await decryptPrivateKeyWithPIN(
                data.encryptedKeyBase64,
                pin,
                data.ivBase64,
                data.saltBase64
            );

            if (decryptedKeyBase64) {
                const keyBytes = Uint8Array.from(atob(decryptedKeyBase64), c => c.charCodeAt(0));
                const sessionKey = await importAESKey(keyBytes.buffer);
                results.push({ keyVersion: data.keyVersion, sessionKey });
            }
        } catch (error) {
            console.error(`[KeyStore] Failed to decrypt group session key version ${data.keyVersion}:`, error);
        }
    }

    // Sort by keyVersion ascending
    return results.sort((a, b) => a.keyVersion - b.keyVersion);
}

/**
 * Get all group session keys for current user (all conversations, all versions)
 * Returns map of conversationId -> { keyVersion -> sessionKey }
 */
export async function getAllGroupSessionKeys(
    currentUserId: string,
    pin: string
): Promise<{ conversationId: string; keyVersion: number; sessionKey: CryptoKey }[]> {
    if (!currentUserId || !pin) {
        return [];
    }

    const db = await getDB();
    const tx = db.transaction(STORES.GROUP_SESSION_KEYS, "readonly");
    const store = tx.objectStore(STORES.GROUP_SESSION_KEYS);
    const index = store.index("currentUserId");

    const normalizedCurrentUserId = String(currentUserId);

    const allData = await new Promise<StoredGroupSessionKey[]>((resolve, reject) => {
        const request = index.getAll(normalizedCurrentUserId);
        request.onsuccess = () => resolve(request.result || []);
        request.onerror = () => reject(request.error);
    });

    const results: { conversationId: string; keyVersion: number; sessionKey: CryptoKey }[] = [];

    for (const data of allData) {
        try {
            const { decryptPrivateKeyWithPIN, importAESKey } = await import("./crypto");
            const decryptedKeyBase64 = await decryptPrivateKeyWithPIN(
                data.encryptedKeyBase64,
                pin,
                data.ivBase64,
                data.saltBase64
            );

            if (decryptedKeyBase64) {
                const keyBytes = Uint8Array.from(atob(decryptedKeyBase64), c => c.charCodeAt(0));
                const sessionKey = await importAESKey(keyBytes.buffer);
                results.push({
                    conversationId: data.conversationId,
                    keyVersion: data.keyVersion,
                    sessionKey,
                });
            }
        } catch (error) {
            console.error(`[KeyStore] Failed to decrypt group session key for ${data.conversationId}:`, error);
        }
    }

    return results;
}

/**
 * Get the latest (highest) key version for a conversation
 */
export async function getLatestGroupKeyVersion(
    currentUserId: string,
    conversationId: string
): Promise<number> {
    if (!currentUserId || !conversationId) {
        return 0;
    }

    const db = await getDB();
    const tx = db.transaction(STORES.GROUP_SESSION_KEYS, "readonly");
    const store = tx.objectStore(STORES.GROUP_SESSION_KEYS);

    const normalizedConversationId = String(conversationId);

    const allData = await new Promise<StoredGroupSessionKey[]>((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => {
            const filtered = (request.result || []).filter(
                (d: StoredGroupSessionKey) => d.conversationId === normalizedConversationId
            );
            resolve(filtered);
        };
        request.onerror = () => reject(request.error);
    });

    if (allData.length === 0) {
        return 0;
    }

    return Math.max(...allData.map(d => d.keyVersion));
}

/**
 * Delete all group session keys for a conversation (when user leaves group)
 * NOTE: This should rarely be used - prefer keeping keys for history decryption
 */
export async function deleteAllGroupSessionKeysForConversation(
    conversationId: string
): Promise<void> {
    if (!conversationId) {
        return;
    }

    const normalizedConversationId = String(conversationId);

    const db = await getDB();
    const tx = db.transaction(STORES.GROUP_SESSION_KEYS, "readwrite");
    const store = tx.objectStore(STORES.GROUP_SESSION_KEYS);

    const allData = await new Promise<StoredGroupSessionKey[]>((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => {
            const filtered = (request.result || []).filter(
                (d: StoredGroupSessionKey) => d.conversationId === normalizedConversationId
            );
            resolve(filtered);
        };
        request.onerror = () => reject(request.error);
    });

    for (const data of allData) {
        await new Promise<void>((resolve, reject) => {
            const request = store.delete(data.id);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
}

/**
 * Delete all group session keys for current user (on logout)
 * NOTE: Keys remain encrypted, so this is mainly for cleanup
 */
export async function deleteAllGroupSessionKeysForUser(currentUserId: string): Promise<void> {
    if (!currentUserId) {
        return;
    }

    const db = await getDB();
    const tx = db.transaction(STORES.GROUP_SESSION_KEYS, "readwrite");
    const store = tx.objectStore(STORES.GROUP_SESSION_KEYS);
    const index = store.index("currentUserId");

    const normalizedCurrentUserId = String(currentUserId);

    const allData = await new Promise<StoredGroupSessionKey[]>((resolve, reject) => {
        const request = index.getAll(normalizedCurrentUserId);
        request.onsuccess = () => resolve(request.result || []);
        request.onerror = () => reject(request.error);
    });

    for (const data of allData) {
        await new Promise<void>((resolve, reject) => {
            const request = store.delete(data.id);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
}

// ==================== CLEAR DATA ====================

/**
 * Clear E2EE data for logout (but keep MY_KEYS - they persist across sessions)
 * Only clears session keys, public keys of others, and fingerprints
 */
export async function clearAllE2EEData(): Promise<void> {
    const db = await getDB();

    const clearStore = (storeName: string): Promise<void> => {
        return new Promise((resolve, reject) => {
            const tx = db.transaction(storeName, "readwrite");
            const store = tx.objectStore(storeName);
            const request = store.clear();
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    };

    // DO NOT clear MY_KEYS - they need to persist across sessions for key continuity
    // Only clear session keys, public keys of others, and fingerprints
    await Promise.all([
        // clearStore(STORES.MY_KEYS), // KEEP THIS - key continuity requires persistence
        clearStore(STORES.PUBLIC_KEYS),
        clearStore(STORES.KNOWN_FINGERPRINTS),
        clearStore(STORES.SESSION_KEYS),
        clearStore(STORES.GROUP_SESSION_KEYS),
        clearStore(STORES.MESSAGE_COUNTERS),
    ]);
}

// ==================== MESSAGE COUNTERS (Anti-Replay Protection) ====================

export interface MessageCounters {
    id: string; // userId_otherUserId
    userId: string; // Current user ID
    otherUserId: string; // Other user ID (conversation partner)
    sendCtr: number; // Send counter (incremented when sending messages)
    recvCtr: number; // Receive counter (incremented when receiving valid messages)
    updatedAt: string; // Last update timestamp
}

/**
 * Get message counters for a conversation (send_ctr and recv_ctr)
 */
export async function getMessageCounters(
    userId: string,
    otherUserId: string
): Promise<MessageCounters | null> {
    if (!userId || !otherUserId) {
        console.warn("[KeyStore] getMessageCounters: userId or otherUserId is empty");
        return null;
    }

    const db = await getDB();
    const tx = db.transaction(STORES.MESSAGE_COUNTERS, "readonly");
    const store = tx.objectStore(STORES.MESSAGE_COUNTERS);
    const index = store.index("userId_otherUserId");

    return new Promise<MessageCounters | null>((resolve, reject) => {
        const request = index.get([userId, otherUserId]);
        request.onsuccess = () => {
            const result = request.result;
            resolve(result || null);
        };
        request.onerror = () => reject(request.error);
    });
}

/**
 * Save or update message counters
 */
export async function saveMessageCounters(
    userId: string,
    otherUserId: string,
    sendCtr: number,
    recvCtr: number
): Promise<void> {
    if (!userId || !otherUserId) {
        throw new Error("saveMessageCounters: userId and otherUserId are required");
    }

    const id = `${userId}_${otherUserId}`;
    const db = await getDB();
    const tx = db.transaction(STORES.MESSAGE_COUNTERS, "readwrite");
    const store = tx.objectStore(STORES.MESSAGE_COUNTERS);

    const data: MessageCounters = {
        id,
        userId,
        otherUserId,
        sendCtr,
        recvCtr,
        updatedAt: new Date().toISOString(),
    };

    return new Promise<void>((resolve, reject) => {
        const request = store.put(data);
        request.onsuccess = () => resolve();
        request.onerror = () => {
            console.error("[KeyStore] Failed to save message counters:", request.error);
            reject(request.error);
        };
    });
}

/**
 * Increment send counter and return new value
 */
export async function incrementSendCounter(
    userId: string,
    otherUserId: string
): Promise<number> {
    const counters = await getMessageCounters(userId, otherUserId);
    const newSendCtr = (counters?.sendCtr || 0) + 1;
    await saveMessageCounters(userId, otherUserId, newSendCtr, counters?.recvCtr || 0);
    return newSendCtr;
}

/**
 * Update receive counter if new counter is valid (must be > current recvCtr)
 * Returns true if counter was updated, false if invalid (replay attack)
 */
export async function updateRecvCounter(
    userId: string,
    otherUserId: string,
    newCounter: number
): Promise<boolean> {
    const counters = await getMessageCounters(userId, otherUserId);
    const currentRecvCtr = counters?.recvCtr || 0;

    // Validate: counter must be > current counter (anti-replay protection)
    if (newCounter <= currentRecvCtr) {
        console.warn(`[KeyStore] Replay/Out-of-order detected: newCounter=${newCounter} <= currentRecvCtr=${currentRecvCtr}`);
        return false;
    }

    // Update counter
    await saveMessageCounters(userId, otherUserId, counters?.sendCtr || 0, newCounter);
    return true;
}

/**
 * Reset counters for a conversation (when re-keying)
 */
export async function resetMessageCounters(
    userId: string,
    otherUserId: string
): Promise<void> {
    await saveMessageCounters(userId, otherUserId, 0, 0);
}

/**
 * Delete message counters for a conversation
 */
export async function deleteMessageCounters(
    userId: string,
    otherUserId: string
): Promise<void> {
    if (!userId || !otherUserId) {
        console.warn("[KeyStore] deleteMessageCounters: userId or otherUserId is empty");
        return;
    }

    const id = `${userId}_${otherUserId}`;
    const db = await getDB();
    const tx = db.transaction(STORES.MESSAGE_COUNTERS, "readwrite");
    const store = tx.objectStore(STORES.MESSAGE_COUNTERS);

    return new Promise<void>((resolve, reject) => {
        const request = store.delete(id);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}
