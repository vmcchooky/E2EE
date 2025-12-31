/**
 * E2EE Crypto Utilities using Web Crypto API
 */

// ==================== CONSTANTS ====================
const RSA_ALGORITHM = {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), // 65537
    hash: "SHA-256",
};

const RSA_SIGNING_ALGORITHM = {
    name: "RSA-PSS",
    saltLength: 32, // Recommended salt length for SHA-256
};

const AES_ALGORITHM = {
    name: "AES-GCM",
    length: 256,
};

const NONCE_LENGTH = 12; // 12 bytes for AES-GCM

// ==================== PBKDF2 (Key Derivation) ====================

/**
 * Derive encryption key from PIN using PBKDF2
 * 
 * SECURITY: PIN is never stored - only used temporarily in memory
 * Flow: PIN + salt → PBKDF2 → Symmetric key → Encrypt/Decrypt private key
 * 
 * @param pin - User's PIN (string) - used temporarily, never stored
 * @param salt - Salt (Uint8Array, stored with encrypted private key)
 * @param iterations - PBKDF2 iterations (default: 100000)
 * @returns CryptoKey for AES-GCM encryption
 */
export async function deriveKeyFromPIN(
    pin: string,
    salt: Uint8Array,
    iterations: number = 100000
): Promise<CryptoKey> {
    // Convert PIN to ArrayBuffer
    const pinBuffer = stringToArrayBuffer(pin);

    // Import PIN as key material
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        pinBuffer,
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"]
    );

    // Derive key using PBKDF2
    const derivedKey = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations,
            hash: "SHA-256",
        } as Pbkdf2Params,
        keyMaterial,
        {
            name: "AES-GCM",
            length: 256,
        },
        true, // extractable
        ["encrypt", "decrypt"],
    );

    return derivedKey;
}

/**
 * Generate random salt for PBKDF2 (16 bytes)
 */
export function generateSalt(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(16));
}

// ==================== PRIVATE KEY ENCRYPTION ====================

/**
 * Encrypt private key with PIN-derived key
 *
 * SECURITY: PIN is never stored - only used temporarily in memory
 * Flow: PIN + salt → PBKDF2 → Symmetric key → Encrypt private key
 * Salt is stored with encrypted private key for decryption later
 *
 * For storage clarity, we split:
 * - iv: Base64(IV / nonce)
 * - encryptedPrivateKey: Base64(ciphertext + auth tag)
 *
 * @param privateKeyBase64 - Private key in Base64 format
 * @param pin - User's PIN (used temporarily, never stored)
 * @param salt - Salt (if not provided, will generate new one and return it)
 * @returns Object with encrypted private key, iv and salt (all Base64)
 *          Salt + iv must be stored with encrypted private key
 */
export async function encryptPrivateKeyWithPIN(
    privateKeyBase64: string,
    pin: string,
    salt?: Uint8Array
): Promise<{ encryptedPrivateKey: string; iv: string; salt: string }> {
    // Generate salt if not provided (random 16 bytes)
    const keySalt = salt || generateSalt();

    // Derive symmetric key from PIN using PBKDF2
    // PIN is used here temporarily and never stored
    const derivedKey = await deriveKeyFromPIN(pin, keySalt);

    // Encrypt private key using AES-GCM with derived key.
    // aesEncrypt currently returns Base64(IV || ciphertext || tag)
    const combinedBase64 = await aesEncrypt(privateKeyBase64, derivedKey);

    // Decode combined and split IV and ciphertext+tag
    const combinedBytes = new Uint8Array(base64ToArrayBuffer(combinedBase64));
    const ivBytes = combinedBytes.slice(0, NONCE_LENGTH);
    const cipherBytes = combinedBytes.slice(NONCE_LENGTH); // ciphertext + tag

    const ivBase64 = arrayBufferToBase64(ivBytes.buffer);
    const encryptedPrivateKeyBase64 = arrayBufferToBase64(cipherBytes.buffer);

    // Return encrypted private key, IV and salt
    // PIN is NOT stored - user must provide it again when decrypting
    return {
        encryptedPrivateKey: encryptedPrivateKeyBase64,
        iv: ivBase64,
        salt: arrayBufferToBase64(keySalt.buffer),
    };
}

/**
 * Decrypt private key with PIN-derived key
 *
 * SECURITY: PIN is never stored - only used temporarily in memory
 * Flow: PIN + salt → PBKDF2 → Symmetric key → Decrypt private key
 *
 * @param encryptedPrivateKeyBase64 - Encrypted private key in Base64 (stored)
 * @param pin - User's PIN (provided by user, used temporarily, never stored)
 * @param ivBase64 - IV/nonce in Base64 format (stored separately)
 * @param saltBase64 - Salt in Base64 format (stored with encrypted private key)
 * @returns Decrypted private key in Base64, or null if decryption fails (wrong PIN)
 */
export async function decryptPrivateKeyWithPIN(
    encryptedPrivateKeyBase64: string,
    pin: string,
    ivBase64: string,
    saltBase64: string
): Promise<string | null> {
    try {
        // Decode salt (stored with encrypted private key)
        const salt = new Uint8Array(base64ToArrayBuffer(saltBase64));

        // Derive symmetric key from PIN using PBKDF2
        // PIN is used here temporarily and never stored
        const derivedKey = await deriveKeyFromPIN(pin, salt);

        // Decode IV and ciphertext
        const ivBytes = new Uint8Array(base64ToArrayBuffer(ivBase64));
        const cipherBytes = new Uint8Array(base64ToArrayBuffer(encryptedPrivateKeyBase64));

        // Decrypt private key using AES-GCM with derived key (no need to rejoin IV)
        const decrypted = await aesDecrypt(
            arrayBufferToBase64(cipherBytes.buffer),
            derivedKey,
            ivBytes,
        );

        // PIN is automatically cleared after function returns (not stored)
        return decrypted;
    } catch (error) {
        console.error("Failed to decrypt private key with PIN:", error);
        // This usually means wrong PIN or corrupted data
        return null;
    }
}

// ==================== UTILITY FUNCTIONS ====================

/**
 * Convert ArrayBuffer to Base64 string
 */
export function arrayBufferToBase64(buffer: ArrayBufferLike): string {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Convert Base64 string to ArrayBuffer
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Convert string to ArrayBuffer (UTF-8)
 */
export function stringToArrayBuffer(str: string): ArrayBuffer {
    const encoder = new TextEncoder();
    return encoder.encode(str).buffer;
}

/**
 * Convert ArrayBuffer to string (UTF-8)
 */
export function arrayBufferToString(buffer: ArrayBuffer): string {
    const decoder = new TextDecoder();
    return decoder.decode(buffer);
}

// ==================== RSA KEY GENERATION ====================

export interface RSAKeyPair {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
}

/**
 * Generate RSA-2048 key pair for key exchange
 */
export async function generateRSAKeyPair(): Promise<RSAKeyPair> {
    const keyPair = await crypto.subtle.generateKey(
        RSA_ALGORITHM,
        true, // extractable
        ["encrypt", "decrypt"]
    );

    return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
    };
}

/**
 * Helper to import a key specifically for Signing (RSA-PSS)
 * Since our stored keys are RSA-OAEP, we need to re-import them as PSS to sign.
 */
export async function importPrivateKeyForSigning(privateKeyBase64: string): Promise<CryptoKey> {
    const keyData = base64ToArrayBuffer(privateKeyBase64);
    return crypto.subtle.importKey(
        "pkcs8",
        keyData,
        {
            name: "RSA-PSS",
            hash: "SHA-256",
        },
        true,
        ["sign"]
    );
}

/**
 * Helper to import a key specifically for Verifying (RSA-PSS)
 */
export async function importPublicKeyForVerifying(publicKeyBase64: string): Promise<CryptoKey> {
    const keyData = base64ToArrayBuffer(publicKeyBase64);
    return crypto.subtle.importKey(
        "spki",
        keyData,
        {
            name: "RSA-PSS",
            hash: "SHA-256",
        },
        true,
        ["verify"]
    );
}


/**
 * Export public key to SPKI format (Base64)
 */
export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
    const exported = await crypto.subtle.exportKey("spki", publicKey);
    return arrayBufferToBase64(exported);
}

/**
 * Export private key to PKCS8 format (Base64)
 */
export async function exportPrivateKey(privateKey: CryptoKey): Promise<string> {
    const exported = await crypto.subtle.exportKey("pkcs8", privateKey);
    return arrayBufferToBase64(exported);
}

/**
 * Import public key from SPKI Base64
 */
export async function importPublicKey(publicKeyBase64: string): Promise<CryptoKey> {
    const keyData = base64ToArrayBuffer(publicKeyBase64);
    return crypto.subtle.importKey(
        "spki",
        keyData,
        RSA_ALGORITHM,
        true,
        ["encrypt"]
    );
}

/**
 * Import private key from PKCS8 Base64
 */
export async function importPrivateKey(privateKeyBase64: string): Promise<CryptoKey> {
    const keyData = base64ToArrayBuffer(privateKeyBase64);
    return crypto.subtle.importKey(
        "pkcs8",
        keyData,
        RSA_ALGORITHM,
        true,
        ["decrypt"]
    );
}

// ==================== RSA ENCRYPTION/DECRYPTION ====================

/**
 * Encrypt data with RSA public key (for key exchange)
 */
export async function rsaEncrypt(
    data: ArrayBuffer,
    publicKey: CryptoKey
): Promise<ArrayBuffer> {
    return crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        data
    );
}

/**
 * Decrypt data with RSA private key
 */
export async function rsaDecrypt(
    encryptedData: ArrayBuffer,
    privateKey: CryptoKey
): Promise<ArrayBuffer> {
    return crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedData
    );
}

// ==================== RSA SIGNING/VERIFYING ====================

/**
 * Sign data with RSA private key (PSS)
 */
export async function rsaSign(
    data: BufferSource,
    privateKey: CryptoKey
): Promise<ArrayBuffer> {
    return crypto.subtle.sign(
        RSA_SIGNING_ALGORITHM,
        privateKey,
        data
    );
}

/**
 * Verify signature with RSA public key (PSS)
 */
export async function rsaVerify(
    signature: BufferSource,
    data: BufferSource,
    publicKey: CryptoKey
): Promise<boolean> {
    return crypto.subtle.verify(
        RSA_SIGNING_ALGORITHM,
        publicKey,
        signature,
        data
    );
}


// ==================== AES KEY GENERATION ====================

/**
 * Generate AES-256 session key
 */
export async function generateAESKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
        AES_ALGORITHM,
        true, // extractable
        ["encrypt", "decrypt"]
    );
}

/**
 * Export AES key to raw bytes (for RSA encryption)
 */
export async function exportAESKey(aesKey: CryptoKey): Promise<ArrayBuffer> {
    return crypto.subtle.exportKey("raw", aesKey);
}

/**
 * Import AES key from raw bytes
 */
export async function importAESKey(keyData: ArrayBuffer): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        "raw",
        keyData,
        AES_ALGORITHM,
        true,
        ["encrypt", "decrypt"]
    );
}

// ==================== AES-GCM ENCRYPTION/DECRYPTION ====================

/**
 * Encrypt message with AES-GCM
 * Returns: nonce (12 bytes) + ciphertext + tag
 */
export async function aesEncrypt(
    plaintext: string,
    aesKey: CryptoKey,
    additionalData?: BufferSource
): Promise<string> {
    // Generate random nonce
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));

    // Convert plaintext to bytes
    const plaintextBytes = stringToArrayBuffer(plaintext);

    // Encrypt with optional AAD (Additional Authenticated Data)
    const encryptParams: AesGcmParams = {
        name: "AES-GCM",
        iv: nonce,
    };
    if (additionalData) {
        encryptParams.additionalData = additionalData;
    }

    const ciphertext = await crypto.subtle.encrypt(
        encryptParams,
        aesKey,
        plaintextBytes
    );

    // Combine nonce + ciphertext
    const combined = new Uint8Array(nonce.length + ciphertext.byteLength);
    combined.set(nonce, 0);
    combined.set(new Uint8Array(ciphertext), nonce.length);

    // Return as Base64
    return arrayBufferToBase64(combined.buffer);
}

/**
 * Decrypt message with AES-GCM
 * Input: Base64 of (nonce + ciphertext + tag)
 */
export async function aesDecrypt(
    encryptedBase64: string,
    aesKey: CryptoKey,
    iv?: Uint8Array,
    additionalData?: BufferSource
): Promise<string | null> {
    try {
        let nonce: Uint8Array;
        let ciphertext: Uint8Array;

        if (iv) {
            // New path: iv provided separately, encryptedBase64 = ciphertext+tag
            // Ensure backing buffer is ArrayBuffer (not SharedArrayBuffer)
            const ivCloned = iv.buffer.slice(0);
            nonce = new Uint8Array(ivCloned);
            ciphertext = new Uint8Array(base64ToArrayBuffer(encryptedBase64) as ArrayBuffer);
        } else {
            // Legacy path: encryptedBase64 = IV || ciphertext || tag
            const combined = new Uint8Array(base64ToArrayBuffer(encryptedBase64) as ArrayBuffer);
            nonce = combined.slice(0, NONCE_LENGTH);
            ciphertext = combined.slice(NONCE_LENGTH);
        }

        // Ensure buffers are ArrayBuffer (not SharedArrayBuffer) for WebCrypto TS types
        const nonceCloned = new Uint8Array(new ArrayBuffer(nonce.length));
        nonceCloned.set(nonce);
        const ciphertextCloned = new Uint8Array(new ArrayBuffer(ciphertext.length));
        ciphertextCloned.set(ciphertext);

        // Decrypt with optional AAD (Additional Authenticated Data)
        const decryptParams: AesGcmParams = {
            name: "AES-GCM",
            iv: nonceCloned,
        };
        if (additionalData) {
            decryptParams.additionalData = additionalData;
        }

        const plaintext = await crypto.subtle.decrypt(
            decryptParams,
            aesKey,
            ciphertextCloned
        );

        return arrayBufferToString(plaintext);
    } catch (error) {
        console.error("AES decryption failed:", error);
        return null;
    }
}

// ==================== FINGERPRINT ====================

/**
 * Generate SHA-256 fingerprint of public key (for TOFU verification)
 * Returns first 16 hex characters (64 bits)
 */
export async function generateFingerprint(publicKeyBase64: string): Promise<string> {
    const keyData = base64ToArrayBuffer(publicKeyBase64);
    const hashBuffer = await crypto.subtle.digest("SHA-256", keyData);
    const hashArray = new Uint8Array(hashBuffer);

    // Convert to hex
    const hex = Array.from(hashArray)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

    // Return first 16 characters
    return hex.substring(0, 16);
}

/**
 * Format fingerprint for display: "xxxx xxxx xxxx xxxx"
 */
export function formatFingerprint(fingerprint: string): string {
    const clean = fingerprint.replace(/\s/g, "");
    const groups: string[] = [];
    for (let i = 0; i < clean.length; i += 4) {
        groups.push(clean.substring(i, i + 4));
    }
    return groups.join(" ");
}

// ==================== KEY EXCHANGE HELPERS ====================

/**
 * Encrypt AES session key with recipient's RSA public key
 * For SESSION_OFFER message
 */
export async function encryptSessionKey(
    aesKey: CryptoKey,
    recipientPublicKey: CryptoKey
): Promise<string> {
    // Export AES key to raw bytes
    const aesKeyBytes = await exportAESKey(aesKey);

    // Encrypt with RSA
    const encryptedKey = await rsaEncrypt(aesKeyBytes, recipientPublicKey);

    // Return as Base64
    return arrayBufferToBase64(encryptedKey);
}

/**
 * Decrypt AES session key with own RSA private key
 * For receiving SESSION_OFFER
 */
export async function decryptSessionKey(
    encryptedKeyBase64: string,
    privateKey: CryptoKey
): Promise<CryptoKey> {
    // Decode Base64
    const encryptedKey = base64ToArrayBuffer(encryptedKeyBase64);

    // Decrypt with RSA
    const aesKeyBytes = await rsaDecrypt(encryptedKey, privateKey);

    // Import as AES key
    return importAESKey(aesKeyBytes);
}

// ==================== HMAC (HASH RATCHET) ====================

/**
 * Import raw key bytes as HMAC Key (SHA-256)
 */
export async function importHMACKey(raw: ArrayBuffer): Promise<CryptoKey> {
    return window.crypto.subtle.importKey(
        "raw",
        raw,
        {
            name: "HMAC",
            hash: { name: "SHA-256" },
        },
        false, // Not extractable
        ["sign", "verify"] // HMAC uses sign/verify
    );
}

/**
 * Compute HMAC-SHA256
 * Returns raw ArrayBuffer
 */
export async function hmacSha256(key: CryptoKey, data: string): Promise<ArrayBuffer> {
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(data);
    return window.crypto.subtle.sign(
        "HMAC",
        key,
        dataBytes
    );
}

