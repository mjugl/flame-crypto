import "crypto";
import { writeFile } from "node:fs/promises";

/**
 * @param {ArrayBuffer} buf 
 */
const arrayBufferToBase64 = (buf) => {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
}

const generateECDHKeyPair = async () => {
    return await crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-384"
        },
        true,
        ["deriveKey"]
    );
}

/**
 * @param {CryptoKey} key 
 */
const exportPublicKey = async (key) => {
    return await crypto.subtle.exportKey(
        "spki",
        key
    )
}

/**
 * @param {CryptoKey} key 
 */
const exportPrivateKey = async (key) => {
    return await crypto.subtle.exportKey(
        "pkcs8",
        key
    )
}

/**
 * @param {CryptoKey} key 
 * @param {string} path 
 */
const writePublicKeyTo = async (key, path) => {
    await writeFile(path, `-----BEGIN PUBLIC KEY-----\n${arrayBufferToBase64(await exportPublicKey(key))}\n-----END PUBLIC KEY-----`);
}

/**
 * @param {CryptoKey} key 
 * @param {string} path 
 */
const writePrivateKeyTo = async (key, path) => {
    await writeFile(path, `-----BEGIN PRIVATE KEY-----\n${arrayBufferToBase64(await exportPrivateKey(key))}\n-----END PRIVATE KEY-----`);
}

const aliceKeyPair = await generateECDHKeyPair();
const bobKeyPair = await generateECDHKeyPair();

await writePublicKeyTo(aliceKeyPair.publicKey, "alice.pem");
await writePublicKeyTo(bobKeyPair.publicKey, "bob.pem");

await writePrivateKeyTo(aliceKeyPair.privateKey, "alice.pfx");
await writePrivateKeyTo(bobKeyPair.privateKey, "bob.pfx");
