import "crypto";
import { readFile } from "fs/promises";

/**
 * @param {ArrayBuffer} buf 
 */
const arrayBufferToBase64 = (buf) => {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
}

const readPublicKey = async (path) => {
    const fileContents = (await readFile(path)).toString("ascii")
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "");
    
    const buf = Buffer.from(fileContents, "base64");

    return await crypto.subtle.importKey(
        "spki",
        buf,
        {
            "name": "ECDH",
            "namedCurve": "P-384",
        },
        true,
        []
    );
}

const readPrivateKey = async (path) => {
    const fileContents = (await readFile(path)).toString("ascii")
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "");
    
    const buf = Buffer.from(fileContents, "base64");

    return await crypto.subtle.importKey(
        "pkcs8",
        buf,
        {
            "name": "ECDH",
            "namedCurve": "P-384",
        },
        true,
        ["deriveKey", "deriveBits"],
    );
}

/**
 * @param {CryptoKey} pubkey 
 * @param {CryptoKey} privkey 
 */
const deriveKey = async (pubkey, privkey) => {
    return await crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: pubkey
        },
        privkey,
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
}

const deriveBits = async (pubkey, privkey) => {
    return await crypto.subtle.deriveBits(
        {
            name: "ECDH",
            public: pubkey
        },
        privkey,
        384
    );
}

const theirPubKey = await readPublicKey("alice.pem");
const myPrivKey = await readPrivateKey("bob.pfx");
const secretKey = await deriveKey(theirPubKey, myPrivKey);

const sharedSecretKey = await arrayBufferToBase64(await crypto.subtle.exportKey("raw", secretKey));
const sharedBits = arrayBufferToBase64(await deriveBits(theirPubKey, myPrivKey));

const myPubKey = await readPublicKey("bob.pem");
const theirPrivKey = await readPrivateKey("alice.pfx");

const otherSecretKey = await deriveKey(theirPubKey, myPrivKey);

console.log("sharedSecretKey", sharedSecretKey);
console.log("sharedBits", sharedBits);

console.log("sk match", sharedSecretKey == await arrayBufferToBase64(await crypto.subtle.exportKey("raw", otherSecretKey)));
console.log("bits match", sharedBits == arrayBufferToBase64(await deriveBits(theirPubKey, myPrivKey)));

const iv = new Uint8Array(96 / 8);
crypto.getRandomValues(iv);

const message = "Hello world!";

const encryptedMessage = await crypto.subtle.encrypt(
    {
        name: "AES-GCM",
        iv: iv
    },
    secretKey,
    Buffer.from(message, "ascii")
);

console.log("encrypted message", encryptedMessage);

const decryptedMessage = await crypto.subtle.decrypt(
    {
        name: "AES-GCM",
        iv: iv
    },
    otherSecretKey,
    encryptedMessage
);

console.log("decrypted message", new TextDecoder("ascii").decode(decryptedMessage));
