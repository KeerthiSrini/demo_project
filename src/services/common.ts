import crypto from "crypto";

const algorithm = "aes-256-cbc"; 
const key = "012345678901234567890123456789ab";
const iv = "0123456789abcdef";

// Encrypting text
export function encrypt(text: string) {
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted.toString("hex");
}