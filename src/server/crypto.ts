// src/server/crypto.ts
function b64ToBytes(b64: string): Uint8Array {
	const bin = atob(b64);
	const bytes = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
	return bytes;
}

function bytesToB64(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
}

export async function aesGcmEncrypt(keyB64: string, plaintext: string): Promise<string> {
	const keyBytes = b64ToBytes(keyB64);
	if (keyBytes.length !== 32) throw new Error("LICENSE_STORE_KEY must decode to 32 bytes");

	const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const data = new TextEncoder().encode(plaintext);

	const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
	const out = new Uint8Array(iv.length + enc.byteLength);
	out.set(iv, 0);
	out.set(new Uint8Array(enc), iv.length);

	return bytesToB64(out);
}

export async function aesGcmDecrypt(keyB64: string, cipherB64: string): Promise<string> {
	const keyBytes = b64ToBytes(keyB64);
	if (keyBytes.length !== 32) throw new Error("LICENSE_STORE_KEY must decode to 32 bytes");

	const raw = b64ToBytes(cipherB64);
	const iv = raw.slice(0, 12);
	const enc = raw.slice(12);

	const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
	const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, enc);

	return new TextDecoder().decode(dec);
}

export async function sha256Hex(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const hash = await crypto.subtle.digest("SHA-256", data);
	return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
