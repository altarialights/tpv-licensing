import type { LicenseStatus } from "../shared";

export interface Env {
	LICENSE_STORE_KEY: string; // base64 32 bytes
}

function json(data: any, status = 200) {
	return new Response(JSON.stringify(data), {
		status,
		headers: { "content-type": "application/json; charset=utf-8" },
	});
}

async function readJsonSafe<T>(req: Request, fallback: T): Promise<T> {
	try {
		return (await req.json()) as T;
	} catch {
		return fallback;
	}
}

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

async function aesGcmEncrypt(keyB64: string, plaintext: string): Promise<string> {
	const keyBytes = b64ToBytes(keyB64);
	if (keyBytes.length !== 32) throw new Error("LICENSE_STORE_KEY must be 32 bytes base64");

	const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const data = new TextEncoder().encode(plaintext);

	const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
	const out = new Uint8Array(iv.length + enc.byteLength);
	out.set(iv, 0);
	out.set(new Uint8Array(enc), iv.length);

	return bytesToB64(out);
}

async function aesGcmDecrypt(keyB64: string, cipherB64: string): Promise<string> {
	const keyBytes = b64ToBytes(keyB64);
	if (keyBytes.length !== 32) throw new Error("LICENSE_STORE_KEY must be 32 bytes base64");

	const raw = b64ToBytes(cipherB64);
	const iv = raw.slice(0, 12);
	const enc = raw.slice(12);

	const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
	const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, enc);

	return new TextDecoder().decode(dec);
}

type StateRow = {
	tenant_id: string;
	device_id: string;
	instance_id: string | null;
	status: LicenseStatus;
	expires_at: string | null;
	license_key_enc: string;
	meta_json: string | null;
	updated_at: number;
	created_at: number;
};

export class Chat {
	constructor(private state: DurableObjectState, private env: Env) { }

	private ensureSchema() {
		this.state.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS license_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        tenant_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        instance_id TEXT,
        status TEXT NOT NULL,
        expires_at TEXT,
        license_key_enc TEXT NOT NULL,
        meta_json TEXT,
        updated_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      );
    `);
	}

	async fetch(request: Request): Promise<Response> {
		this.ensureSchema();
		const url = new URL(request.url);

		// OJO: rutas SIN /internal (para que cuadren con https://do/get)
		if (url.pathname === "/get" && request.method === "GET") {
			const row = this.state.storage.sql
				.exec(`SELECT * FROM license_state WHERE id=1 LIMIT 1;`)
				.toArray()[0] as StateRow | undefined;

			if (!row) return json({ ok: false, error: "not_found" }, 404);
			return json({ ok: true, row });
		}

		if (url.pathname === "/upsert" && request.method === "POST") {
			const body = await readJsonSafe(request, {
				tenantId: "",
				deviceId: "",
				instanceId: null as string | null,
				status: "invalid" as LicenseStatus,
				expiresAt: null as string | null,
				licenseKey: "",
				meta: null as any,
			});

			if (!body.tenantId || !body.deviceId || !body.licenseKey) {
				return json({ ok: false, error: "bad_request" }, 400);
			}

			const now = Date.now();
			const encKey = await aesGcmEncrypt(this.env.LICENSE_STORE_KEY, String(body.licenseKey));
			const metaJson = body.meta ? JSON.stringify(body.meta) : null;

			this.state.storage.sql.exec(
				`INSERT INTO license_state
          (id, tenant_id, device_id, instance_id, status, expires_at, license_key_enc, meta_json, updated_at, created_at)
         VALUES
          (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
          tenant_id=excluded.tenant_id,
          device_id=excluded.device_id,
          instance_id=excluded.instance_id,
          status=excluded.status,
          expires_at=excluded.expires_at,
          license_key_enc=excluded.license_key_enc,
          meta_json=excluded.meta_json,
          updated_at=excluded.updated_at;`,
				body.tenantId,
				body.deviceId,
				body.instanceId,
				body.status,
				body.expiresAt,
				encKey,
				metaJson,
				now,
				now
			);

			return json({ ok: true });
		}

		if (url.pathname === "/get-decrypted" && request.method === "GET") {
			const row = this.state.storage.sql
				.exec(`SELECT * FROM license_state WHERE id=1 LIMIT 1;`)
				.toArray()[0] as StateRow | undefined;

			if (!row) return json({ ok: false, error: "not_found" }, 404);

			const licenseKey = await aesGcmDecrypt(this.env.LICENSE_STORE_KEY, row.license_key_enc);
			return json({ ok: true, row: { ...row, licenseKey } });
		}

		return new Response("Not found", { status: 404 });
	}
}
