import { SignJWT, jwtVerify } from "jose";
import type {
	ActivateRequest,
	ActivateResponse,
	ApiError,
	LemonWebhookPayload,
	LicenseStatus,
} from "../shared";
import { Chat } from "./chat";

export { Chat };

export interface Env {
	// Secrets (ponlos como secrets/vars en Cloudflare)
	LEMON_WEBHOOK_SECRET: string; // "Signing secret" del webhook
	LICENSE_JWT_SECRET: string;   // para firmar JWT
	LICENSE_STORE_KEY: string;    // base64 32 bytes (AES-GCM)

	Chat: DurableObjectNamespace;
}

// ---------------- Helpers ----------------

function json(data: any, status = 200) {
	return new Response(JSON.stringify(data), {
		status,
		headers: { "content-type": "application/json; charset=utf-8" },
	});
}

function requireJson(req: Request) {
	const ct = req.headers.get("content-type") || "";
	if (!ct.toLowerCase().includes("application/json")) {
		return json({ ok: false, error: "Content-Type must be application/json" }, 415);
	}
	return null;
}

async function readJsonSafe<T>(req: Request, fallback: T): Promise<T> {
	try {
		return (await req.json()) as T;
	} catch {
		return fallback;
	}
}

function secretKey(str: string) {
	return new TextEncoder().encode(str);
}

async function signToken(env: Env, claims: { tenantId: string; deviceId: string; licHash: string }) {
	return await new SignJWT(claims)
		.setProtectedHeader({ alg: "HS256", typ: "JWT" })
		.setIssuedAt()
		.setExpirationTime("30d")
		.sign(secretKey(env.LICENSE_JWT_SECRET));
}

async function verifyToken(env: Env, token: string) {
	const { payload } = await jwtVerify(token, secretKey(env.LICENSE_JWT_SECRET), {
		algorithms: ["HS256"],
	});

	const tenantId = String(payload.tenantId || "");
	const deviceId = String(payload.deviceId || "");
	const licHash = String(payload.licHash || "");

	if (!tenantId || !deviceId || !licHash) throw new Error("Invalid token claims");
	return { tenantId, deviceId, licHash };
}

async function sha256Hex(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const hash = await crypto.subtle.digest("SHA-256", data);
	return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqualHex(a: string, b: string) {
	if (a.length !== b.length) return false;
	let out = 0;
	for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return out === 0;
}

async function verifyLemonSignature(req: Request, secret: string, rawBody: string) {
	// Lemon firma con HMAC SHA-256 y lo manda como HEX en X-Signature :contentReference[oaicite:5]{index=5}
	const sig = (req.headers.get("X-Signature") || "").trim();
	if (!sig) return false;

	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"]
	);

	const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(rawBody));
	const hex = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");

	return timingSafeEqualHex(hex, sig);
}

function getLicenseStub(env: Env, licHash: string) {
	// 1 DO por licencia (licHash)
	const id = env.Chat.idFromName("lic:" + licHash);
	return env.Chat.get(id);
}

// ---------------- Lemon License API ----------------
// Docs oficiales (License API) 

async function lemonActivate(licenseKey: string, instanceName: string) {
	const body = new URLSearchParams();
	body.set("license_key", licenseKey);
	body.set("instance_name", instanceName);

	const r = await fetch("https://api.lemonsqueezy.com/v1/licenses/activate", {
		method: "POST",
		headers: {
			Accept: "application/json",
			"content-type": "application/x-www-form-urlencoded",
		},
		body,
	});

	const text = await r.text();
	let data: any = null;
	try { data = JSON.parse(text); } catch { }
	return { ok: r.ok, status: r.status, data, text };
}

async function lemonValidate(licenseKey: string, instanceId?: string | null) {
	const body = new URLSearchParams();
	body.set("license_key", licenseKey);
	if (instanceId) body.set("instance_id", instanceId);

	const r = await fetch("https://api.lemonsqueezy.com/v1/licenses/validate", {
		method: "POST",
		headers: {
			Accept: "application/json",
			"content-type": "application/x-www-form-urlencoded",
		},
		body,
	});

	const text = await r.text();
	let data: any = null;
	try { data = JSON.parse(text); } catch { }
	return { ok: r.ok, status: r.status, data, text };
}

// ---------------- Worker Routes ----------------

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		if (url.pathname === "/health") {
			return json({ ok: true, service: "tpv-licensing", ts: Date.now() });
		}

		// 1) WEBHOOK Lemon
		if (url.pathname === "/v1/webhooks/lemon" && request.method === "POST") {
			const raw = await request.text();

			const validSig = await verifyLemonSignature(request, env.LEMON_WEBHOOK_SECRET, raw);
			if (!validSig) return json({ ok: false, error: "invalid_signature" }, 401);

			let payload: LemonWebhookPayload | null = null;
			try {
				payload = JSON.parse(raw);
			} catch {
				return json({ ok: false, error: "invalid_json" }, 400);
			}

			const eventName = String(payload?.meta?.event_name || "");
			const attrs = payload?.data?.attributes || {};

			// En license_key_created suele venir attrs.key y attrs.status :contentReference[oaicite:7]{index=7}
			const licenseKey = String((attrs as any).key || "").trim();
			const status = String((attrs as any).status || "").trim() as LicenseStatus;
			const expiresAt = (attrs as any).expires_at ? String((attrs as any).expires_at) : null;

			if (licenseKey) {
				const licHash = await sha256Hex(licenseKey);
				const stub = getLicenseStub(env, licHash);

				// Guardamos con placeholders si aún no hay activación en app
				await stub.fetch("https://do/upsert", {
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({
						tenantId: "PENDING",
						deviceId: "PENDING",
						instanceId: null,
						status: (status || "active") as LicenseStatus,
						expiresAt,
						licenseKey,
						meta: { eventName, payload },
					}),
				});
			}

			return json({ ok: true, received: true, eventName });
		}

		// 2) ACTIVAR (TPV MAIN)
		if (url.pathname === "/v1/license/activate" && request.method === "POST") {
			const err = requireJson(request);
			if (err) return err;

			const body = await readJsonSafe<ActivateRequest>(request, {
				activationKey: "",
				deviceId: "",
			});

			const activationKey = String(body.activationKey || "").trim();
			const deviceId = String(body.deviceId || "").trim();
			const instanceName = String(body.instanceName || `tpv-${deviceId.slice(0, 12)}`).trim();

			if (!activationKey || !deviceId) {
				const out: ApiError = { ok: false, error: "activationKey and deviceId required" };
				return json(out, 400);
			}

			const act = await lemonActivate(activationKey, instanceName);
			if (!act.ok) {
				const out: ApiError = { ok: false, error: act.data?.error || "lemon_activate_failed", details: act.data || act.text };
				return json(out, 400);
			}

			const licenseKeyObj = act.data?.license_key;
			const instanceObj = act.data?.instance;

			const status = (licenseKeyObj?.status || "active") as LicenseStatus;
			const expiresAt = licenseKeyObj?.expires_at ? String(licenseKeyObj.expires_at) : null;
			const instanceId = instanceObj?.id ? String(instanceObj.id) : null;

			const licHash = await sha256Hex(activationKey);
			const stub = getLicenseStub(env, licHash);

			// tenantId definitivo (uno por cliente/restaurante)
			const tenantId = crypto.randomUUID();

			await stub.fetch("https://do/upsert", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					tenantId,
					deviceId,
					instanceId,
					status,
					expiresAt,
					licenseKey: activationKey,
					meta: act.data?.meta || null,
				}),
			});

			const token = await signToken(env, { tenantId, deviceId, licHash });

			const out: ActivateResponse = {
				ok: true,
				tenantId,
				token,
				status,
				expiresAt,
			};

			return json(out);
		}

		// 3) STATUS
		if (url.pathname === "/v1/license/status" && request.method === "GET") {
			const h = request.headers.get("authorization") || "";
			const m = h.match(/^Bearer\s+(.+)$/i);
			if (!m) return json({ ok: false, error: "missing_token" }, 401);

			let claims: { tenantId: string; deviceId: string; licHash: string };
			try {
				claims = await verifyToken(env, m[1]);
			} catch {
				return json({ ok: false, error: "invalid_token" }, 401);
			}

			const stub = getLicenseStub(env, claims.licHash);
			const cur = await stub.fetch("https://do/get", { method: "GET" });
			if (!cur.ok) return json({ ok: false, error: "not_found" }, 404);

			const j = await cur.json<any>();
			return json({ ok: true, state: j.row, serverTime: Date.now() });
		}

		// 4) VALIDATE (re-check con Lemon)
		if (url.pathname === "/v1/license/validate" && request.method === "POST") {
			const h = request.headers.get("authorization") || "";
			const m = h.match(/^Bearer\s+(.+)$/i);
			if (!m) return json({ ok: false, error: "missing_token" }, 401);

			let claims: { tenantId: string; deviceId: string; licHash: string };
			try {
				claims = await verifyToken(env, m[1]);
			} catch {
				return json({ ok: false, error: "invalid_token" }, 401);
			}

			const stub = getLicenseStub(env, claims.licHash);

			const dec = await stub.fetch("https://do/get-decrypted", { method: "GET" });
			if (!dec.ok) return json({ ok: false, error: "not_found" }, 404);
			const dj = await dec.json<any>();

			const licenseKey = String(dj?.row?.licenseKey || "");
			const instanceId = dj?.row?.instance_id ? String(dj.row.instance_id) : null;

			const val = await lemonValidate(licenseKey, instanceId);
			if (!val.ok) return json({ ok: false, error: "lemon_validate_failed", details: val.data || val.text }, 400);

			const status = (val.data?.license_key?.status || "active") as LicenseStatus;
			const expiresAt = val.data?.license_key?.expires_at ? String(val.data.license_key.expires_at) : null;

			await stub.fetch("https://do/upsert", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					tenantId: dj.row.tenant_id,
					deviceId: dj.row.device_id,
					instanceId,
					status,
					expiresAt,
					licenseKey,
					meta: val.data?.meta || null,
				}),
			});

			return json({ ok: true, status, expiresAt, valid: val.data?.valid, meta: val.data?.meta });
		}

		return new Response("Not found", { status: 404 });
	},
};
