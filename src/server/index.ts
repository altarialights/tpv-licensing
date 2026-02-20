// src/server/index.ts
import { SignJWT, jwtVerify } from "jose";
import type {
	ActivateRequest,
	ActivateResponse,
	ApiError,
	LemonWebhookPayload,
	LicenseStatus,
} from "../shared";

import { getDb, type TursoEnv } from "./db";
import {
	ensureExtraSchema,
	ensureTenantExistsMinimal,
	ensureDevice,
	upsertLicenseFromEventOrActivation,
	upsertLicenseInstance,
	getLicenseByHash,
	getDecryptedLicenseKey,
	upsertWebhookEvent,
	markWebhookProcessed,
} from "./licenseStore";
import { sha256Hex } from "./crypto";

// ---------------- Env ----------------

export interface Env extends TursoEnv {
	LEMON_WEBHOOK_SECRET: string;
	LICENSE_JWT_SECRET: string;

	/**
	 * Base64 32 bytes (AES-GCM)
	 * Lo reutilizamos para cifrar también tokens de tenant DB.
	 */
	LICENSE_STORE_KEY: string;

	/**
	 * Turso Platform API (para crear DB y tokens)
	 */
	TURSO_ORG_SLUG: string;        // ej: "altarialights"
	TURSO_PLATFORM_TOKEN: string;  // API token de Turso Platform API
	TURSO_GROUP?: string;          // opcional (si no existe => "default")
	TURSO_TOKEN_TTL?: string;      // opcional, ej "7d"
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

function assertEnv(env: Env, names: (keyof Env)[]) {
	for (const n of names) {
		const v = (env as any)[n];
		if (!v || String(v).trim().length === 0) return `missing_env_${String(n)}`;
	}
	return null;
}

async function signToken(
	env: Env,
	claims: { tenantId: string; deviceId: string; licHash: string }
) {
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

function timingSafeEqualHex(a: string, b: string) {
	if (a.length !== b.length) return false;
	let out = 0;
	for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return out === 0;
}

async function verifyLemonSignature(req: Request, secret: string, rawBody: string) {
	const sig = (req.headers.get("X-Signature") || "").trim().toLowerCase();

	if (!secret || secret.trim().length === 0) {
		console.log("[LEMON] Missing LEMON_WEBHOOK_SECRET in env");
		return false;
	}
	if (!sig) return false;

	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"]
	);

	const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(rawBody));
	const hex = [...new Uint8Array(mac)]
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");

	return timingSafeEqualHex(hex, sig);
}

// ---------------- libsql exec helper (compat) ----------------

async function execSql(db: any, sql: string, args: any[] = []) {
	try {
		return await db.execute({ sql, args });
	} catch {
		return await db.execute(sql, args);
	}
}

// ---------------- Base64 helpers ----------------

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

// ---------------- AES-GCM encrypt/decrypt (token storage) ----------------

async function aesGcmEncryptB64(keyB64: string, plaintext: string): Promise<string> {
	const keyBytes = b64ToBytes(keyB64);
	if (keyBytes.length !== 32) throw new Error("LICENSE_STORE_KEY must be 32 bytes (base64)");

	const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const pt = new TextEncoder().encode(plaintext);

	const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt));

	const out = new Uint8Array(iv.length + ct.length);
	out.set(iv, 0);
	out.set(ct, iv.length);
	return "v1:" + bytesToB64(out);
}

async function aesGcmDecryptB64(keyB64: string, blob: string): Promise<string> {
	if (!blob.startsWith("v1:")) throw new Error("unknown_cipher_version");
	const raw = b64ToBytes(blob.slice(3));
	const iv = raw.slice(0, 12);
	const ct = raw.slice(12);

	const keyBytes = b64ToBytes(keyB64);
	if (keyBytes.length !== 32) throw new Error("LICENSE_STORE_KEY must be 32 bytes (base64)");

	const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
	const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
	return new TextDecoder().decode(pt);
}

// ---------------- Turso Platform API ----------------

const TURSO_API_BASE = "https://api.turso.tech/v1";

async function tursoCreateDatabase(env: Env, dbName: string) {
	const group =
		env.TURSO_GROUP && env.TURSO_GROUP.trim().length > 0
			? env.TURSO_GROUP.trim()
			: "default";

	const r = await fetch(
		`${TURSO_API_BASE}/organizations/${encodeURIComponent(env.TURSO_ORG_SLUG)}/databases`,
		{
			method: "POST",
			headers: {
				Authorization: `Bearer ${env.TURSO_PLATFORM_TOKEN}`,
				"content-type": "application/json",
				Accept: "application/json",
			},
			body: JSON.stringify({ name: dbName, group }),
		}
	);

	const text = await r.text();
	let data: any = null;
	try {
		data = JSON.parse(text);
	} catch { }
	return { ok: r.ok, status: r.status, data, text };
}

async function tursoGetDatabase(env: Env, dbName: string) {
	const r = await fetch(
		`${TURSO_API_BASE}/organizations/${encodeURIComponent(
			env.TURSO_ORG_SLUG
		)}/databases/${encodeURIComponent(dbName)}`,
		{
			method: "GET",
			headers: {
				Authorization: `Bearer ${env.TURSO_PLATFORM_TOKEN}`,
				Accept: "application/json",
			},
		}
	);
	const text = await r.text();
	let data: any = null;
	try {
		data = JSON.parse(text);
	} catch { }
	return { ok: r.ok, status: r.status, data, text };
}

async function tursoCreateDbToken(env: Env, dbName: string, expiration: string) {
	const url =
		`${TURSO_API_BASE}/organizations/${encodeURIComponent(env.TURSO_ORG_SLUG)}` +
		`/databases/${encodeURIComponent(dbName)}/auth/tokens` +
		`?expiration=${encodeURIComponent(expiration)}&authorization=full-access`;

	const r = await fetch(url, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${env.TURSO_PLATFORM_TOKEN}`,
			Accept: "application/json",
		},
	});

	const text = await r.text();
	let data: any = null;
	try {
		data = JSON.parse(text);
	} catch { }
	return { ok: r.ok, status: r.status, data, text };
}

function approxTtlToMs(ttl: string): number | null {
	const s = ttl.trim().toLowerCase();
	const m = s.match(/^(\d+)\s*([mhdw])$/);
	if (!m) return null;
	const n = parseInt(m[1], 10);
	const unit = m[2];
	const minute = 60_000;
	const hour = 60 * minute;
	const day = 24 * hour;
	const week = 7 * day;
	switch (unit) {
		case "m":
			return n * minute;
		case "h":
			return n * hour;
		case "d":
			return n * day;
		case "w":
			return n * week;
		default:
			return null;
	}
}

// ---------------- Tenant DB provisioning / rotation ----------------

function normalizeDbName(tenantId: string) {
	const t = tenantId.toLowerCase();
	return `tpv-${t}`.slice(0, 64);
}

async function getTenantDbRow(dbi: any, tenantId: string) {
	const r = await execSql(
		dbi,
		`SELECT tenant_id, turso_db_name, turso_url, turso_auth_token_enc,
		        token_expires_at_ms, provisioning_status, last_error, rotated_at_ms
		   FROM tenant_databases
		  WHERE tenant_id = ?`,
		[tenantId]
	);

	const rows = (r?.rows || r?.result?.rows || []) as any[];
	return rows.length ? rows[0] : null;
}

async function upsertTenantDbRow(dbi: any, row: {
	tenantId: string;
	dbName: string | null;
	url: string | null;
	tokenEnc: string | null;
	tokenExpiresAtMs: number | null;
	status: "creating" | "ready" | "error";
	lastError: string | null;
	rotatedAtMs?: number | null;
}) {
	const now = Date.now();
	await execSql(
		dbi,
		`INSERT INTO tenant_databases
		 (tenant_id, turso_db_name, turso_url, turso_auth_token_enc,
		  token_expires_at_ms, provisioning_status, last_error, created_at_ms, rotated_at_ms)
		 VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at_ms FROM tenant_databases WHERE tenant_id = ?), ?), ?)
		 ON CONFLICT(tenant_id) DO UPDATE SET
		   turso_db_name = excluded.turso_db_name,
		   turso_url = excluded.turso_url,
		   turso_auth_token_enc = excluded.turso_auth_token_enc,
		   token_expires_at_ms = excluded.token_expires_at_ms,
		   provisioning_status = excluded.provisioning_status,
		   last_error = excluded.last_error,
		   rotated_at_ms = excluded.rotated_at_ms`,
		[
			row.tenantId,
			row.dbName,
			row.url,
			row.tokenEnc,
			row.tokenExpiresAtMs,
			row.status,
			row.lastError,
			row.tenantId,
			now,
			row.rotatedAtMs ?? null,
		]
	);
}

async function ensureTenantDatabaseProvisioned(env: Env, dbi: any, tenantId: string) {
	const ttl =
		env.TURSO_TOKEN_TTL && env.TURSO_TOKEN_TTL.trim().length > 0
			? env.TURSO_TOKEN_TTL.trim()
			: "7d";
	const ttlMs = approxTtlToMs(ttl);
	const rotateBeforeMs = 24 * 60 * 60 * 1000;

	const current = await getTenantDbRow(dbi, tenantId);

	if (current && current.provisioning_status === "ready" && current.turso_url && current.turso_auth_token_enc) {
		const exp = current.token_expires_at_ms ? Number(current.token_expires_at_ms) : null;
		if (exp && exp - Date.now() > rotateBeforeMs) {
			return { ok: true, dbName: String(current.turso_db_name || ""), url: String(current.turso_url || ""), rotated: false };
		}
		// exp no existe o expira pronto -> rotamos
	}

	await upsertTenantDbRow(dbi, {
		tenantId,
		dbName: current?.turso_db_name ? String(current.turso_db_name) : normalizeDbName(tenantId),
		url: current?.turso_url ? String(current.turso_url) : null,
		tokenEnc: current?.turso_auth_token_enc ? String(current.turso_auth_token_enc) : null,
		tokenExpiresAtMs: current?.token_expires_at_ms ? Number(current.token_expires_at_ms) : null,
		status: "creating",
		lastError: null,
		rotatedAtMs: current?.rotated_at_ms ? Number(current.rotated_at_ms) : null,
	});

	const dbName = current?.turso_db_name ? String(current.turso_db_name) : normalizeDbName(tenantId);

	// 1) si no tenemos url, intentamos crear o recuperar DB
	if (!current || !current.turso_url) {
		const created = await tursoCreateDatabase(env, dbName);

		let hostname =
			created.data?.database?.Hostname ||
			created.data?.database?.hostname ||
			created.data?.Hostname ||
			created.data?.hostname ||
			null;

		if (!created.ok || !hostname) {
			// puede existir ya -> GET
			const got = await tursoGetDatabase(env, dbName);
			if (!got.ok) {
				const errTxt = `create_db_failed status=${created.status} / get_db_failed status=${got.status}`;
				await upsertTenantDbRow(dbi, {
					tenantId,
					dbName,
					url: null,
					tokenEnc: null,
					tokenExpiresAtMs: null,
					status: "error",
					lastError: errTxt,
					rotatedAtMs: null,
				});
				throw new Error(errTxt);
			}
			hostname =
				got.data?.database?.Hostname ||
				got.data?.database?.hostname ||
				got.data?.Hostname ||
				got.data?.hostname ||
				null;

			if (!hostname) {
				const errTxt = "get_db_missing_hostname";
				await upsertTenantDbRow(dbi, {
					tenantId,
					dbName,
					url: null,
					tokenEnc: null,
					tokenExpiresAtMs: null,
					status: "error",
					lastError: errTxt,
					rotatedAtMs: null,
				});
				throw new Error(errTxt);
			}
		}

		const url = String(hostname).startsWith("libsql://")
			? String(hostname)
			: `libsql://${hostname}`;

		// 2) token
		const tok = await tursoCreateDbToken(env, dbName, ttl);
		if (!tok.ok) {
			const errTxt = `create_token_failed status=${tok.status}`;
			await upsertTenantDbRow(dbi, {
				tenantId,
				dbName,
				url,
				tokenEnc: null,
				tokenExpiresAtMs: null,
				status: "error",
				lastError: errTxt,
				rotatedAtMs: null,
			});
			throw new Error(errTxt);
		}

		const tokenPlain = tok.data?.jwt || tok.data?.token || tok.data?.Token || tok.data?.authToken;
		if (!tokenPlain) {
			const errTxt = "create_token_missing_jwt";
			await upsertTenantDbRow(dbi, {
				tenantId,
				dbName,
				url,
				tokenEnc: null,
				tokenExpiresAtMs: null,
				status: "error",
				lastError: errTxt,
				rotatedAtMs: null,
			});
			throw new Error(errTxt);
		}

		const tokenEnc = await aesGcmEncryptB64(env.LICENSE_STORE_KEY, String(tokenPlain));
		const expMs = ttlMs ? Date.now() + ttlMs : null;

		await upsertTenantDbRow(dbi, {
			tenantId,
			dbName,
			url,
			tokenEnc,
			tokenExpiresAtMs: expMs,
			status: "ready",
			lastError: null,
			rotatedAtMs: Date.now(),
		});

		return { ok: true, dbName, url, rotated: true };
	}

	// si tenemos URL, rotamos token (o lo creamos si falta)
	const url = String(current.turso_url);
	const tok = await tursoCreateDbToken(env, dbName, ttl);
	if (!tok.ok) {
		const errTxt = `rotate_token_failed status=${tok.status}`;
		await upsertTenantDbRow(dbi, {
			tenantId,
			dbName,
			url,
			tokenEnc: current.turso_auth_token_enc ? String(current.turso_auth_token_enc) : null,
			tokenExpiresAtMs: current.token_expires_at_ms ? Number(current.token_expires_at_ms) : null,
			status: "error",
			lastError: errTxt,
			rotatedAtMs: current.rotated_at_ms ? Number(current.rotated_at_ms) : null,
		});
		throw new Error(errTxt);
	}

	const tokenPlain = tok.data?.jwt || tok.data?.token || tok.data?.Token || tok.data?.authToken;
	if (!tokenPlain) {
		const errTxt = "rotate_token_missing_jwt";
		await upsertTenantDbRow(dbi, {
			tenantId,
			dbName,
			url,
			tokenEnc: null,
			tokenExpiresAtMs: null,
			status: "error",
			lastError: errTxt,
			rotatedAtMs: null,
		});
		throw new Error(errTxt);
	}

	const tokenEnc = await aesGcmEncryptB64(env.LICENSE_STORE_KEY, String(tokenPlain));
	const expMs = ttlMs ? Date.now() + ttlMs : null;

	await upsertTenantDbRow(dbi, {
		tenantId,
		dbName,
		url,
		tokenEnc,
		tokenExpiresAtMs: expMs,
		status: "ready",
		lastError: null,
		rotatedAtMs: Date.now(),
	});

	return { ok: true, dbName, url, rotated: true };
}

async function rotateTenantDbTokenNow(env: Env, dbi: any, tenantId: string) {
	const row = await getTenantDbRow(dbi, tenantId);
	if (!row?.turso_db_name || !row?.turso_url) {
		throw new Error("tenant_db_not_provisioned");
	}

	const ttl =
		env.TURSO_TOKEN_TTL && env.TURSO_TOKEN_TTL.trim().length > 0
			? env.TURSO_TOKEN_TTL.trim()
			: "7d";
	const ttlMs = approxTtlToMs(ttl);

	const dbName = String(row.turso_db_name);
	const url = String(row.turso_url);

	const tok = await tursoCreateDbToken(env, dbName, ttl);
	if (!tok.ok) throw new Error(`create_token_failed status=${tok.status}`);

	const tokenPlain = tok.data?.jwt || tok.data?.token || tok.data?.Token || tok.data?.authToken;
	if (!tokenPlain) throw new Error("create_token_missing_jwt");

	const tokenEnc = await aesGcmEncryptB64(env.LICENSE_STORE_KEY, String(tokenPlain));
	const expMs = ttlMs ? Date.now() + ttlMs : null;

	await upsertTenantDbRow(dbi, {
		tenantId,
		dbName,
		url,
		tokenEnc,
		tokenExpiresAtMs: expMs,
		status: "ready",
		lastError: null,
		rotatedAtMs: Date.now(),
	});

	return { ok: true, tokenExpiresAtMs: expMs, rotatedAtMs: Date.now() };
}

// ---------------- Lemon License API ----------------

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
	try {
		data = JSON.parse(text);
	} catch { }
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
	try {
		data = JSON.parse(text);
	} catch { }
	return { ok: r.ok, status: r.status, data, text };
}

// ---------------- Worker ----------------

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		// DB init (lazy)
		let db: ReturnType<typeof getDb> | null = null;
		const get = () => {
			if (!db) db = getDb(env);
			return db!;
		};

		if (url.pathname === "/health") {
			return json({ ok: true, service: "tpv-licensing", ts: Date.now() });
		}

		// 1) WEBHOOK Lemon
		if (url.pathname === "/v1/webhooks/lemon" && request.method === "POST") {
			const miss = assertEnv(env, [
				"LEMON_WEBHOOK_SECRET",
				"TURSO_DATABASE_URL",
				"TURSO_AUTH_TOKEN",
				"LICENSE_STORE_KEY",
			]);
			if (miss) return json({ ok: false, error: miss }, 500);

			const raw = await request.text();

			console.log("[LEMON] webhook hit", {
				ts: Date.now(),
				sigPresent: Boolean((request.headers.get("X-Signature") || "").trim()),
				bytes: raw.length,
			});

			const validSig = await verifyLemonSignature(request, env.LEMON_WEBHOOK_SECRET, raw);
			if (!validSig) return json({ ok: false, error: "invalid_signature" }, 401);

			const sig = (request.headers.get("X-Signature") || "").trim().toLowerCase();
			const bodySha = await sha256Hex(raw);
			const eventUid = await sha256Hex(sig + ":" + bodySha);

			const dbi = get();
			await ensureExtraSchema(dbi);

			let payload: LemonWebhookPayload | null = null;
			try {
				payload = JSON.parse(raw);
			} catch {
				return json({ ok: false, error: "invalid_json" }, 400);
			}

			const eventName = String(payload?.meta?.event_name || "");
			const testMode = Boolean(payload?.meta?.test_mode);

			const resourceType = (payload as any)?.data?.type ? String((payload as any).data.type) : null;
			const resourceId = (payload as any)?.data?.id ? String((payload as any).data.id) : null;

			const idemp = await upsertWebhookEvent(dbi, {
				event_uid: eventUid,
				event_name: eventName || "unknown",
				resource_type: resourceType,
				resource_id: resourceId,
				sig_hex: sig || null,
				body_sha256: bodySha,
				payload_json: raw,
			});

			if (idemp.already) {
				return json({ ok: true, received: true, eventName, idempotent: true });
			}

			try {
				const attrs = payload?.data?.attributes || {};
				const licenseKey = String((attrs as any).key || "").trim();
				const status = String((attrs as any).status || "unknown").trim() as LicenseStatus;
				const expiresAt = (attrs as any).expires_at ? String((attrs as any).expires_at) : null;

				console.log("[LEMON] event", { eventName, hasKey: Boolean(licenseKey), status, expiresAt, testMode });

				if (licenseKey) {
					await upsertLicenseFromEventOrActivation({
						db: dbi,
						storeKeyB64: env.LICENSE_STORE_KEY,
						licenseKeyPlain: licenseKey,
						tenantId: null,
						status: (status || "active") as LicenseStatus,
						expiresAt,
						testMode,

						lemon_license_key_id: resourceId,
						lemon_created_at: (attrs as any).created_at ? String((attrs as any).created_at) : null,
						lemon_updated_at: (attrs as any).updated_at ? String((attrs as any).updated_at) : null,

						meta: { eventName, payload },
					});
				}

				await markWebhookProcessed(dbi, eventUid, true);
				return json({ ok: true, received: true, eventName });
			} catch (e: any) {
				await markWebhookProcessed(dbi, eventUid, false, String(e?.message || e));
				return json({ ok: false, error: "webhook_processing_failed" }, 500);
			}
		}

		// 2) ACTIVAR (TPV MAIN)
		if (url.pathname === "/v1/license/activate" && request.method === "POST") {
			const miss = assertEnv(env, [
				"LICENSE_JWT_SECRET",
				"LICENSE_STORE_KEY",
				"TURSO_DATABASE_URL",
				"TURSO_AUTH_TOKEN",
				"TURSO_ORG_SLUG",
				"TURSO_PLATFORM_TOKEN",
			]);
			if (miss) return json({ ok: false, error: miss }, 500);

			const err = requireJson(request);
			if (err) return err;

			const body = await readJsonSafe<ActivateRequest>(request, {
				activationKey: "",
				deviceId: "",
				instanceName: undefined,
			} as any);

			const activationKey = String((body as any).activationKey || "").trim();

			const reqDeviceId = String((body as any).deviceId || "").trim();
			const deviceId = reqDeviceId || crypto.randomUUID();

			const reqInstanceName = String((body as any).instanceName || "").trim();
			const instanceName = reqInstanceName || `tpv-${deviceId.slice(0, 12)}`;

			if (!activationKey) {
				const out: ApiError = { ok: false, error: "activationKey required" };
				return json(out, 400);
			}

			const act = await lemonActivate(activationKey, instanceName);
			if (!act.ok) {
				const out: ApiError = {
					ok: false,
					error: act.data?.error || "lemon_activate_failed",
					details: act.data || act.text,
				};
				return json(out, 400);
			}

			const licenseKeyObj = act.data?.license_key;
			const instanceObj = act.data?.instance;

			const status = (licenseKeyObj?.status || "active") as LicenseStatus;
			const expiresAt = licenseKeyObj?.expires_at ? String(licenseKeyObj.expires_at) : null;
			const instanceId = instanceObj?.id ? String(instanceObj.id) : null;

			const dbi = get();
			await ensureExtraSchema(dbi);

			const licHash = await sha256Hex(activationKey);
			const existing = await getLicenseByHash(dbi, licHash);

			let tenantId =
				existing?.tenant_id && existing.tenant_id !== "PENDING"
					? existing.tenant_id
					: crypto.randomUUID();

			await ensureTenantExistsMinimal(dbi, tenantId);
			await ensureDevice(dbi, tenantId, deviceId, "tpv");

			// ✅ Provisiona DB por tenant (idempotente) + token cifrado
			try {
				await ensureTenantDatabaseProvisioned(env, dbi, tenantId);
			} catch (e: any) {
				console.log("[TURSO] provisioning failed", { tenantId, err: String(e?.message || e) });
				const out: ApiError = {
					ok: false,
					error: "tenant_db_provision_failed",
					details: String(e?.message || e),
				};
				return json(out, 500);
			}

			const { license } = await upsertLicenseFromEventOrActivation({
				db: dbi,
				storeKeyB64: env.LICENSE_STORE_KEY,
				licenseKeyPlain: activationKey,
				tenantId,
				status,
				expiresAt,
				testMode: Boolean(act.data?.meta?.test_mode),

				lemon_license_key_id: licenseKeyObj?.id ? String(licenseKeyObj.id) : existing?.lemon_license_key_id ?? null,
				lemon_customer_id: licenseKeyObj?.customer_id ? String(licenseKeyObj.customer_id) : null,
				lemon_order_id: licenseKeyObj?.order_id ? String(licenseKeyObj.order_id) : null,
				lemon_order_item_id: licenseKeyObj?.order_item_id ? String(licenseKeyObj.order_item_id) : null,
				lemon_store_id: licenseKeyObj?.store_id ? String(licenseKeyObj.store_id) : null,
				lemon_product_id: licenseKeyObj?.product_id ? String(licenseKeyObj.product_id) : null,

				instances_count: typeof licenseKeyObj?.instances_count === "number" ? licenseKeyObj.instances_count : null,
				activation_limit: typeof licenseKeyObj?.activation_limit === "number" ? licenseKeyObj.activation_limit : null,

				user_name: licenseKeyObj?.user_name ? String(licenseKeyObj.user_name) : null,
				user_email: licenseKeyObj?.user_email ? String(licenseKeyObj.user_email) : null,

				lemon_created_at: licenseKeyObj?.created_at ? String(licenseKeyObj.created_at) : null,
				lemon_updated_at: licenseKeyObj?.updated_at ? String(licenseKeyObj.updated_at) : null,

				meta: act.data?.meta || null,
			});

			if (instanceId) {
				await upsertLicenseInstance(dbi, {
					instanceId,
					licenseId: license.license_id,
					tenantId,
					deviceId,
					instanceName: instanceName || null,
				});
			}

			const token = await signToken(env, { tenantId, deviceId, licHash });

			const out: ActivateResponse & { deviceId: string } = {
				ok: true,
				tenantId,
				deviceId,
				token,
				status,
				expiresAt,
			};

			return json(out);
		}

		// 3) STATUS
		if (url.pathname === "/v1/license/status" && request.method === "GET") {
			const miss = assertEnv(env, ["LICENSE_JWT_SECRET", "TURSO_DATABASE_URL", "TURSO_AUTH_TOKEN"]);
			if (miss) return json({ ok: false, error: miss }, 500);

			const h = request.headers.get("authorization") || "";
			const m = h.match(/^Bearer\s+(.+)$/i);
			if (!m) return json({ ok: false, error: "missing_token" }, 401);

			let claims: { tenantId: string; deviceId: string; licHash: string };
			try {
				claims = await verifyToken(env, m[1]);
			} catch {
				return json({ ok: false, error: "invalid_token" }, 401);
			}

			const dbi = get();
			const lic = await getLicenseByHash(dbi, claims.licHash);
			if (!lic) return json({ ok: false, error: "not_found" }, 404);

			return json({
				ok: true,
				state: {
					tenant_id: lic.tenant_id,
					status: lic.status,
					expires_at: lic.expires_at,
					disabled: lic.disabled,
					test_mode: lic.test_mode,
					key_short: lic.key_short,
					updated_at_ms: lic.updated_at_ms,
					created_at_ms: lic.created_at_ms,
				},
				serverTime: Date.now(),
			});
		}

		// 4) VALIDATE (re-check con Lemon)
		if (url.pathname === "/v1/license/validate" && request.method === "POST") {
			const miss = assertEnv(env, [
				"LICENSE_JWT_SECRET",
				"LICENSE_STORE_KEY",
				"TURSO_DATABASE_URL",
				"TURSO_AUTH_TOKEN",
			]);
			if (miss) return json({ ok: false, error: miss }, 500);

			const h = request.headers.get("authorization") || "";
			const m = h.match(/^Bearer\s+(.+)$/i);
			if (!m) return json({ ok: false, error: "missing_token" }, 401);

			let claims: { tenantId: string; deviceId: string; licHash: string };
			try {
				claims = await verifyToken(env, m[1]);
			} catch {
				return json({ ok: false, error: "invalid_token" }, 401);
			}

			const dbi = get();
			await ensureExtraSchema(dbi);

			const dec = await getDecryptedLicenseKey(dbi, env.LICENSE_STORE_KEY, claims.licHash);
			if (!dec) return json({ ok: false, error: "not_found" }, 404);

			const licenseKey = dec.licenseKey;

			const val = await lemonValidate(licenseKey, null);
			if (!val.ok) {
				return json({ ok: false, error: "lemon_validate_failed", details: val.data || val.text }, 400);
			}

			const status = (val.data?.license_key?.status || "active") as LicenseStatus;
			const expiresAt = val.data?.license_key?.expires_at ? String(val.data.license_key.expires_at) : null;

			await upsertLicenseFromEventOrActivation({
				db: dbi,
				storeKeyB64: env.LICENSE_STORE_KEY,
				licenseKeyPlain: licenseKey,
				tenantId: dec.lic.tenant_id,
				status,
				expiresAt,
				testMode: Boolean(val.data?.meta?.test_mode),
				instances_count: typeof val.data?.license_key?.instances_count === "number" ? val.data.license_key.instances_count : null,
				activation_limit: typeof val.data?.license_key?.activation_limit === "number" ? val.data.license_key.activation_limit : null,
				lemon_updated_at: val.data?.license_key?.updated_at ? String(val.data.license_key.updated_at) : null,
				meta: val.data?.meta || null,
			});

			return json({ ok: true, status, expiresAt, valid: val.data?.valid, meta: val.data?.meta });
		}

		// 5) ROTATE TENANT DB TOKEN (manual, sin /activate)
		if (url.pathname === "/v1/tenant/rotate-token" && request.method === "POST") {
			const miss = assertEnv(env, [
				"LICENSE_JWT_SECRET",
				"LICENSE_STORE_KEY",
				"TURSO_DATABASE_URL",
				"TURSO_AUTH_TOKEN",
				"TURSO_ORG_SLUG",
				"TURSO_PLATFORM_TOKEN",
			]);
			if (miss) return json({ ok: false, error: miss }, 500);

			const h = request.headers.get("authorization") || "";
			const m = h.match(/^Bearer\s+(.+)$/i);
			if (!m) return json({ ok: false, error: "missing_token" }, 401);

			let claims: { tenantId: string; deviceId: string; licHash: string };
			try {
				claims = await verifyToken(env, m[1]);
			} catch {
				return json({ ok: false, error: "invalid_token" }, 401);
			}

			const dbi = get();
			await ensureExtraSchema(dbi);

			try {
				const res = await rotateTenantDbTokenNow(env, dbi, claims.tenantId);
				return json({ tenantId: claims.tenantId, ...res });
			} catch (e: any) {
				return json({ ok: false, error: "rotate_failed", details: String(e?.message || e) }, 500);
			}
		}

		return new Response("Not found", { status: 404 });
	},
};