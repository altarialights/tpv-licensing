// src/server/licenseStore.ts
import type { Client } from "@libsql/client/web";
import type { LicenseStatus } from "../shared";
import { aesGcmDecrypt, aesGcmEncrypt, sha256Hex } from "./crypto";
import { exec, execMany } from "./db";

export type LicenseRow = {
	license_id: string;
	tenant_id: string | null;
	license_key_hash: string;
	license_key_enc: string | null;
	status: LicenseStatus | string;
	disabled: number;
	test_mode: number;
	expires_at: string | null;
	activation_limit: number | null;
	instances_count: number | null;

	lemon_license_key_id: string | null;
	lemon_order_id: string | null;
	lemon_order_item_id: string | null;
	lemon_customer_id: string | null;
	lemon_store_id: string | null;
	lemon_product_id: string | null;

	user_name: string | null;
	user_email: string | null;
	key_short: string | null;

	lemon_created_at: string | null;
	lemon_updated_at: string | null;

	created_at_ms: number;
	updated_at_ms: number;
};

export async function ensureExtraSchema(db: Client) {
	// ✅ Tu schema principal ya lo has creado en Turso.
	// Solo añadimos un “extra” para guardar meta_json como antes (opcional).
	await exec(
		db,
		`
    CREATE TABLE IF NOT EXISTS license_meta (
      license_id TEXT PRIMARY KEY,
      meta_json  TEXT,
      updated_at_ms INTEGER NOT NULL DEFAULT (unixepoch()*1000),
      FOREIGN KEY (license_id) REFERENCES licenses(license_id) ON DELETE CASCADE
    );
    `
	);
}

export async function getLicenseByHash(db: Client, licHash: string): Promise<LicenseRow | null> {
	const r = await exec(db, `SELECT * FROM licenses WHERE license_key_hash = ? LIMIT 1;`, [licHash]);
	const row = (r.rows?.[0] as any) || null;
	return row ? (row as LicenseRow) : null;
}

export async function getLicenseMeta(db: Client, licenseId: string): Promise<string | null> {
	const r = await exec(db, `SELECT meta_json FROM license_meta WHERE license_id=? LIMIT 1;`, [licenseId]);
	const row = (r.rows?.[0] as any) || null;
	return row?.meta_json ?? null;
}

export async function upsertLicenseMeta(db: Client, licenseId: string, meta: any) {
	const metaJson = meta ? JSON.stringify(meta) : null;
	const now = Date.now();
	await exec(
		db,
		`
    INSERT INTO license_meta (license_id, meta_json, updated_at_ms)
    VALUES (?, ?, ?)
    ON CONFLICT(license_id) DO UPDATE SET
      meta_json=excluded.meta_json,
      updated_at_ms=excluded.updated_at_ms;
    `,
		[licenseId, metaJson, now]
	);
}

export async function ensureTenantExistsMinimal(db: Client, tenantId: string) {
	// “Upsert” mínimo (por si activas sin tener el tenant todavía).
	const now = Date.now();
	await exec(
		db,
		`
    INSERT INTO tenants (tenant_id, status, created_at_ms, updated_at_ms)
    VALUES (?, 'active', ?, ?)
    ON CONFLICT(tenant_id) DO UPDATE SET
      updated_at_ms=excluded.updated_at_ms;
    `,
		[tenantId, now, now]
	);
}

export async function ensureDevice(db: Client, tenantId: string, deviceId: string, role: "tpv" | "handy" = "tpv") {
	const now = Date.now();
	await exec(
		db,
		`
    INSERT INTO devices (device_id, tenant_id, role, first_seen_at_ms, last_seen_at_ms)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(device_id) DO UPDATE SET
      tenant_id=excluded.tenant_id,
      role=excluded.role,
      last_seen_at_ms=excluded.last_seen_at_ms;
    `,
		[deviceId, tenantId, role, now, now]
	);
}

export async function upsertLicenseFromEventOrActivation(params: {
	db: Client;
	storeKeyB64: string;

	// identity
	licenseKeyPlain: string; // la key real (para cifrar)
	tenantId?: string | null;

	// status
	status?: LicenseStatus;
	expiresAt?: string | null;
	testMode?: boolean;

	// lemon-ish (opcionales)
	lemon_license_key_id?: string | null;
	lemon_order_id?: string | null;
	lemon_order_item_id?: string | null;
	lemon_customer_id?: string | null;
	lemon_store_id?: string | null;
	lemon_product_id?: string | null;

	user_name?: string | null;
	user_email?: string | null;

	lemon_created_at?: string | null;
	lemon_updated_at?: string | null;

	activation_limit?: number | null;
	instances_count?: number | null;

	meta?: any;
}): Promise<{ license: LicenseRow; licHash: string }> {
	const { db, storeKeyB64, licenseKeyPlain } = params;

	const licHash = await sha256Hex(licenseKeyPlain);
	const existing = await getLicenseByHash(db, licHash);

	const now = Date.now();
	const licenseId = existing?.license_id || crypto.randomUUID();

	const enc = await aesGcmEncrypt(storeKeyB64, licenseKeyPlain);
	const keyShort = licenseKeyPlain ? licenseKeyPlain.slice(0, 4) + "…" + licenseKeyPlain.slice(-4) : null;

	const status = (params.status || (existing?.status as any) || "unknown") as any;
	const expiresAt = params.expiresAt ?? existing?.expires_at ?? null;
	const tenantId = params.tenantId ?? existing?.tenant_id ?? null;

	const testMode = params.testMode ? 1 : existing?.test_mode ?? 0;

	await exec(
		db,
		`
    INSERT INTO licenses (
      license_id, tenant_id, license_key_hash, license_key_enc,
      status, disabled, test_mode,
      expires_at, activation_limit, instances_count,
      lemon_license_key_id, lemon_order_id, lemon_order_item_id, lemon_customer_id, lemon_store_id, lemon_product_id,
      user_name, user_email, key_short,
      lemon_created_at, lemon_updated_at,
      created_at_ms, updated_at_ms
    ) VALUES (
      ?, ?, ?, ?,
      ?, COALESCE(?,0), ?,
      ?, ?, ?,
      ?, ?, ?, ?, ?, ?,
      ?, ?, ?,
      ?, ?,
      ?, ?
    )
    ON CONFLICT(license_key_hash) DO UPDATE SET
      tenant_id=excluded.tenant_id,
      license_key_enc=excluded.license_key_enc,
      status=excluded.status,
      test_mode=excluded.test_mode,
      expires_at=excluded.expires_at,
      activation_limit=COALESCE(excluded.activation_limit, licenses.activation_limit),
      instances_count=COALESCE(excluded.instances_count, licenses.instances_count),
      lemon_license_key_id=COALESCE(excluded.lemon_license_key_id, licenses.lemon_license_key_id),
      lemon_order_id=COALESCE(excluded.lemon_order_id, licenses.lemon_order_id),
      lemon_order_item_id=COALESCE(excluded.lemon_order_item_id, licenses.lemon_order_item_id),
      lemon_customer_id=COALESCE(excluded.lemon_customer_id, licenses.lemon_customer_id),
      lemon_store_id=COALESCE(excluded.lemon_store_id, licenses.lemon_store_id),
      lemon_product_id=COALESCE(excluded.lemon_product_id, licenses.lemon_product_id),
      user_name=COALESCE(excluded.user_name, licenses.user_name),
      user_email=COALESCE(excluded.user_email, licenses.user_email),
      key_short=COALESCE(excluded.key_short, licenses.key_short),
      lemon_created_at=COALESCE(excluded.lemon_created_at, licenses.lemon_created_at),
      lemon_updated_at=COALESCE(excluded.lemon_updated_at, licenses.lemon_updated_at),
      updated_at_ms=excluded.updated_at_ms;
    `,
		[
			licenseId,
			tenantId,
			licHash,
			enc,
			status,
			existing?.disabled ?? 0,
			testMode,
			expiresAt,
			params.activation_limit ?? existing?.activation_limit ?? null,
			params.instances_count ?? existing?.instances_count ?? null,
			params.lemon_license_key_id ?? existing?.lemon_license_key_id ?? null,
			params.lemon_order_id ?? existing?.lemon_order_id ?? null,
			params.lemon_order_item_id ?? existing?.lemon_order_item_id ?? null,
			params.lemon_customer_id ?? existing?.lemon_customer_id ?? null,
			params.lemon_store_id ?? existing?.lemon_store_id ?? null,
			params.lemon_product_id ?? existing?.lemon_product_id ?? null,
			params.user_name ?? existing?.user_name ?? null,
			params.user_email ?? existing?.user_email ?? null,
			existing?.key_short ?? keyShort,
			params.lemon_created_at ?? existing?.lemon_created_at ?? null,
			params.lemon_updated_at ?? existing?.lemon_updated_at ?? null,
			existing?.created_at_ms ?? now,
			now,
		]
	);

	const license = (await getLicenseByHash(db, licHash))!;
	if (params.meta !== undefined) {
		await upsertLicenseMeta(db, license.license_id, params.meta);
	}

	return { license, licHash };
}

export async function upsertLicenseInstance(db: Client, args: {
	instanceId: string;
	licenseId: string;
	tenantId: string | null;
	deviceId: string;
	instanceName: string | null;
}) {
	const now = Date.now();
	await exec(
		db,
		`
    INSERT INTO license_instances (
      instance_id, license_id, tenant_id, device_id, instance_name,
      activated_at_ms, revoked_at_ms
    ) VALUES (?, ?, ?, ?, ?, ?, NULL)
    ON CONFLICT(instance_id) DO UPDATE SET
      license_id=excluded.license_id,
      tenant_id=excluded.tenant_id,
      device_id=excluded.device_id,
      instance_name=excluded.instance_name,
      revoked_at_ms=NULL;
    `,
		[args.instanceId, args.licenseId, args.tenantId, args.deviceId, args.instanceName, now]
	);
}

export async function getDecryptedLicenseKey(db: Client, storeKeyB64: string, licHash: string) {
	const lic = await getLicenseByHash(db, licHash);
	if (!lic || !lic.license_key_enc) return null;
	const licenseKey = await aesGcmDecrypt(storeKeyB64, lic.license_key_enc);
	return { lic, licenseKey };
}

export async function upsertWebhookEvent(db: Client, args: {
	event_uid: string;
	event_name: string;
	resource_type: string | null;
	resource_id: string | null;
	sig_hex: string | null;
	body_sha256: string;
	payload_json: string;
}) {
	const now = Date.now();

	// idempotencia: si ya existe, no re-procesamos
	const existing = await exec(db, `SELECT processed_ok FROM webhook_events WHERE event_uid=? LIMIT 1;`, [args.event_uid]);
	if (existing.rows?.length) return { already: true };

	await exec(
		db,
		`
    INSERT INTO webhook_events (
      event_uid, event_name, resource_type, resource_id,
      sig_hex, body_sha256, payload_json,
      received_at_ms, processed_at_ms, processed_ok, error_text
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, NULL);
    `,
		[
			args.event_uid,
			args.event_name,
			args.resource_type,
			args.resource_id,
			args.sig_hex,
			args.body_sha256,
			args.payload_json,
			now,
		]
	);

	return { already: false };
}

export async function markWebhookProcessed(db: Client, eventUid: string, ok: boolean, errorText?: string | null) {
	const now = Date.now();
	await exec(
		db,
		`
    UPDATE webhook_events
    SET processed_at_ms=?, processed_ok=?, error_text=?
    WHERE event_uid=?;
    `,
		[now, ok ? 1 : 0, ok ? null : (errorText || "error"), eventUid]
	);
}
