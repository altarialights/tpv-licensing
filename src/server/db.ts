// src/server/db.ts
import { createClient, type Client } from "@libsql/client/web";

export interface TursoEnv {
	TURSO_DATABASE_URL: string;
	TURSO_AUTH_TOKEN: string;
}

let _client: Client | null = null;

export function getDb(env: TursoEnv): Client {
	if (_client) return _client;

	const url = String(env.TURSO_DATABASE_URL || "").trim();
	const authToken = String(env.TURSO_AUTH_TOKEN || "").trim();

	if (!url) throw new Error("missing_env_TURSO_DATABASE_URL");
	if (!authToken) throw new Error("missing_env_TURSO_AUTH_TOKEN");

	_client = createClient({ url, authToken });
	return _client;
}

export async function exec(db: Client, sql: string, args: any[] = []) {
	return db.execute({ sql, args });
}

export async function execMany(db: Client, statements: { sql: string; args?: any[] }[]) {
	// libsql HTTP no garantiza transacciones multi-statement igual que sqlite local,
	// pero esto reduce round-trips.
	for (const st of statements) {
		await db.execute({ sql: st.sql, args: st.args || [] });
	}
}
