// src/server/index.ts
import { SignJWT, jwtVerify } from "jose";
import { createClient } from "@libsql/client/web";

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
	LICENSE_STORE_KEY: string; // base64 32 bytes (AES-GCM)

	// Turso Platform API (crear DB por tenant y tokens por DB)
	TURSO_ORG_SLUG: string; // ej: "altarialights"
	TURSO_PLATFORM_TOKEN: string; // token platform
	TURSO_GROUP?: string; // opcional (si no pones, usamos "default")
	TURSO_TOKEN_TTL?: string; // opcional ej "7d"
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
	const hex = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");

	return timingSafeEqualHex(hex, sig);
}

/** ✅ FIX: Turso suele devolver 0/1; Rust espera boolean en status */
function toBool01(v: any, fallback = false): boolean {
	if (typeof v === "boolean") return v;
	if (typeof v === "number") return v !== 0;
	if (typeof v === "string") {
		const s = v.trim().toLowerCase();
		if (s === "true" || s === "1") return true;
		if (s === "false" || s === "0") return false;
	}
	return fallback;
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

// ---------------- AES-GCM encrypt/decrypt ----------------

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

// ========================
// TU SCHEMA (tal cual)
// ========================

const TENANT_SCHEMA_SQL = String.raw`
/* =========================================================
   TPV SCHEMA (Inventario con LOTES + FEFO)
   - Sin migraciones: pensado para borrar DB y recrear
   - Cambios clave:
     ✅ Productos = ficha (catálogo)
     ✅ NUEVO: Lotes_Producto = existencias por lote (caducidad/cantidad)
     ✅ NUEVO: Lote_Consumos = trazabilidad (qué lote se consumió en cada línea)
     ✅ Vistas opcionales para Stock_Actual / Caducidad_Proxima / Lote_Proximo
========================================================= */

PRAGMA foreign_keys = ON;

/* =========================================================
   1. Seguridad y Usuarios
========================================================= */
CREATE TABLE IF NOT EXISTS Roles (
  ID_Rol INTEGER PRIMARY KEY AUTOINCREMENT,
  Nombre_Rol TEXT NOT NULL UNIQUE
);

-- Seeds roles
INSERT OR IGNORE INTO Roles (Nombre_Rol) VALUES
  ('Camarero'),
  ('Cocinero'),
  ('Limpieza');

CREATE TABLE IF NOT EXISTS Usuarios (
  ID_Usuario INTEGER PRIMARY KEY AUTOINCREMENT,
  ID_Rol INTEGER NOT NULL,
  Email TEXT NOT NULL UNIQUE,
  Password_Hash TEXT NOT NULL,
  Nombre TEXT NOT NULL,
  Apellido TEXT,
  Estado TEXT DEFAULT 'Activo',
  Requiere_Setup INTEGER DEFAULT 0, -- 0/1
  FOREIGN KEY (ID_Rol) REFERENCES Roles(ID_Rol)
);

/* =========================================================
   2. Personal y Horarios (Trabajadores)
========================================================= */
CREATE TABLE IF NOT EXISTS Trabajadores (
  ID_Trabajador INTEGER PRIMARY KEY AUTOINCREMENT,
  ID_Usuario INTEGER UNIQUE NOT NULL,
  DNI TEXT UNIQUE,
  Telefono TEXT,
  Puesto TEXT,
  IBAN TEXT,
  Numero_Seguridad_Social TEXT UNIQUE,
  Fecha_Inicio_Contrato DATE,
  Fecha_Fin_Contrato DATE,
  FOREIGN KEY (ID_Usuario) REFERENCES Usuarios(ID_Usuario)
);

CREATE TABLE IF NOT EXISTS Turnos (
  ID_Turno INTEGER PRIMARY KEY AUTOINCREMENT,
  Nombre_Turno TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS Asignacion_Turnos (
  ID_Asignacion INTEGER PRIMARY KEY AUTOINCREMENT,
  ID_Trabajador INTEGER NOT NULL,
  Fecha DATE NOT NULL,
  ID_Turno INTEGER NOT NULL,
  Area TEXT NOT NULL,
  Hora_Inicio TIME,
  Hora_Fin TIME,
  Notas TEXT,
  FOREIGN KEY (ID_Trabajador) REFERENCES Trabajadores(ID_Trabajador),
  FOREIGN KEY (ID_Turno) REFERENCES Turnos(ID_Turno)
);

CREATE INDEX IF NOT EXISTS idx_asig_fecha ON Asignacion_Turnos(Fecha);
CREATE INDEX IF NOT EXISTS idx_asig_trab_fecha ON Asignacion_Turnos(ID_Trabajador, Fecha);

-- Seeds turnos
INSERT OR IGNORE INTO Turnos (Nombre_Turno) VALUES
  ('LIBRE'),
  ('PARTIDO'),
  ('MAÑANA'),
  ('TARDE'),
  ('NOCHE');

/* =========================================================
   3. Inventario y Productos (con LOTES)
========================================================= */
CREATE TABLE IF NOT EXISTS Categorias_Producto (
  ID_Categoria INTEGER PRIMARY KEY AUTOINCREMENT,
  Nombre TEXT NOT NULL UNIQUE,
  Nombre_Imagen TEXT,
  Ruta_Imagen TEXT,
  Vendible INTEGER NOT NULL DEFAULT 1,   -- 0/1
  Pasa_Cocina INTEGER NOT NULL DEFAULT 0 -- 0/1
);

CREATE TABLE IF NOT EXISTS Proveedores (
  ID_Proveedor INTEGER PRIMARY KEY AUTOINCREMENT,
  Nombre_Empresa TEXT NOT NULL,
  Contacto TEXT,
  Telefono TEXT,
  Email TEXT UNIQUE,
  CIF TEXT UNIQUE,
  Informacion_adicional TEXT,
  Nombre_Imagen TEXT,
  Ruta_Imagen TEXT
);

-- ✅ Productos = ficha estable (SIN lote/caducidad/stock)
CREATE TABLE IF NOT EXISTS Productos (
  ID_Producto INTEGER PRIMARY KEY AUTOINCREMENT,
  ID_Categoria INTEGER NOT NULL,

  -- proveedor por defecto (opcional)
  ID_Proveedor INTEGER,

  Nombre TEXT NOT NULL UNIQUE,
  Precio_Venta REAL,

  -- umbrales / info estable
  Stock_Minimo REAL DEFAULT 0,
  Unidad_Medida TEXT,

  Nombre_Imagen TEXT,
  Ruta_Imagen TEXT,

  -- sigue siendo útil como “cantidad típica a pedir” (opcional)
  Cantidad_Pedido_Esperada REAL,

  FOREIGN KEY (ID_Categoria) REFERENCES Categorias_Producto(ID_Categoria),
  FOREIGN KEY (ID_Proveedor) REFERENCES Proveedores(ID_Proveedor)
);

-- ✅ NUEVO: LOTES (existencias reales por lote/caducidad)
CREATE TABLE IF NOT EXISTS Lotes_Producto (
  ID_Lote INTEGER PRIMARY KEY AUTOINCREMENT,
  ID_Producto INTEGER NOT NULL,

  Codigo_Lote TEXT NOT NULL,          -- ej: "L-2026-001"
  Fecha_Entrada DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
  Caducidad DATE,                     -- NULL si no aplica

  Cantidad_Inicial REAL NOT NULL DEFAULT 0,
  Stock_Disponible REAL NOT NULL DEFAULT 0,

  -- opcional: compras por lote
  Coste_Unitario REAL,
  ID_Proveedor INTEGER,

  Notas TEXT,

  FOREIGN KEY (ID_Producto) REFERENCES Productos(ID_Producto) ON DELETE CASCADE,
  FOREIGN KEY (ID_Proveedor) REFERENCES Proveedores(ID_Proveedor),

  UNIQUE (ID_Producto, Codigo_Lote),
  CHECK (Cantidad_Inicial >= 0),
  CHECK (Stock_Disponible >= 0)
);

-- Índices para FEFO (buscar rápido el lote con menor caducidad y stock>0)
CREATE INDEX IF NOT EXISTS idx_lotes_producto_cad
  ON Lotes_Producto(ID_Producto, Caducidad);

CREATE INDEX IF NOT EXISTS idx_lotes_producto_stock
  ON Lotes_Producto(ID_Producto, Stock_Disponible);

CREATE INDEX IF NOT EXISTS idx_lotes_producto_entrada
  ON Lotes_Producto(ID_Producto, Fecha_Entrada);

/* =========================================================
   ALÉRGENOS (catálogo + relación con productos)
========================================================= */
CREATE TABLE IF NOT EXISTS Alergenos (
  ID_Alergeno INTEGER PRIMARY KEY AUTOINCREMENT,
  Nombre TEXT NOT NULL UNIQUE,
  Nombre_Imagen TEXT,
  Ruta_Imagen TEXT
);

CREATE TABLE IF NOT EXISTS Producto_Alergenos (
  ID_Producto INTEGER NOT NULL,
  ID_Alergeno INTEGER NOT NULL,
  PRIMARY KEY (ID_Producto, ID_Alergeno),
  FOREIGN KEY (ID_Producto) REFERENCES Productos(ID_Producto) ON DELETE CASCADE,
  FOREIGN KEY (ID_Alergeno) REFERENCES Alergenos(ID_Alergeno) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_prod_alerg_prod ON Producto_Alergenos(ID_Producto);
CREATE INDEX IF NOT EXISTS idx_prod_alerg_alerg ON Producto_Alergenos(ID_Alergeno);

/* =========================================================
   4. Zonas / Mesas / Clientes / Reservas
========================================================= */
CREATE TABLE IF NOT EXISTS Zonas (
  ID_Zona INTEGER PRIMARY KEY AUTOINCREMENT,
  Nombre_Zona TEXT NOT NULL UNIQUE,
  Room_Points TEXT NOT NULL DEFAULT '[]',
  Updated_At DATETIME
);

CREATE TABLE IF NOT EXISTS Mesas (
  ID_Mesa INTEGER PRIMARY KEY AUTOINCREMENT,
  ID_Zona INTEGER NOT NULL,
  Numero_Mesa TEXT NOT NULL,
  Capacidad INTEGER NOT NULL,

  Ubicacion_X INTEGER NOT NULL,
  Ubicacion_Y INTEGER NOT NULL,

  Shape TEXT NOT NULL, -- 'rect' | 'rounded' | 'circle'
  Width INTEGER NOT NULL,
  Height INTEGER NOT NULL,
  Radius INTEGER,

  Updated_At DATETIME,
  Es_Sistema INTEGER NOT NULL DEFAULT 0,

  UNIQUE (ID_Zona, Numero_Mesa),
  FOREIGN KEY (ID_Zona) REFERENCES Zonas(ID_Zona) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Clientes (
  ID_Cliente INTEGER PRIMARY KEY AUTOINCREMENT,
  Nombre TEXT NOT NULL,
  Telefono TEXT,
  Email TEXT,
  Notas TEXT,
  Total_Gastado REAL NOT NULL DEFAULT 0,
  Created_At TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS Reservas (
  ID_Reserva INTEGER PRIMARY KEY AUTOINCREMENT,

  ID_Cliente INTEGER NOT NULL,
  ID_Mesa INTEGER NOT NULL,

  Dia_YMD TEXT NOT NULL,     -- 'YYYY-MM-DD'
  Hora TEXT NOT NULL,        -- 'HH:MM'
  Turno TEXT NOT NULL,       -- 'COMIDA' | 'CENA'
  Comensales INTEGER NOT NULL DEFAULT 1,
  Nota TEXT,
  Estado TEXT NOT NULL DEFAULT 'ACTIVA', -- ACTIVA | CANCELADA | NO_SHOW | FINALIZADA

  Created_At TEXT DEFAULT (datetime('now','localtime')),

  FOREIGN KEY (ID_Cliente) REFERENCES Clientes(ID_Cliente),
  FOREIGN KEY (ID_Mesa) REFERENCES Mesas(ID_Mesa)
);

CREATE INDEX IF NOT EXISTS idx_reservas_mesa_dia_hora
ON Reservas(ID_Mesa, Dia_YMD, Hora);

/* =========================================================
   5. Comandas / Detalles / Facturas / Cuentas
========================================================= */
CREATE TABLE IF NOT EXISTS Comandas (
  ID_Comanda INTEGER PRIMARY KEY AUTOINCREMENT,
  ID_Mesa INTEGER NOT NULL,
  ID_Reserva INTEGER NULL,
  ID_Trabajador INTEGER NULL,

  Fecha_Hora_Apertura TEXT NOT NULL,
  Fecha_Hora_Cierre TEXT NULL,
  Total_Comanda REAL NOT NULL DEFAULT 0,
  Estado TEXT NOT NULL DEFAULT 'Abierta', -- Abierta | Pagada

  FOREIGN KEY (ID_Mesa) REFERENCES Mesas(ID_Mesa),
  FOREIGN KEY (ID_Reserva) REFERENCES Reservas(ID_Reserva),
  FOREIGN KEY (ID_Trabajador) REFERENCES Trabajadores(ID_Trabajador) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_comandas_mesa_estado
ON Comandas(ID_Mesa, Estado);

CREATE INDEX IF NOT EXISTS idx_comandas_reserva
ON Comandas(ID_Reserva);

-- ✅ útil para stats de camareros
CREATE INDEX IF NOT EXISTS idx_comandas_trab_apertura
ON Comandas(ID_Trabajador, Fecha_Hora_Apertura);


CREATE TABLE IF NOT EXISTS Detalle_Comanda (
  ID_Detalle INTEGER PRIMARY KEY AUTOINCREMENT,
  ID_Comanda INTEGER NOT NULL,
  ID_Producto INTEGER NOT NULL,
  Cantidad REAL NOT NULL,
  Precio_Unitario REAL NOT NULL,
  Notas TEXT,
  Estado_Cocina TEXT DEFAULT 'PENDIENTE',
  Fecha_Hora_Cocina DATETIME,
  ID_Usuario_Cocinero INTEGER,
  FOREIGN KEY (ID_Comanda) REFERENCES Comandas(ID_Comanda),
  FOREIGN KEY (ID_Producto) REFERENCES Productos(ID_Producto)
);
CREATE INDEX IF NOT EXISTS idx_dc_cocinero_fecha
ON Detalle_Comanda(ID_Usuario_Cocinero, Fecha_Hora_Cocina);

CREATE INDEX IF NOT EXISTS idx_dc_estado_fecha
ON Detalle_Comanda(Estado_Cocina, Fecha_Hora_Cocina);

-- ✅ NUEVO (muy recomendado): trazabilidad de consumo por lote
CREATE TABLE IF NOT EXISTS Lote_Consumos (
  ID_Detalle INTEGER NOT NULL,
  ID_Lote INTEGER NOT NULL,
  Cantidad REAL NOT NULL,
  PRIMARY KEY (ID_Detalle, ID_Lote),
  FOREIGN KEY (ID_Detalle) REFERENCES Detalle_Comanda(ID_Detalle) ON DELETE CASCADE,
  FOREIGN KEY (ID_Lote) REFERENCES Lotes_Producto(ID_Lote),
  CHECK (Cantidad > 0)
);

CREATE INDEX IF NOT EXISTS idx_lote_consumos_lote ON Lote_Consumos(ID_Lote);

CREATE TABLE IF NOT EXISTS Facturas (
  ID_Factura INTEGER PRIMARY KEY AUTOINCREMENT,
  ID_Comanda INTEGER UNIQUE NOT NULL,
  ID_Cliente INTEGER,
  Fecha_Emision DATETIME NOT NULL,
  Subtotal REAL NOT NULL,
  IVA REAL NOT NULL,
  Total_Pagado REAL NOT NULL,
  Metodo_Pago TEXT,
  FOREIGN KEY (ID_Comanda) REFERENCES Comandas(ID_Comanda),
  FOREIGN KEY (ID_Cliente) REFERENCES Clientes(ID_Cliente)
);

CREATE TABLE IF NOT EXISTS Cuentas_Gastos (
  ID_Gasto INTEGER PRIMARY KEY AUTOINCREMENT,
  Fecha DATE NOT NULL,
  Concepto TEXT NOT NULL,
  Importe REAL NOT NULL,
  Tipo_Gasto TEXT NOT NULL
);

/* =========================================================
   6. Tareas
========================================================= */
CREATE TABLE IF NOT EXISTS Tareas (
  ID_Tarea INTEGER PRIMARY KEY AUTOINCREMENT,
  Titulo TEXT NOT NULL,
  Descripcion TEXT,
  Fecha_Creacion DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
  Fecha_Limite DATE,
  Estado TEXT NOT NULL DEFAULT 'ABIERTA'
);

CREATE TABLE IF NOT EXISTS Tarea_Asignaciones (
  ID_Tarea INTEGER NOT NULL,
  ID_Trabajador INTEGER NOT NULL,
  Asignada_At DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
  Estado TEXT NOT NULL DEFAULT 'PENDIENTE',
  Finalizada_At DATETIME,
  PRIMARY KEY (ID_Tarea, ID_Trabajador),
  FOREIGN KEY (ID_Tarea) REFERENCES Tareas(ID_Tarea) ON DELETE CASCADE,
  FOREIGN KEY (ID_Trabajador) REFERENCES Trabajadores(ID_Trabajador) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tarea_asig_trab ON Tarea_Asignaciones(ID_Trabajador, Estado);
CREATE INDEX IF NOT EXISTS idx_tarea_asig_tarea ON Tarea_Asignaciones(ID_Tarea);

/* =========================================================
   7. Fichajes
========================================================= */
CREATE TABLE IF NOT EXISTS Fichajes (
  ID_Fichaje INTEGER PRIMARY KEY AUTOINCREMENT,
  ID_Usuario INTEGER NOT NULL,
  Fecha DATE NOT NULL,
  Parte INTEGER NOT NULL DEFAULT 1, -- 1 o 2
  Hora_Entrada DATETIME,
  Hora_Salida DATETIME,
  Estado TEXT DEFAULT 'ABIERTO',
  Cerrado_Automatico INTEGER DEFAULT 0,
  Cierre_Motivo TEXT,
  Incidencia TEXT,
  UNIQUE(ID_Usuario, Fecha, Parte),
  FOREIGN KEY (ID_Usuario) REFERENCES Usuarios(ID_Usuario)
);

CREATE INDEX IF NOT EXISTS idx_fichajes_user_fecha ON Fichajes(ID_Usuario, Fecha);
CREATE INDEX IF NOT EXISTS idx_fichajes_user_abierto ON Fichajes(ID_Usuario, Estado);

CREATE TABLE IF NOT EXISTS Fichaje_Dia (
  ID_Usuario INTEGER NOT NULL,
  Fecha DATE NOT NULL,
  Turno_Partido INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ID_Usuario, Fecha),
  FOREIGN KEY (ID_Usuario) REFERENCES Usuarios(ID_Usuario)
);

/* =========================================================
   8. Pagos
========================================================= */
CREATE TABLE IF NOT EXISTS Pagos (
  ID_Pago INTEGER PRIMARY KEY AUTOINCREMENT,
  ID_Comanda INTEGER NOT NULL,
  Fecha_Hora DATETIME NOT NULL,
  Metodo_Pago TEXT NOT NULL,
  Importe_Total REAL NOT NULL,
  Tipo TEXT NOT NULL, -- 'TOTAL' | 'FRACCIONADO'

  ID_Usuario_Cobrador INTEGER,
  ID_Trabajador_Cobrador INTEGER,

  FOREIGN KEY (ID_Comanda) REFERENCES Comandas(ID_Comanda) ON DELETE CASCADE,
  FOREIGN KEY (ID_Usuario_Cobrador) REFERENCES Usuarios(ID_Usuario) ON DELETE SET NULL,
  FOREIGN KEY (ID_Trabajador_Cobrador) REFERENCES Trabajadores(ID_Trabajador) ON DELETE SET NULL
);

-- ✅ índices para stats rápidas
CREATE INDEX IF NOT EXISTS idx_pagos_fecha ON Pagos(Fecha_Hora);
CREATE INDEX IF NOT EXISTS idx_pagos_comanda_fecha ON Pagos(ID_Comanda, Fecha_Hora);
CREATE INDEX IF NOT EXISTS idx_pagos_trab_cobrador_fecha
ON Pagos(ID_Trabajador_Cobrador, Fecha_Hora);

CREATE TABLE IF NOT EXISTS Pago_Detalles (
  ID_Pago INTEGER NOT NULL,
  ID_Detalle INTEGER NOT NULL,
  PRIMARY KEY (ID_Pago, ID_Detalle),
  FOREIGN KEY (ID_Pago) REFERENCES Pagos(ID_Pago),
  FOREIGN KEY (ID_Detalle) REFERENCES Detalle_Comanda(ID_Detalle)
);

/* =========================================================
   9. Configuración (single-row)
========================================================= */
CREATE TABLE IF NOT EXISTS Business_Settings (
  ID INTEGER PRIMARY KEY CHECK (ID = 1),
  Business_Name TEXT NOT NULL DEFAULT 'TPV',
  Logo_DataUrl  TEXT,
  Direccion TEXT DEFAULT '',
  Telefono  TEXT DEFAULT '',
  CIF       TEXT DEFAULT '',
  Mensaje_Footer TEXT DEFAULT '¡Gracias por su visita!',
  IVA_Percent REAL NOT NULL DEFAULT 10,
  Updated_At TEXT DEFAULT (datetime('now','localtime'))
);

INSERT OR IGNORE INTO Business_Settings (ID) VALUES (1);

CREATE TABLE IF NOT EXISTS Ticket_Settings (
  ID INTEGER PRIMARY KEY CHECK (ID = 1),
  Show_Logo          INTEGER NOT NULL DEFAULT 1,
  Show_BusinessName  INTEGER NOT NULL DEFAULT 1,
  Show_Address       INTEGER NOT NULL DEFAULT 1,
  Show_Phone         INTEGER NOT NULL DEFAULT 1,
  Show_CIF           INTEGER NOT NULL DEFAULT 1,
  Show_DateTime      INTEGER NOT NULL DEFAULT 1,
  Show_LineItems     INTEGER NOT NULL DEFAULT 1,
  Show_BaseAndIVA    INTEGER NOT NULL DEFAULT 1,
  Show_Total         INTEGER NOT NULL DEFAULT 1,
  Show_FooterMessage INTEGER NOT NULL DEFAULT 1,
  Updated_At TEXT DEFAULT (datetime('now','localtime'))
);

INSERT OR IGNORE INTO Ticket_Settings (ID) VALUES (1);

CREATE TABLE IF NOT EXISTS Horario_Predeterminado (
  ID_Default INTEGER PRIMARY KEY AUTOINCREMENT,
  ID_Trabajador INTEGER NOT NULL,
  Weekday INTEGER NOT NULL,         -- 1..7
  Orden INTEGER NOT NULL DEFAULT 1, -- 1..N por día
  ID_Turno INTEGER NOT NULL,
  Area TEXT NOT NULL,
  Hora_Inicio TIME,
  Hora_Fin TIME,
  Notas TEXT,
  FOREIGN KEY (ID_Trabajador) REFERENCES Trabajadores(ID_Trabajador) ON DELETE CASCADE,
  FOREIGN KEY (ID_Turno) REFERENCES Turnos(ID_Turno),
  UNIQUE (ID_Trabajador, Weekday, Orden)
);

CREATE INDEX IF NOT EXISTS idx_hp_trab_weekday ON Horario_Predeterminado(ID_Trabajador, Weekday);

/* =========================================================
   10. VISTAS ÚTILES
========================================================= */
CREATE VIEW IF NOT EXISTS v_inventario_producto_stock AS
SELECT
  p.ID_Producto,
  COALESCE(SUM(l.Stock_Disponible), 0) AS Stock_Actual,

  (
    SELECT l2.Caducidad
    FROM Lotes_Producto l2
    WHERE l2.ID_Producto = p.ID_Producto
      AND COALESCE(l2.Stock_Disponible, 0) > 0
      AND l2.Caducidad IS NOT NULL
    ORDER BY date(l2.Caducidad) ASC, datetime(l2.Fecha_Entrada) ASC, l2.ID_Lote ASC
    LIMIT 1
  ) AS Caducidad_Proxima,

  (
    SELECT l3.Codigo_Lote
    FROM Lotes_Producto l3
    WHERE l3.ID_Producto = p.ID_Producto
      AND COALESCE(l3.Stock_Disponible, 0) > 0
    ORDER BY
      CASE WHEN l3.Caducidad IS NULL THEN 1 ELSE 0 END,
      date(l3.Caducidad) ASC,
      datetime(l3.Fecha_Entrada) ASC,
      l3.ID_Lote ASC
    LIMIT 1
  ) AS Lote_Proximo
FROM Productos p
LEFT JOIN Lotes_Producto l ON l.ID_Producto = p.ID_Producto
GROUP BY p.ID_Producto;

/* =========================================================
   SEEDS / DATOS INICIALES (DEMO)
========================================================= */

-- Categorías
INSERT OR IGNORE INTO Categorias_Producto (Nombre, Nombre_Imagen, Ruta_Imagen, Vendible, Pasa_Cocina) VALUES
  ('Comidas',  'comidas.png', '/comidas.png', 1, 1),
  ('Bebidas',  'comidas.png', '/comidas.png', 1, 0),
  ('Limpieza', 'comidas.png', '/comidas.png', 0, 0),
  ('Postres',  'comidas.png', '/comidas.png', 1, 1);

-- Proveedores
INSERT OR IGNORE INTO Proveedores (Nombre_Empresa, Contacto, Telefono, Email, CIF) VALUES
  ('Distribuciones Demo SL', 'Carlos', '910000001', 'proveedor1@demo.com', 'B00000001'),
  ('Bebidas Demo SL',        'Marta',  '910000002', 'proveedor2@demo.com', 'B00000002'),
  ('Limpieza Demo SL',       'Pablo',  '910000003', 'proveedor3@demo.com', 'B00000003');

-- Productos (ficha)
INSERT OR IGNORE INTO Productos (
  ID_Categoria, ID_Proveedor, Nombre, Precio_Venta, Stock_Minimo,
  Unidad_Medida, Nombre_Imagen, Ruta_Imagen, Cantidad_Pedido_Esperada
) VALUES
(
  (SELECT ID_Categoria FROM Categorias_Producto WHERE Nombre='Comidas' LIMIT 1),
  (SELECT ID_Proveedor FROM Proveedores WHERE Nombre_Empresa='Distribuciones Demo SL' LIMIT 1),
  'Hamburguesa', 9.50, 5,
  'ud', 'comidas.png', '/comidas.png', 30
),
(
  (SELECT ID_Categoria FROM Categorias_Producto WHERE Nombre='Bebidas' LIMIT 1),
  (SELECT ID_Proveedor FROM Proveedores WHERE Nombre_Empresa='Bebidas Demo SL' LIMIT 1),
  'Coca-Cola', 2.50, 10,
  'ud', 'comidas.png', '/comidas.png', 100
),
(
  (SELECT ID_Categoria FROM Categorias_Producto WHERE Nombre='Limpieza' LIMIT 1),
  (SELECT ID_Proveedor FROM Proveedores WHERE Nombre_Empresa='Limpieza Demo SL' LIMIT 1),
  'Lavavajillas', 8.90, 3,
  'ud', 'comidas.png', '/comidas.png', 12
);

-- ✅ LOTES DEMO (varios lotes por producto)
INSERT OR IGNORE INTO Lotes_Producto (
  ID_Producto, Codigo_Lote, Fecha_Entrada, Caducidad,
  Cantidad_Inicial, Stock_Disponible, Coste_Unitario, ID_Proveedor, Notas
) VALUES
-- Hamburguesa (2 lotes con caducidades diferentes)
(
  (SELECT ID_Producto FROM Productos WHERE Nombre='Hamburguesa' LIMIT 1),
  'H-0001', datetime('now','localtime','-3 days'), date('now','+3 days'),
  8, 8, 4.20,
  (SELECT ID_Proveedor FROM Proveedores WHERE Nombre_Empresa='Distribuciones Demo SL' LIMIT 1),
  'Lote más antiguo'
),
(
  (SELECT ID_Producto FROM Productos WHERE Nombre='Hamburguesa' LIMIT 1),
  'H-0002', datetime('now','localtime','-1 days'), date('now','+10 days'),
  12, 12, 4.10,
  (SELECT ID_Proveedor FROM Proveedores WHERE Nombre_Empresa='Distribuciones Demo SL' LIMIT 1),
  'Lote reciente'
),

-- Coca-Cola (1 lote)
(
  (SELECT ID_Producto FROM Productos WHERE Nombre='Coca-Cola' LIMIT 1),
  'C-0002', datetime('now','localtime','-1 days'), date('now','+180 days'),
  60, 60, 0.60,
  (SELECT ID_Proveedor FROM Proveedores WHERE Nombre_Empresa='Bebidas Demo SL' LIMIT 1),
  NULL
),

-- Lavavajillas (sin caducidad)
(
  (SELECT ID_Producto FROM Productos WHERE Nombre='Lavavajillas' LIMIT 1),
  'LIM-0003', datetime('now','localtime','-15 days'), NULL,
  8, 8, 2.30,
  (SELECT ID_Proveedor FROM Proveedores WHERE Nombre_Empresa='Limpieza Demo SL' LIMIT 1),
  'Sin caducidad'
);

-- Alérgenos
INSERT OR IGNORE INTO Alergenos (Nombre, Nombre_Imagen, Ruta_Imagen) VALUES
  ('Gluten', 'gluten.png', '/alergenos/gluten.png'),
  ('Crustáceos', 'crustaceos.png', '/alergenos/crustaceos.png'),
  ('Huevos', 'huevos.png', '/alergenos/huevos.png'),
  ('Pescado', 'pescado.png', '/alergenos/pescado.png'),
  ('Cacahuetes', 'cacahuetes.png', '/alergenos/cacahuetes.png'),
  ('Soja', 'soja.png', '/alergenos/soja.png'),
  ('Lácteos', 'lacteos.png', '/alergenos/lacteos.png'),
  ('Frutos de cáscara', 'frutos_cascara.png', '/alergenos/frutos_cascara.png'),
  ('Apio', 'apio.png', '/alergenos/apio.png'),
  ('Mostaza', 'mostaza.png', '/alergenos/mostaza.png'),
  ('Sésamo', 'sesamo.png', '/alergenos/sesamo.png'),
  ('Sulfitos', 'sulfitos.png', '/alergenos/sulfitos.png'),
  ('Altramuces', 'altramuces.png', '/alergenos/altramuces.png'),
  ('Moluscos', 'moluscos.png', '/alergenos/moluscos.png');

-- Zonas / Mesas
INSERT OR IGNORE INTO Zonas (Nombre_Zona, Room_Points, Updated_At) VALUES
  ('Salon', '[]', datetime('now')),
  ('Terraza', '[]', datetime('now'));

-- ✅✅ NUEVO: ZONA + MESA "BARRA" (para Venta Rápida, NO se renderiza si filtras Es_Sistema=1)
INSERT OR IGNORE INTO Zonas (Nombre_Zona, Room_Points, Updated_At)
VALUES ('BARRA', '[]', datetime('now'));

INSERT OR IGNORE INTO Mesas (
  ID_Zona, Numero_Mesa, Capacidad,
  Ubicacion_X, Ubicacion_Y,
  Shape, Width, Height, Radius,
  Updated_At, Es_Sistema
) VALUES (
  (SELECT ID_Zona FROM Zonas WHERE Nombre_Zona='BARRA' LIMIT 1),
  'BARRA', 0,
  0, 0,
  'rect', 1, 1, NULL,
  datetime('now'), 1
);

-- Mesas visibles
INSERT OR IGNORE INTO Mesas (
  ID_Zona, Numero_Mesa, Capacidad,
  Ubicacion_X, Ubicacion_Y,
  Shape, Width, Height, Radius,
  Updated_At
) VALUES
(
  (SELECT ID_Zona FROM Zonas WHERE Nombre_Zona='Salon' LIMIT 1),
  'M1', 4, 120, 140, 'rect', 90, 60, NULL, datetime('now')
),
(
  (SELECT ID_Zona FROM Zonas WHERE Nombre_Zona='Salon' LIMIT 1),
  'M2', 2, 260, 140, 'rounded', 80, 55, 10, datetime('now')
),
(
  (SELECT ID_Zona FROM Zonas WHERE Nombre_Zona='Terraza' LIMIT 1),
  'T1', 4, 140, 260, 'circle', 70, 70, 35, datetime('now')
);

-- Fichajes demo (se ignora si no existe camarero@local)
INSERT OR IGNORE INTO Fichajes (
  ID_Usuario, Fecha, Hora_Entrada, Hora_Salida,
  Estado, Cerrado_Automatico, Cierre_Motivo, Incidencia
) VALUES
(
  (SELECT ID_Usuario FROM Usuarios WHERE Email='camarero@local' LIMIT 1),
  date('now'),
  datetime('now','-6 hours'),
  datetime('now','-1 hours'),
  'CERRADO',
  0,
  NULL,
  NULL
);
/* =========================================================
   SEEDS CLIENTES + RESERVAS + COMANDAS + PAGOS (para STATS)
========================================================= */

INSERT OR IGNORE INTO Clientes (ID_Cliente, Nombre, Telefono, Email, Notas, Total_Gastado, Created_At) VALUES
  (1, 'Ana Prueba',    '600000001', 'ana@demo.com',    'Nueva hoy con compra',     45.00, datetime('now','localtime','-2 hours')),
  (2, 'Bruno Demo',    '600000002', 'bruno@demo.com',  'Nueva hoy sin compra',     0.00,  datetime('now','localtime','-1 hours')),
  (3, 'Carla Test',    '600000003', 'carla@demo.com',  'Primera compra hoy',       18.50, datetime('now','localtime','-3 hours')),
  (4, 'Dani Repe',     '600000004', 'dani@demo.com',   'Compra antigua + hoy',     120.00, datetime('now','localtime','-40 days')),
  (5, 'Eva Repe',      '600000005', 'eva@demo.com',    'Compra antigua + semana',  70.00, datetime('now','localtime','-90 days')),
  (6, 'Fran VIP',      '600000006', 'fran@demo.com',   'Top gasto',                999.99, datetime('now','localtime','-200 days'));

INSERT OR IGNORE INTO Reservas (ID_Reserva, ID_Cliente, ID_Mesa, Dia_YMD, Hora, Turno, Comensales, Nota, Estado, Created_At) VALUES
  (101, 1, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='M1' AND COALESCE(Es_Sistema,0)=0 LIMIT 1), date('now'), '13:30', 'COMIDA', 2, 'Reserva hoy', 'FINALIZADA', datetime('now','localtime','-4 hours')),
  (102, 3, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='M2' AND COALESCE(Es_Sistema,0)=0 LIMIT 1), date('now'), '14:15', 'COMIDA', 2, 'Reserva hoy', 'FINALIZADA', datetime('now','localtime','-4 hours')),
  (103, 4, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='T1' AND COALESCE(Es_Sistema,0)=0 LIMIT 1), date('now'), '21:30', 'CENA',   3, 'Reserva hoy', 'FINALIZADA', datetime('now','localtime','-6 hours')),
  (201, 5, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='M1' AND COALESCE(Es_Sistema,0)=0 LIMIT 1), date('now','-3 days'), '20:30', 'CENA', 2, 'Reserva semana', 'FINALIZADA', datetime('now','localtime','-3 days')),
  (301, 4, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='M2' AND COALESCE(Es_Sistema,0)=0 LIMIT 1), date('now','-20 days'), '13:00', 'COMIDA', 2, 'Antigua', 'FINALIZADA', datetime('now','localtime','-20 days')),
  (302, 5, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='T1' AND COALESCE(Es_Sistema,0)=0 LIMIT 1), date('now','-40 days'), '14:00', 'COMIDA', 2, 'Antigua', 'FINALIZADA', datetime('now','localtime','-40 days')),
  (303, 6, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='M1' AND COALESCE(Es_Sistema,0)=0 LIMIT 1), date('now','-120 days'), '21:00', 'CENA', 4, 'Antigua VIP', 'FINALIZADA', datetime('now','localtime','-120 days'));

INSERT OR IGNORE INTO Comandas (
  ID_Comanda, ID_Mesa, ID_Reserva, ID_Trabajador,
  Fecha_Hora_Apertura, Fecha_Hora_Cierre, Total_Comanda, Estado
) VALUES
  (1001, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='M1' AND COALESCE(Es_Sistema,0)=0 LIMIT 1), 101, NULL,
   datetime('now','localtime','-3 hours'), datetime('now','localtime','-2 hours'), 25.00, 'Pagada'),
  (1002, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='M2' AND COALESCE(Es_Sistema,0)=0 LIMIT 1), 102, NULL,
   datetime('now','localtime','-3 hours'), datetime('now','localtime','-2 hours'), 18.50, 'Pagada'),
  (1003, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='T1' AND COALESCE(Es_Sistema,0)=0 LIMIT 1), 103, NULL,
   datetime('now','localtime','-5 hours'), datetime('now','localtime','-4 hours'), 40.00, 'Pagada'),
  (2001, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='M1' AND COALESCE(Es_Sistema,0)=0 LIMIT 1), 201, NULL,
   datetime('now','localtime','-3 days','-2 hours'), datetime('now','localtime','-3 days','-1 hours'), 22.00, 'Pagada'),
  (3001, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='M2' AND COALESCE(Es_Sistema,0)=0 LIMIT 1), 301, NULL,
   datetime('now','localtime','-20 days','-2 hours'), datetime('now','localtime','-20 days','-1 hours'), 35.00, 'Pagada'),
  (3002, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='T1' AND COALESCE(Es_Sistema,0)=0 LIMIT 1), 302, NULL,
   datetime('now','localtime','-40 days','-2 hours'), datetime('now','localtime','-40 days','-1 hours'), 15.00, 'Pagada'),
  (3003, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='M1' AND COALESCE(Es_Sistema,0)=0 LIMIT 1), 303, NULL,
   datetime('now','localtime','-120 days','-2 hours'), datetime('now','localtime','-120 days','-1 hours'), 200.00, 'Pagada');

INSERT OR IGNORE INTO Pagos (
  ID_Pago, ID_Comanda, Fecha_Hora, Metodo_Pago, Importe_Total, Tipo,
  ID_Usuario_Cobrador, ID_Trabajador_Cobrador
) VALUES
  (5001, 1001, datetime('now','localtime','-2 hours'), 'TARJETA', 25.00, 'TOTAL', NULL, NULL),
  (5002, 1002, datetime('now','localtime','-2 hours'), 'EFECTIVO', 18.50, 'TOTAL', NULL, NULL),
  (5003, 1003, datetime('now','localtime','-4 hours'), 'TARJETA', 40.00, 'TOTAL', NULL, NULL),
  (6001, 2001, datetime('now','localtime','-3 days','-1 hours'), 'TARJETA', 22.00, 'TOTAL', NULL, NULL),
  (7001, 3001, datetime('now','localtime','-20 days','-1 hours'), 'EFECTIVO', 35.00, 'TOTAL', NULL, NULL),
  (7002, 3002, datetime('now','localtime','-40 days','-1 hours'), 'EFECTIVO', 15.00, 'TOTAL', NULL, NULL),
  (7003, 3003, datetime('now','localtime','-120 days','-1 hours'), 'TARJETA', 200.00, 'TOTAL', NULL, NULL);

INSERT OR IGNORE INTO Reservas (ID_Reserva, ID_Cliente, ID_Mesa, Dia_YMD, Hora, Turno, Comensales, Estado)
VALUES (401, 1, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='M1' AND COALESCE(Es_Sistema,0)=0 LIMIT 1),
        date('now','-10 days'), '13:00', 'COMIDA', 2, 'FINALIZADA');

INSERT OR IGNORE INTO Comandas (ID_Comanda, ID_Mesa, ID_Reserva, Fecha_Hora_Apertura, Fecha_Hora_Cierre, Total_Comanda, Estado)
VALUES (4001, (SELECT ID_Mesa FROM Mesas WHERE Numero_Mesa='M1' AND COALESCE(Es_Sistema,0)=0 LIMIT 1),
        401, datetime('now','localtime','-10 days','-2 hours'), datetime('now','localtime','-10 days','-1 hours'), 12.00, 'Pagada');

INSERT OR IGNORE INTO Pagos (ID_Pago, ID_Comanda, Fecha_Hora, Metodo_Pago, Importe_Total, Tipo)
VALUES (8001, 4001, datetime('now','localtime','-10 days','-1 hours'), 'TARJETA', 12.00, 'TOTAL');
`;

// ========================
// SQL splitter seguro (respeta strings y comentarios)
// ========================
function splitSqlStatements(sql: string): string[] {
	const out: string[] = [];
	let buf = "";

	let inSQuote = false;
	let inDQuote = false;
	let inLineComment = false;
	let inBlockComment = false;

	for (let i = 0; i < sql.length; i++) {
		const c = sql[i];
		const n = i + 1 < sql.length ? sql[i + 1] : "";

		// fin de comentario línea
		if (inLineComment) {
			buf += c;
			if (c === "\n") inLineComment = false;
			continue;
		}

		// fin comentario bloque
		if (inBlockComment) {
			buf += c;
			if (c === "*" && n === "/") {
				buf += n;
				i++;
				inBlockComment = false;
			}
			continue;
		}

		// iniciar comentarios (si no estás en strings)
		if (!inSQuote && !inDQuote) {
			if (c === "-" && n === "-") {
				buf += c + n;
				i++;
				inLineComment = true;
				continue;
			}
			if (c === "/" && n === "*") {
				buf += c + n;
				i++;
				inBlockComment = true;
				continue;
			}
		}

		// toggle quotes
		if (!inDQuote && c === "'" && !inLineComment && !inBlockComment) {
			// maneja escape '' dentro de string
			if (inSQuote && n === "'") {
				buf += "''";
				i++;
				continue;
			}
			inSQuote = !inSQuote;
			buf += c;
			continue;
		}
		if (!inSQuote && c === `"` && !inLineComment && !inBlockComment) {
			inDQuote = !inDQuote;
			buf += c;
			continue;
		}

		// split por ;
		if (!inSQuote && !inDQuote && c === ";") {
			const stmt = buf.trim();
			if (stmt) out.push(stmt);
			buf = "";
			continue;
		}

		buf += c;
	}

	const last = buf.trim();
	if (last) out.push(last);
	return out;
}

// ========================
// Turso Platform API
// ========================

const TURSO_API_BASE = "https://api.turso.tech/v1";

async function tursoCreateDatabase(env: Env, dbName: string) {
	const group =
		env.TURSO_GROUP && env.TURSO_GROUP.trim().length > 0 ? env.TURSO_GROUP.trim() : "default";

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
		`${TURSO_API_BASE}/organizations/${encodeURIComponent(env.TURSO_ORG_SLUG)}/databases/${encodeURIComponent(dbName)}`,
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

function normalizeDbName(tenantId: string) {
	// nombres de turso: evita caracteres raros y limita longitud
	const t = tenantId.toLowerCase().replace(/[^a-z0-9-]/g, "-");
	return `tpv-${t}`.slice(0, 64);
}

// ========================
// Provision tenant DB + execute schema
// ========================

async function getTenantDbRow(dbi: any, tenantId: string) {
	const r = await execSql(
		dbi,
		`SELECT tenant_id, turso_db_name, turso_url, turso_auth_token_enc
		   FROM tenant_databases
		  WHERE tenant_id = ?`,
		[tenantId]
	);
	const rows = (r?.rows || r?.result?.rows || []) as any[];
	return rows.length ? rows[0] : null;
}

async function upsertTenantDbRow(dbi: any, tenantId: string, dbName: string, url: string, tokenEnc: string) {
	await execSql(
		dbi,
		`INSERT INTO tenant_databases (tenant_id, turso_db_name, turso_url, turso_auth_token_enc, created_at_ms, rotated_at_ms)
		 VALUES (?, ?, ?, ?, (unixepoch()*1000), (unixepoch()*1000))
		 ON CONFLICT(tenant_id) DO UPDATE SET
		   turso_db_name = excluded.turso_db_name,
		   turso_url = excluded.turso_url,
		   turso_auth_token_enc = excluded.turso_auth_token_enc,
		   rotated_at_ms = (unixepoch()*1000)`,
		[tenantId, dbName, url, tokenEnc]
	);
}

async function applyTenantSchema(tenantUrl: string, tenantTokenPlain: string) {
	const tenantDb = createClient({ url: tenantUrl, authToken: tenantTokenPlain });

	const stmts = splitSqlStatements(TENANT_SCHEMA_SQL);

	// Ejecuta en orden
	for (const s of stmts) {
		// Seguridad: evita ejecutar "vacíos"
		const sql = s.trim();
		if (!sql) continue;
		await tenantDb.execute(sql);
	}
}

async function ensureTenantDatabaseProvisioned(env: Env, dbi: any, tenantId: string) {
	// si ya existe mapping completo, no hacemos nada
	const current = await getTenantDbRow(dbi, tenantId);
	if (current?.turso_url && current?.turso_auth_token_enc) {
		return { ok: true, url: String(current.turso_url), dbName: String(current.turso_db_name || "") };
	}

	const ttl = env.TURSO_TOKEN_TTL && env.TURSO_TOKEN_TTL.trim().length > 0 ? env.TURSO_TOKEN_TTL.trim() : "7d";
	const dbName = current?.turso_db_name ? String(current.turso_db_name) : normalizeDbName(tenantId);

	// 1) crear db (o recuperarla si ya existe)
	let dbUrl: string | null = null;

	const created = await tursoCreateDatabase(env, dbName);
	let hostname =
		created.data?.database?.Hostname ||
		created.data?.database?.hostname ||
		created.data?.Hostname ||
		created.data?.hostname ||
		null;

	if (!created.ok || !hostname) {
		const got = await tursoGetDatabase(env, dbName);
		if (!got.ok) throw new Error(`turso_create_or_get_db_failed create=${created.status} get=${got.status}`);

		hostname =
			got.data?.database?.Hostname ||
			got.data?.database?.hostname ||
			got.data?.Hostname ||
			got.data?.hostname ||
			null;

		if (!hostname) throw new Error("turso_db_missing_hostname");
	}

	dbUrl = String(hostname).startsWith("libsql://") ? String(hostname) : `libsql://${hostname}`;

	// 2) token para esa db
	const tok = await tursoCreateDbToken(env, dbName, ttl);
	if (!tok.ok) throw new Error(`turso_create_token_failed status=${tok.status}`);

	const tokenPlain = tok.data?.jwt || tok.data?.token || tok.data?.Token || tok.data?.authToken;
	if (!tokenPlain) throw new Error("turso_create_token_missing_jwt");

	// 3) aplicar schema
	await applyTenantSchema(dbUrl, String(tokenPlain));

	// 4) guardar token cifrado en DB general
	const tokenEnc = await aesGcmEncryptB64(env.LICENSE_STORE_KEY, String(tokenPlain));
	await upsertTenantDbRow(dbi, tenantId, dbName, dbUrl, tokenEnc);

	return { ok: true, url: dbUrl, dbName };
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
			const miss = assertEnv(env, ["LEMON_WEBHOOK_SECRET", "TURSO_DATABASE_URL", "TURSO_AUTH_TOKEN", "LICENSE_STORE_KEY"]);
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

			const body = await readJsonSafe<ActivateRequest>(
				request,
				{
					activationKey: "",
					deviceId: "",
					instanceName: undefined,
				} as any
			);

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

			const tenantId =
				existing?.tenant_id && existing.tenant_id !== "PENDING"
					? existing.tenant_id
					: crypto.randomUUID();

			await ensureTenantExistsMinimal(dbi, tenantId);
			await ensureDevice(dbi, tenantId, deviceId, "tpv");

			// ✅ Crea DB del tenant + token + ejecuta TU schema
			try {
				await ensureTenantDatabaseProvisioned(env, dbi, tenantId);
			} catch (e: any) {
				console.log("[TURSO] tenant provisioning failed", { tenantId, err: String(e?.message || e) });
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
			await ensureExtraSchema(dbi);

			const lic = await getLicenseByHash(dbi, claims.licHash);
			if (!lic) return json({ ok: false, error: "not_found" }, 404);

			return json({
				ok: true,
				state: {
					tenant_id: lic.tenant_id,
					status: lic.status,
					expires_at: lic.expires_at,
					disabled: toBool01((lic as any).disabled, false),
					test_mode: toBool01((lic as any).test_mode, false),
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
				instances_count:
					typeof val.data?.license_key?.instances_count === "number"
						? val.data.license_key.instances_count
						: null,
				activation_limit:
					typeof val.data?.license_key?.activation_limit === "number"
						? val.data.license_key.activation_limit
						: null,
				lemon_updated_at: val.data?.license_key?.updated_at ? String(val.data.license_key.updated_at) : null,
				meta: val.data?.meta || null,
			});

			return json({ ok: true, status, expiresAt, valid: val.data?.valid, meta: val.data?.meta });
		}

		return new Response("Not found", { status: 404 });
	},
};