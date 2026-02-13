// src/shared.ts

export type LicenseStatus = "active" | "expired" | "disabled" | "invalid";

export type ActivateRequest = {
	activationKey: string;   // la key que te da Lemon
	deviceId: string;        // hash estable del hardware (o lo que uses)
	instanceName?: string;   // opcional (nombre legible)
};

export type ActivateResponse = {
	ok: true;
	tenantId: string;        // tu id interno (por restaurante)
	token: string;           // JWT para llamadas futuras
	status: LicenseStatus;
	expiresAt: string | null;
};

export type ApiError = { ok: false; error: string };

export type LemonWebhookPayload = {
	meta?: {
		event_name?: string;
		custom_data?: Record<string, any>;
	};
	data?: {
		type?: string;
		id?: string;
		attributes?: Record<string, any>;
	};
};
