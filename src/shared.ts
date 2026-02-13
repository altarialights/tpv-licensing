export type LicenseStatus =
	| "active"
	| "inactive"
	| "expired"
	| "disabled"
	| "invalid";

export type ApiError = {
	ok: false;
	error: string;
	details?: any;
};

export type ActivateRequest = {
	activationKey: string; // la license key que mete el cliente
	deviceId: string;      // id único del dispositivo (tpv main)
	instanceName?: string; // opcional (si no, se genera)
};

export type ActivateResponse = {
	ok: true;
	tenantId: string;
	token: string;         // JWT para siguientes llamadas
	status: LicenseStatus;
	expiresAt: string | null;
};

export type LemonWebhookPayload = {
	meta?: {
		event_name?: string;
		test_mode?: boolean;
	};
	data?: {
		attributes?: Record<string, any>;
	};
};
