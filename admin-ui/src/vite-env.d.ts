/// <reference types="vite/client" />

interface ImportMetaEnv {
	readonly VITE_AUTH_URL?: string;
	readonly VITE_USE_MOCKS?: string;
	/** Override the mock logged-in user. Values: "admin" (default), "alice", "bob" */
	readonly VITE_MOCK_USER?: string;
}

interface ImportMeta {
	readonly env: ImportMetaEnv;
}
