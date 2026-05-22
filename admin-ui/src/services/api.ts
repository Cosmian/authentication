export class ApiError extends Error {
    constructor(
        public status: number,
        message: string,
    ) {
        super(message);
        this.name = "ApiError";
    }
}

async function handleResponse<T>(response: Response): Promise<T> {
    if (!response.ok) {
        const text = await response.text().catch(() => "Unknown error");
        throw new ApiError(response.status, text);
    }
    if (response.status === 204) {
        return undefined as T;
    }
    return response.json() as Promise<T>;
}

export async function apiGet<T>(baseUrl: string, path: string): Promise<T> {
    const response = await fetch(`${baseUrl}${path}`, {
        method: "GET",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
    });
    return handleResponse<T>(response);
}

export async function apiPost<T>(baseUrl: string, path: string, body: unknown): Promise<T> {
    const response = await fetch(`${baseUrl}${path}`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    return handleResponse<T>(response);
}

export async function apiPut<T>(baseUrl: string, path: string, body: unknown): Promise<T> {
    const response = await fetch(`${baseUrl}${path}`, {
        method: "PUT",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    return handleResponse<T>(response);
}

export async function apiDelete<T = void>(baseUrl: string, path: string): Promise<T> {
    const response = await fetch(`${baseUrl}${path}`, {
        method: "DELETE",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
    });
    return handleResponse<T>(response);
}
