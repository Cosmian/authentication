import { apiGet } from "./api";

const ROLES_PATH = "/public/roles";

export function createRolesApi(baseUrl: string) {
    return {
        list: (): Promise<string[]> => apiGet<string[]>(baseUrl, ROLES_PATH),
    };
}
