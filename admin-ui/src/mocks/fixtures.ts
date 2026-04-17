import { ADMIN_REALM_ID } from "../constants/apiPaths";

export interface MockRealmDto {
    id: string;
}

export const mockRealms: MockRealmDto[] = [{ id: ADMIN_REALM_ID }, { id: "sample-realm" }];

export const mockVersion = "mock-0.1.0";