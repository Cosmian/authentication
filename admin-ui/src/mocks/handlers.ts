import { http, HttpResponse } from "msw";
import { API_REALMS, API_VERSION } from "../constants/apiPaths";
import { mockRealms, mockVersion } from "./fixtures";

export const handlers = [
    http.get(API_REALMS, () => HttpResponse.json(mockRealms)),
    http.get(API_VERSION, () => HttpResponse.json(mockVersion)),
];