import type { ApiError } from "./contracts";

export class ApiClientError extends Error {
  readonly code: ApiError["code"];
  readonly requestId: string | null;

  constructor(error: ApiError) {
    super(error.message);
    this.name = "ApiClientError";
    this.code = error.code;
    this.requestId = error.request_id;
  }
}
