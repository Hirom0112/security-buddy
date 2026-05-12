// Mirror of Pydantic response models from apps/api.
// Hand-maintained for Slice 0. Consider openapi-typescript if it grows unwieldy.
//
// TODO(slice-1+): add Campaign, Attack, Verdict, Vulnerability types as
// the backend routes are built.

export interface HealthStatus {
  status: "ok" | "degraded" | "down";
  db: "ok" | "error";
  redis: "ok" | "error";
  langsmith: "ok" | "error";
  version: string;
}

export interface LoginFormState {
  error?: string | undefined;
}
