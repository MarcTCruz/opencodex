import * as z from "zod/v4";
import type { OcxConfig } from "../../types";

export const DEFAULT_NATIVE_MAIN_AUTH_GRACE_SECONDS = 60;
export const nativeMainAuthGraceSecondsSchema = z.number().int().min(1).max(86_400);

export function nativeMainAuthGraceSecondsConfigError(value: unknown): string | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const grace = (value as Record<string, unknown>).nativeMainAuthGraceSeconds;
  return grace === undefined || nativeMainAuthGraceSecondsSchema.safeParse(grace).success
    ? null : "schema_invalid: nativeMainAuthGraceSeconds: must be an integer from 1 to 86400, or omitted";
}

export function resolveNativeMainAuthGraceMs(
  config: Pick<OcxConfig, "nativeMainAuthGraceSeconds"> | null | undefined,
): number {
  const parsed = nativeMainAuthGraceSecondsSchema.safeParse(config?.nativeMainAuthGraceSeconds);
  return parsed.success ? parsed.data * 1_000 : DEFAULT_NATIVE_MAIN_AUTH_GRACE_SECONDS * 1_000;
}
