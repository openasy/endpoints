// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export const CHECKS = ["disk-encryption", "os-version", "firewall", "screen-lock"] as const;
export type CheckId = (typeof CHECKS)[number];
export type CheckStatus = "pass" | "fail" | "unknown" | "not-applicable";
export type Posture = "compliant" | "at-risk" | "non-compliant" | "pending";
export type Platform = "darwin" | "windows" | "linux" | "other";

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface Failing {
  check: CheckId;
  detail: string;
  since: string;
  graceEndsAt: string | null;
  blocked: boolean;
}

export interface Device {
  id: string;
  uuid: string;
  name: string;
  hostname: string;
  serial: string;
  hardware: { vendor: string; model: string; cpu: string; memoryBytes: number | null };
  platform: Platform;
  os: { name: string; version: string; build: string; platform: string };
  osqueryVersion: string;
  packVersion: string;
  owner: string;
  enrolledAt: string;
  lastSeenAt: string;
  stale: boolean;
  reenrollUntil: string | null;
  posture: Posture;
  failing: Failing[];
  checks: Array<{ check: CheckId; status: CheckStatus; detail: string }>;
}

export interface DeviceDetail extends Omit<Device, "checks"> {
  checks: Array<{
    check: CheckId;
    status: CheckStatus;
    detail: string;
    since: string;
    enabled: boolean;
    onFailure: "block" | "grace";
    exception: { id: string; reason: string; expiresAt: string } | null;
  }>;
  users: Array<{ uid: string; username: string; description: string }>;
  software: number;
  enrollSecret: { id: string; name: string } | null;
}

export interface Installed {
  source: string;
  name: string;
  version: string;
  publisher: string;
  identifier: string;
  path: string;
}

export interface SoftwareTitle {
  name: string;
  publisher: string;
  platforms: string[];
  devices: number;
  newest: string;
  notOnNewest: number;
  versions: Array<{ version: string; devices: number }>;
}

export interface Install {
  device: { id: string; name: string; owner: string; platform: Platform };
  version: string;
  path: string;
}

export interface CheckStats {
  check: CheckId;
  enabled: boolean;
  onFailure: "block" | "grace";
  passing: number;
  failing: number;
  excepted: number;
  unknown: number;
  notApplicable: number;
}

export interface Compliance {
  checks: CheckStats[];
  platforms: Array<{ platform: "darwin" | "windows" | "linux" } & Record<Posture, number>>;
  failing: Array<Failing & { device: { id: string; name: string; owner: string; platform: Platform; os: string } }>;
}

export interface Policy {
  checks: Record<CheckId, { enabled: boolean; onFailure: "block" | "grace" }>;
  graceDays: number;
  staleDays: number;
  minimum: { macos: string; windowsBuild: number; linux: Record<string, string> };
  screenLockMinutes: number;
  updatedAt: string | null;
  updatedBy: string | null;
}

export interface PolicyException {
  id: string;
  device: { id: string; name: string };
  check: CheckId;
  reason: string;
  expiresAt: string;
  active: boolean;
  createdBy: string;
  createdAt: string;
}

export interface EnrollSecret {
  id: string;
  name: string;
  fingerprint: string;
  createdAt: string;
  createdBy: string;
  expiresAt: string | null;
  revokedAt: string | null;
  lastUsedAt: string | null;
  status: "active" | "expired" | "revoked";
  devices: number;
}

export type SetupPlatform = "darwin" | "linux" | "windows";

export interface Setup {
  publicUrl: string;
  tlsHostname: string;
  https: boolean;
  packVersion: string;
  pack: string;
  platforms: Record<SetupPlatform, { flags: string; steps: string }>;
}

export interface AuditEvent {
  id: number;
  at: string;
  actor: string;
  action: string;
  target: string;
  result: "success" | "denied";
  detail: string;
}

export interface Summary {
  devices: number;
  postures: Record<Posture, number>;
  stale: number;
  checks: CheckStats[];
  enrollSecrets: number;
  packVersion: string;
  outdatedPack: number;
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers },
  });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return ((res.headers.get("content-type") ?? "").includes("json") ? await res.json() : await res.text()) as T;
}
