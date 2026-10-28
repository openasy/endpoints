// What makes a device compliant (ADR 0065): four checks, each read from the answers of the fixed query pack
// (osquery/osquery.conf), against one policy. Nothing here talks to a device; it reads what osquery already sent.

export const CHECKS = ["disk-encryption", "os-version", "firewall", "screen-lock"] as const;
export type CheckId = (typeof CHECKS)[number];
export type CheckStatus = "pass" | "fail" | "unknown" | "not-applicable";
export type Platform = "darwin" | "windows" | "linux" | "other";
export type Posture = "compliant" | "at-risk" | "non-compliant" | "pending";

/** A snapshot row as osquery sends it: every value is text. */
export type Rows = Array<Record<string, string>>;

export interface Policy {
  checks: Record<CheckId, { enabled: boolean; onFailure: "block" | "grace" }>;
  /** How long a failing check with onFailure grace leaves the device at risk before it is non-compliant. */
  graceDays: number;
  /** A device that has not checked in for this long is stale. */
  staleDays: number;
  minimum: {
    /** macOS, as major.minor or major.minor.patch. */
    macos: string;
    /** Windows build number, such as 22631 for Windows 11 23H2. */
    windowsBuild: number;
    /** By os_version.platform, such as ubuntu or debian: a distribution not listed is not checked. */
    linux: Record<string, string>;
  };
  /** The screen locks, or asks for its password, within this many minutes. */
  screenLockMinutes: number;
}

export const DEFAULT_POLICY: Policy = {
  checks: {
    "disk-encryption": { enabled: true, onFailure: "block" },
    "os-version": { enabled: true, onFailure: "grace" },
    firewall: { enabled: true, onFailure: "grace" },
    "screen-lock": { enabled: true, onFailure: "grace" },
  },
  graceDays: 7,
  staleDays: 7,
  minimum: { macos: "15.0", windowsBuild: 22631, linux: { ubuntu: "22.04", debian: "12" } },
  screenLockMinutes: 5,
};

/** The device facts the checks need besides the query answers. */
export interface DeviceFacts {
  platform: Platform;
  osName: string;
  osVersion: string;
  osBuild: string;
  osPlatform: string;
}

export interface CheckResult {
  check: CheckId;
  status: CheckStatus;
  detail: string;
}

/** osquery's os_version.platform as one of the platforms the pack has queries for. */
export function platformOf(osPlatform: string): Platform {
  if (osPlatform === "darwin") return "darwin";
  if (osPlatform === "windows") return "windows";
  if (!osPlatform || /bsd/.test(osPlatform)) return "other";
  return "linux";
}

/** Compares versions part by part, numbers as numbers: 15.10 is after 15.9, 22.04 equals 22.4. */
export function compareVersions(a: string, b: string): number {
  const parts = (v: string) => v.split(/[.\-+_~: ]/).filter(Boolean);
  const pa = parts(a);
  const pb = parts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "0";
    const y = pb[i] ?? "0";
    const nx = /^\d+$/.test(x) ? Number(x) : NaN;
    const ny = /^\d+$/.test(y) ? Number(y) : NaN;
    const c = !Number.isNaN(nx) && !Number.isNaN(ny) ? nx - ny : x.localeCompare(y);
    if (c !== 0) return c < 0 ? -1 : 1;
  }
  return 0;
}

/** The leading numeric part of a version as osquery reports it: "24.04.1 LTS (Noble Numbat)" is 24.04.1. */
const leading = (v: string) => /^\d+(\.\d+)*/.exec(v.trim())?.[0] ?? "";

const NO_ANSWER = "osquery has not answered this query yet.";

/** Each check of the policy for one device, from the last answer of each query in the pack. */
export function evaluate(device: DeviceFacts, results: Record<string, Rows | undefined>, policy: Policy): CheckResult[] {
  return CHECKS.map((check) => ({ check, ...one(check, device, results, policy) }));
}

function one(check: CheckId, d: DeviceFacts, results: Record<string, Rows | undefined>, policy: Policy): Omit<CheckResult, "check"> {
  const na = (detail: string) => ({ status: "not-applicable" as const, detail });
  const pass = (detail: string) => ({ status: "pass" as const, detail });
  const fail = (detail: string) => ({ status: "fail" as const, detail });
  const unknown = { status: "unknown" as const, detail: NO_ANSWER };
  if (d.platform === "other") return na("osquery reports a platform Endpoints has no queries for.");

  if (check === "disk-encryption") {
    if (d.platform === "darwin") {
      const rows = results.endpoints_encryption_macos;
      if (!rows) return unknown;
      // On APFS, / is the sealed system volume; what people write is on the data volume.
      const r = rows.find((x) => x.path === "/System/Volumes/Data") ?? rows.find((x) => x.path === "/");
      if (!r) return fail("osquery found no volume for /.");
      return r.encrypted === "1" || r.filevault_status === "on" ? pass("FileVault is on.") : fail("FileVault is off.");
    }
    if (d.platform === "windows") {
      const rows = results.endpoints_encryption_windows;
      if (!rows) return unknown;
      const r = rows[0];
      if (!r) return fail("BitLocker reports nothing for C:.");
      return r.protection_status === "1" ? pass("BitLocker protects C:.") : fail("BitLocker does not protect C:.");
    }
    const rows = results.endpoints_encryption_linux;
    if (!rows) return unknown;
    const r = rows.find((x) => x.encrypted === "1");
    return r ? pass(`The disk that holds / is encrypted${r.type ? ` (${r.type})` : ""}.`) : fail("The disk that holds / is not encrypted.");
  }

  if (check === "os-version") {
    if (!d.osVersion && !d.osBuild) return unknown;
    if (d.platform === "darwin") {
      const v = leading(d.osVersion);
      return compareVersions(v, policy.minimum.macos) >= 0 ? pass(`macOS ${v}.`) : fail(`macOS ${v} is older than ${policy.minimum.macos}.`);
    }
    if (d.platform === "windows") {
      const build = Number(d.osBuild);
      if (!Number.isInteger(build) || build <= 0) return unknown;
      return build >= policy.minimum.windowsBuild ? pass(`Build ${build}.`) : fail(`Build ${build} is older than ${policy.minimum.windowsBuild}.`);
    }
    const min = policy.minimum.linux[d.osPlatform];
    const name = d.osName || d.osPlatform;
    if (!min) return na(`The policy sets no minimum for ${name}.`);
    const v = leading(d.osVersion);
    return compareVersions(v, min) >= 0 ? pass(`${name} ${v}.`) : fail(`${name} ${v} is older than ${min}.`);
  }

  if (check === "firewall") {
    if (d.platform === "linux") return na("Not checked on Linux: core osquery cannot read ufw or nftables.");
    if (d.platform === "darwin") {
      const rows = results.endpoints_firewall_macos;
      if (!rows) return unknown;
      const state = Number(rows[0]?.global_state ?? 0);
      return state >= 1 ? pass(state === 2 ? "The firewall is on and blocks all incoming connections." : "The firewall is on.") : fail("The firewall is off.");
    }
    const rows = results.endpoints_firewall_windows;
    if (!rows) return unknown;
    const state = rows[0]?.firewall ?? "";
    return state === "Good" ? pass("Security Center reports the firewall on.") : fail(`Security Center reports the firewall as ${state || "missing"}.`);
  }

  // screen-lock
  const limit = policy.screenLockMinutes * 60;
  if (d.platform === "linux") return na("Not checked on Linux: core osquery cannot read the desktop's settings.");
  if (d.platform === "darwin") {
    const rows = results.endpoints_screenlock_macos;
    if (!rows) return unknown;
    const r = rows[0];
    if (!r || r.enabled !== "1") return fail("No password is asked after sleep or the screen saver.");
    const grace = Number(r.grace_period);
    if (!Number.isFinite(grace) || grace < 0) return fail("The delay before the password is unknown.");
    if (grace > limit) return fail(`The password is asked only ${minutes(grace)} after sleep or the screen saver.`);
    return pass(grace === 0 ? "A password is asked at once after sleep or the screen saver." : `A password is asked within ${minutes(grace)}.`);
  }
  const rows = results.endpoints_screenlock_windows;
  if (!rows) return unknown;
  const secs = Number(rows[0]?.data);
  if (!rows[0] || !Number.isFinite(secs) || secs <= 0) return fail("No machine inactivity limit is set.");
  return secs <= limit ? pass(`Windows locks after ${minutes(secs)} idle.`) : fail(`Windows locks only after ${minutes(secs)} idle.`);
}

const minutes = (s: number) => (s < 60 ? `${s} s` : s % 60 ? `${Math.floor(s / 60)} min ${s % 60} s` : `${s / 60} min`);

const DAY = 86_400_000;

export interface StoredCheck extends CheckResult {
  since: string;
}

export interface Failing {
  check: CheckId;
  detail: string;
  since: string;
  /** When the device becomes non-compliant for it; null when it blocks at once. */
  graceEndsAt: string | null;
  /** Counts against the device now: it blocks, or its grace period ended. */
  blocked: boolean;
}

/** A device's posture from its stored checks: exceptions make a failing check count as passing. */
export function postureOf(checks: StoredCheck[], policy: Policy, excepted: Set<CheckId>, now: number): { posture: Posture; failing: Failing[] } {
  const failing: Failing[] = [];
  let unknown = 0;
  for (const c of checks) {
    const rule = policy.checks[c.check];
    if (!rule.enabled || c.status === "not-applicable") continue;
    if (c.status === "unknown") unknown++;
    if (c.status !== "fail" || excepted.has(c.check)) continue;
    const grace = rule.onFailure === "grace" && policy.graceDays > 0;
    const ends = grace ? Date.parse(c.since) + policy.graceDays * DAY : null;
    failing.push({
      check: c.check,
      detail: c.detail,
      since: c.since,
      graceEndsAt: ends === null ? null : new Date(ends).toISOString(),
      blocked: ends === null || ends <= now,
    });
  }
  if (failing.some((f) => f.blocked)) return { posture: "non-compliant", failing };
  if (failing.length) return { posture: "at-risk", failing };
  // A check osquery has not answered yet is neither passed nor failed: the device waits for it.
  if (unknown) return { posture: "pending", failing };
  return { posture: "compliant", failing };
}

const bad = (detail: string) => Object.assign(new Error(detail), { invalid: true });

/** Checks a policy sent to the API, filling what it leaves out from the current one. Throws with a reason. */
export function parsePolicy(body: Record<string, unknown>, current: Policy): Policy {
  const out: Policy = structuredClone(current);
  if (body.checks !== undefined) {
    if (!body.checks || typeof body.checks !== "object" || Array.isArray(body.checks)) throw bad("checks is an object keyed by check.");
    for (const [id, rule] of Object.entries(body.checks as Record<string, unknown>)) {
      if (!(CHECKS as readonly string[]).includes(id)) throw bad(`checks has ${id}, which is not one of ${CHECKS.join(", ")}.`);
      const r = rule as Record<string, unknown> | null;
      if (!r || typeof r !== "object") throw bad(`checks.${id} is an object.`);
      if (r.enabled !== undefined && typeof r.enabled !== "boolean") throw bad(`checks.${id}.enabled is true or false.`);
      if (r.onFailure !== undefined && r.onFailure !== "block" && r.onFailure !== "grace") throw bad(`checks.${id}.onFailure is block or grace.`);
      const target = out.checks[id as CheckId];
      if (typeof r.enabled === "boolean") target.enabled = r.enabled;
      if (r.onFailure === "block" || r.onFailure === "grace") target.onFailure = r.onFailure;
    }
  }
  const whole = (v: unknown, name: string, min: number, max: number) => {
    if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) throw bad(`${name} is a whole number from ${min} to ${max}.`);
    return v;
  };
  if (body.graceDays !== undefined) out.graceDays = whole(body.graceDays, "graceDays", 0, 30);
  if (body.staleDays !== undefined) out.staleDays = whole(body.staleDays, "staleDays", 1, 90);
  if (body.screenLockMinutes !== undefined) out.screenLockMinutes = whole(body.screenLockMinutes, "screenLockMinutes", 1, 60);
  if (body.minimum !== undefined) {
    const m = body.minimum as Record<string, unknown> | null;
    if (!m || typeof m !== "object" || Array.isArray(m)) throw bad("minimum is an object with macos, windowsBuild and linux.");
    const version = (v: unknown, name: string) => {
      if (typeof v !== "string" || !/^\d{1,4}(\.\d{1,4}){0,2}$/.test(v)) throw bad(`${name} is a version such as 15.0 or 22.04.`);
      return v;
    };
    if (m.macos !== undefined) out.minimum.macos = version(m.macos, "minimum.macos");
    if (m.windowsBuild !== undefined) out.minimum.windowsBuild = whole(m.windowsBuild, "minimum.windowsBuild", 1, 99_999);
    if (m.linux !== undefined) {
      const l = m.linux as Record<string, unknown> | null;
      if (!l || typeof l !== "object" || Array.isArray(l)) throw bad('minimum.linux is an object of distribution and version, such as {"ubuntu": "22.04"}.');
      const entries = Object.entries(l);
      if (entries.length > 20) throw bad("minimum.linux has at most 20 distributions.");
      out.minimum.linux = {};
      for (const [k, v] of entries) {
        if (!/^[a-z][a-z0-9_-]{0,31}$/.test(k)) throw bad(`minimum.linux has ${k}, which is not a distribution as osquery names it, such as ubuntu.`);
        out.minimum.linux[k] = version(v, `minimum.linux.${k}`);
      }
    }
  }
  return out;
}
