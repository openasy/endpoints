import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import type { AuthEvent, Role } from "@openasy/auth";
import { flagsFile, installSteps, INVENTORY, PACK, PACK_TEXT, PACK_VERSION, SOFTWARE_SOURCES, USERS, type SetupPlatform } from "./pack.ts";
import {
  CHECKS,
  compareVersions,
  DEFAULT_POLICY,
  evaluate,
  parsePolicy,
  platformOf,
  postureOf,
  type CheckId,
  type CheckStatus,
  type Failing,
  type Platform,
  type Policy,
  type Posture,
  type Rows,
  type StoredCheck,
} from "./posture.ts";

export type ProblemCode = "invalid-json" | "invalid-body" | "not-found" | "conflict" | "payload-too-large" | "internal-error";

export class EndpointsError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

const bad = (detail: string) => new EndpointsError(422, "invalid-body", detail);
const notFound = (what: string) => new EndpointsError(404, "not-found", `${what} does not exist.`);
const conflict = (detail: string) => new EndpointsError(409, "conflict", detail);

/** Who is calling, as app.ts knows it from the session or token: their name and email, or the token's name. */
export interface Actor {
  name: string;
  role: Role;
}

const DAY = 86_400_000;
const HOUR = 3_600_000;
/** An admin's permission for a device to enrol again lasts this long. */
const REENROL_MS = 7 * DAY;
/** The most rows Endpoints keeps from one snapshot, and the longest value: a laptop has fewer packages than this. */
const MAX_ROWS = 20_000;
const MAX_VALUE = 1024;

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

/** The kinds of event the audit screen filters by: the start of each action's name. */
export const AUDIT_KINDS = ["device", "secret", "policy", "exception", "auth"] as const;

type Row = Record<string, SQLInputValue>;

const text = (v: unknown, name: string, max: number): string => {
  if (typeof v !== "string" || !v.trim()) throw bad(`${name} is required.`);
  if (v.trim().length > max) throw bad(`${name} is at most ${max} characters.`);
  return v.trim();
};
const whole = (v: unknown, name: string, min: number, max: number, fallback?: number): number => {
  if (v === undefined && fallback !== undefined) return fallback;
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) throw bad(`${name} must be a whole number from ${min} to ${max}.`);
  return v;
};
/** A value osquery sent: text, cut to a length a column can show. */
const str = (v: unknown): string => (typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : "").slice(0, MAX_VALUE);

/** A snapshot's rows as osquery sends them, every value text; anything else is left out. */
function rowsOf(v: unknown): Rows | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: Rows = [];
  for (const r of v.slice(0, MAX_ROWS)) {
    if (!r || typeof r !== "object" || Array.isArray(r)) continue;
    const row: Record<string, string> = {};
    for (const [k, val] of Object.entries(r as Record<string, unknown>).slice(0, 64)) row[k.slice(0, 64)] = str(val);
    out.push(row);
  }
  return out;
}

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});

export interface EndpointsOptions {
  /** The address people open Endpoints at, behind TLS: osquery is pointed at its host. */
  publicUrl: string;
  /** Every event written to the audit log, for the structured log (ADR 0017). */
  onEvent?: (e: AuditEvent) => void;
  clock?: () => number;
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

export interface DeviceCheck extends StoredCheck {
  enabled: boolean;
  onFailure: "block" | "grace";
  exception: { id: string; reason: string; expiresAt: string } | null;
}

export function createEndpoints(db: DatabaseSync, { publicUrl, onEvent, clock = Date.now }: EndpointsOptions) {
  const iso = (ms = clock()) => new Date(ms).toISOString();
  const counters = { enrolmentsRefused: 0, invalidNodeKeys: 0, snapshots: 0, unknownQueries: 0 };

  // ---------------------------------------------------------------- the record (ADR 0013)

  const insertEvent = db.prepare("INSERT INTO audit (at, actor, action, target, result, detail) VALUES (?, ?, ?, ?, ?, ?)");
  function record(actor: string, action: string, target: string, opts: { result?: "success" | "denied"; detail?: string } = {}) {
    const event = { at: iso(), actor, action, target, result: opts.result ?? "success", detail: opts.detail ?? "" };
    const r = insertEvent.run(event.at, event.actor, event.action, event.target, event.result, event.detail);
    onEvent?.({ id: Number(r.lastInsertRowid), ...event });
  }

  /** Sign-ins, failures and changes to members and tokens from @openasy/auth, which names people by their id. */
  function recordAuth(event: AuthEvent) {
    const person = (id?: string) => {
      const u = id ? (db.prepare("SELECT name, email FROM auth_users WHERE id = ?").get(id) as { name: string; email: string } | undefined) : undefined;
      return u ? `${u.name} <${u.email}>` : (id ?? "");
    };
    record(person(event.actor) || "unknown", `auth.${event.type}`, person(event.target ?? event.actor), {
      result: event.type === "sign-in-failed" ? "denied" : "success",
      detail: [event.method, event.detail, `from ${event.ip}`].filter(Boolean).join(", "),
    });
  }

  // A device that cannot enrol asks again every minute; its refusal is recorded once an hour, not each time.
  const refusedAt = new Map<string, number>();
  function refuse(target: string, reason: string) {
    counters.enrolmentsRefused++;
    const key = `${target}\n${reason}`;
    const last = refusedAt.get(key);
    if (last !== undefined && last + HOUR > clock()) return { node_invalid: true };
    refusedAt.set(key, clock());
    if (refusedAt.size > 10_000) refusedAt.clear();
    record("osquery", "device.enrol", target, { result: "denied", detail: reason });
    return { node_invalid: true };
  }

  // ---------------------------------------------------------------- policy

  let current: Policy = (() => {
    const r = db.prepare("SELECT body FROM policy WHERE id = 1").get() as { body: string } | undefined;
    // A policy saved by an older release may lack fields added since; the defaults fill them.
    return r ? parsePolicy(JSON.parse(r.body) as Record<string, unknown>, DEFAULT_POLICY) : structuredClone(DEFAULT_POLICY);
  })();

  function policy() {
    const r = db.prepare("SELECT updated_at, updated_by FROM policy WHERE id = 1").get() as { updated_at: string; updated_by: string } | undefined;
    return { ...current, updatedAt: r?.updated_at ?? null, updatedBy: r?.updated_by ?? null };
  }

  function savePolicy(body: Record<string, unknown>, actor: Actor) {
    let next: Policy;
    try {
      next = parsePolicy(body, current);
    } catch (err) {
      throw bad((err as Error).message);
    }
    db.prepare(
      "INSERT INTO policy (id, body, updated_at, updated_by) VALUES (1, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET body = excluded.body, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
    ).run(JSON.stringify(next), iso(), actor.name);
    current = next;
    // What devices already reported is checked again against the new policy; a check that starts failing now starts its
    // grace period now.
    const ids = db.prepare("SELECT id FROM devices").all() as Array<{ id: string }>;
    db.exec("BEGIN");
    try {
      for (const { id } of ids) evaluateDevice(id);
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    record(actor.name, "policy.update", "policy", { detail: `${ids.length} devices checked again` });
    return policy();
  }

  // ---------------------------------------------------------------- enrolment secrets

  const toSecret = (r: Row) => {
    const revoked = r.revoked_at as string | null;
    const expires = r.expires_at as string | null;
    return {
      id: r.id as string,
      name: r.name as string,
      fingerprint: r.fingerprint as string,
      createdAt: r.created_at as string,
      createdBy: r.created_by as string,
      expiresAt: expires,
      revokedAt: revoked,
      lastUsedAt: (r.last_used_at as string | null) ?? null,
      status: revoked ? ("revoked" as const) : expires && expires <= iso() ? ("expired" as const) : ("active" as const),
      devices: Number(r.devices ?? 0),
    };
  };
  const SECRET_SELECT = "SELECT s.*, (SELECT COUNT(*) FROM devices d WHERE d.enroll_secret_id = s.id) AS devices FROM enroll_secrets s";

  const secrets = () => (db.prepare(`${SECRET_SELECT} ORDER BY s.created_at DESC`).all() as Row[]).map(toSecret);

  /** A new secret for osquery to enrol with, shown once. Many devices may enrol with it until it expires. */
  function createSecret(body: Record<string, unknown>, actor: Actor) {
    const name = text(body.name, "name", 64);
    const days = whole(body.expiresInDays, "expiresInDays", 1, 365, 90);
    if (db.prepare("SELECT 1 FROM enroll_secrets WHERE name = ?").get(name)) throw conflict(`An enrolment secret named ${name} exists.`);
    const secret = `oee_${randomBytes(32).toString("base64url")}`;
    const id = randomUUID();
    const hash = sha256(secret);
    db.prepare("INSERT INTO enroll_secrets (id, name, secret_hash, fingerprint, created_at, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
      id,
      name,
      hash,
      `SHA256:${hash.slice(0, 16)}`,
      iso(),
      actor.name,
      iso(clock() + days * DAY),
    );
    record(actor.name, "secret.create", name, { detail: `expires in ${days} days` });
    return { ...toSecret(db.prepare(`${SECRET_SELECT} WHERE s.id = ?`).get(id) as Row), secret };
  }

  /** No new device enrols with it; devices that did keep their own node keys. */
  function revokeSecret(id: string, actor: Actor) {
    const r = db.prepare("SELECT * FROM enroll_secrets WHERE id = ?").get(id) as Row | undefined;
    if (!r) throw notFound("The enrolment secret");
    if (!r.revoked_at) {
      db.prepare("UPDATE enroll_secrets SET revoked_at = ? WHERE id = ?").run(iso(), id);
      record(actor.name, "secret.revoke", r.name as string);
    }
    return toSecret(db.prepare(`${SECRET_SELECT} WHERE s.id = ?`).get(id) as Row);
  }

  // ---------------------------------------------------------------- osquery: enrol and results

  /** Hardware and operating system from osquery's host_details or the inventory query, into the device's columns. */
  function facts(system: Record<string, unknown>, os: Record<string, unknown>, osqueryVersion: string) {
    const osPlatform = str(os.platform);
    const memory = Number(str(system.physical_memory));
    return {
      name: str(system.computer_name) || str(system.hostname),
      hostname: str(system.hostname),
      serial: str(system.hardware_serial),
      vendor: str(system.hardware_vendor),
      model: str(system.hardware_model),
      cpu: str(system.cpu_brand),
      memory_bytes: Number.isFinite(memory) && memory > 0 ? memory : null,
      platform: platformOf(osPlatform),
      os_name: str(os.name),
      os_version: str(os.version),
      os_build: str(os.build),
      os_platform: osPlatform,
      osquery_version: osqueryVersion,
    };
  }

  function writeFacts(id: string, f: ReturnType<typeof facts>) {
    // A value osquery left empty keeps the one it sent before; the platform always follows the operating system.
    db.prepare(
      `UPDATE devices SET name = COALESCE(NULLIF(?, ''), name), hostname = COALESCE(NULLIF(?, ''), hostname), serial = COALESCE(NULLIF(?, ''), serial),
         vendor = COALESCE(NULLIF(?, ''), vendor), model = COALESCE(NULLIF(?, ''), model), cpu = COALESCE(NULLIF(?, ''), cpu),
         memory_bytes = COALESCE(?, memory_bytes), platform = CASE WHEN ? = '' THEN platform ELSE ? END, os_name = COALESCE(NULLIF(?, ''), os_name),
         os_version = COALESCE(NULLIF(?, ''), os_version), os_build = COALESCE(NULLIF(?, ''), os_build), os_platform = COALESCE(NULLIF(?, ''), os_platform),
         osquery_version = COALESCE(NULLIF(?, ''), osquery_version) WHERE id = ?`,
    ).run(
      f.name,
      f.hostname,
      f.serial,
      f.vendor,
      f.model,
      f.cpu,
      f.memory_bytes,
      f.os_platform,
      f.platform,
      f.os_name,
      f.os_version,
      f.os_build,
      f.os_platform,
      f.osquery_version,
      id,
    );
  }

  /**
   * osquery's enrolment (its TLS enroll plugin): a secret and the host's details in, a node key out. The answer has
   * osquery's shape, `node_invalid` on refusal, so osquery tries again later. A hardware UUID that is enrolled already
   * enrols again only when an admin allowed it: a copied secret cannot take over another device's record.
   */
  function enroll(body: Record<string, unknown>) {
    const secret = str(body.enroll_secret);
    const details = obj(body.host_details);
    const system = obj(details.system_info);
    const uuid = (str(system.uuid) || str(body.host_identifier)).trim().toUpperCase();
    const s = secret ? (db.prepare("SELECT * FROM enroll_secrets WHERE secret_hash = ?").get(sha256(secret)) as Row | undefined) : undefined;
    const label = uuid || "unknown device";
    if (!s) return refuse(label, "unknown enrolment secret");
    if (s.revoked_at) return refuse(label, `enrolment secret ${s.name as string} is revoked`);
    if ((s.expires_at as string) <= iso()) return refuse(label, `enrolment secret ${s.name as string} has expired`);
    if (!/^[0-9A-F-]{8,64}$/.test(uuid)) return refuse(label, "no hardware UUID; start osquery with --host_identifier=uuid");

    const f = facts(system, obj(details.os_version), str(obj(details.osquery_info).version));
    const existing = db.prepare("SELECT * FROM devices WHERE uuid = ?").get(uuid) as Row | undefined;
    if (existing?.node_key_hash && !((existing.reenroll_until as string | null) && (existing.reenroll_until as string) > iso()))
      return refuse(existing.name as string, "already enrolled; an admin must allow it to enrol again");

    const nodeKey = `oen_${randomBytes(32).toString("base64url")}`;
    const now = iso();
    let id = existing?.id as string | undefined;
    if (id) {
      db.prepare("UPDATE devices SET node_key_hash = ?, reenroll_until = NULL, enroll_secret_id = ?, enrolled_at = ?, last_seen_at = ? WHERE id = ?").run(
        sha256(nodeKey),
        s.id as string,
        now,
        now,
        id,
      );
    } else {
      id = randomUUID();
      db.prepare(
        "INSERT INTO devices (id, uuid, node_key_hash, enroll_secret_id, name, platform, enrolled_at, last_seen_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).run(id, uuid, sha256(nodeKey), s.id as string, f.name || uuid, f.platform, now, now, now);
    }
    writeFacts(id, f);
    db.prepare("UPDATE enroll_secrets SET last_used_at = ? WHERE id = ?").run(now, s.id as string);
    evaluateDevice(id);
    const name = (db.prepare("SELECT name FROM devices WHERE id = ?").get(id) as { name: string }).name;
    record("osquery", "device.enrol", name, { detail: `${existing ? "enrolled again" : "enrolled"} with ${s.name as string}, ${uuid}` });
    return { node_key: nodeKey, node_invalid: false };
  }

  /** One snapshot of a pack query, kept when it is newer than the one before. */
  function applySnapshot(device: Row, entry: Record<string, unknown>) {
    const name = str(entry.name);
    if (entry.action !== "snapshot" || !(name in PACK.schedule)) {
      counters.unknownQueries++;
      return;
    }
    const rows = rowsOf(entry.snapshot);
    if (!rows) return;
    const sent = Number(entry.unixTime) * 1000;
    const at = iso(Number.isFinite(sent) && sent > 0 && sent < clock() + DAY ? sent : clock());
    const id = device.id as string;
    const pack = str(obj(entry.decorations).endpoints_pack);
    if (pack) db.prepare("UPDATE devices SET pack_version = ? WHERE id = ?").run(pack, id);
    counters.snapshots++;

    const source = SOFTWARE_SOURCES[name];
    const before = db.prepare("SELECT at FROM results WHERE device_id = ? AND query = ?").get(id, name) as { at: string } | undefined;
    // osquery may send buffered results late; an older snapshot never replaces a newer one.
    if (before && before.at > at) return;
    db.prepare(
      "INSERT INTO results (device_id, query, rows, at) VALUES (?, ?, ?, ?) ON CONFLICT (device_id, query) DO UPDATE SET rows = excluded.rows, at = excluded.at",
    ).run(id, name, source ? JSON.stringify({ count: rows.length }) : JSON.stringify(rows), at);

    if (name === INVENTORY && rows[0]) {
      const r = rows[0];
      const os = { name: r.os_name, version: r.os_version, build: r.os_build, platform: r.os_platform };
      writeFacts(id, facts(r, os, r.osquery_version ?? ""));
    }
    if (source) {
      db.prepare("DELETE FROM software WHERE device_id = ? AND source = ?").run(id, source);
      const insert = db.prepare("INSERT INTO software (device_id, source, name, version, publisher, identifier, path) VALUES (?, ?, ?, ?, ?, ?, ?)");
      for (const r of rows) {
        // macOS names applications by their bundle, Slack.app; people call it Slack.
        const title = (source === "macos" ? (r.name ?? "").replace(/\.app$/, "") : (r.name ?? "")).trim();
        if (title) insert.run(id, source, title, r.version ?? "", r.publisher ?? "", r.identifier ?? "", r.path ?? "");
      }
    }
  }

  /**
   * osquery's TLS logger: result and status logs for the device whose node key sent them. Results of the pack's
   * snapshot queries are kept; status logs are osquery's own messages and are not. An unknown key gets osquery's
   * `node_invalid`, which makes it enrol again.
   */
  function ingest(body: Record<string, unknown>) {
    const key = str(body.node_key);
    const device = key ? (db.prepare("SELECT * FROM devices WHERE node_key_hash = ?").get(sha256(key)) as Row | undefined) : undefined;
    if (!device) {
      counters.invalidNodeKeys++;
      return { node_invalid: true };
    }
    db.exec("BEGIN");
    try {
      db.prepare("UPDATE devices SET last_seen_at = ? WHERE id = ?").run(iso(), device.id as string);
      if (body.log_type === "result" && Array.isArray(body.data)) {
        for (const entry of body.data) applySnapshot(device, obj(entry));
        evaluateDevice(device.id as string);
      }
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    return { node_invalid: false };
  }

  // ---------------------------------------------------------------- checks and posture

  function resultsOf(id: string): Record<string, Rows> {
    const out: Record<string, Rows> = {};
    for (const r of db.prepare("SELECT query, rows FROM results WHERE device_id = ?").all(id) as Array<{ query: string; rows: string }>)
      if (!SOFTWARE_SOURCES[r.query]) out[r.query] = JSON.parse(r.rows) as Rows;
    return out;
  }

  /** Runs the checks on what the device last reported; a check keeps its `since` until its status changes. */
  function evaluateDevice(id: string) {
    const d = db.prepare("SELECT platform, os_name, os_version, os_build, os_platform FROM devices WHERE id = ?").get(id) as Row | undefined;
    if (!d) return;
    const results = evaluate(
      {
        platform: d.platform as Platform,
        osName: d.os_name as string,
        osVersion: d.os_version as string,
        osBuild: d.os_build as string,
        osPlatform: d.os_platform as string,
      },
      resultsOf(id),
      current,
    );
    const now = iso();
    for (const c of results) {
      const before = db.prepare("SELECT status, detail FROM checks WHERE device_id = ? AND check_id = ?").get(id, c.check) as Row | undefined;
      if (!before)
        db.prepare("INSERT INTO checks (device_id, check_id, status, detail, since) VALUES (?, ?, ?, ?, ?)").run(id, c.check, c.status, c.detail, now);
      else if (before.status !== c.status)
        db.prepare("UPDATE checks SET status = ?, detail = ?, since = ? WHERE device_id = ? AND check_id = ?").run(c.status, c.detail, now, id, c.check);
      else if (before.detail !== c.detail) db.prepare("UPDATE checks SET detail = ? WHERE device_id = ? AND check_id = ?").run(c.detail, id, c.check);
    }
  }

  const activeExceptions = (deviceId?: string) =>
    (
      db
        .prepare(`SELECT * FROM exceptions WHERE expires_at > ?${deviceId ? " AND device_id = ?" : ""} ORDER BY expires_at`)
        .all(...(deviceId ? [iso(), deviceId] : [iso()])) as Row[]
    ).map((r) => ({
      id: r.id as string,
      deviceId: r.device_id as string,
      check: r.check_id as CheckId,
      reason: r.reason as string,
      expiresAt: r.expires_at as string,
      createdBy: r.created_by as string,
      createdAt: r.created_at as string,
    }));

  function storedChecks(): Map<string, StoredCheck[]> {
    const by = new Map<string, StoredCheck[]>();
    for (const r of db.prepare("SELECT * FROM checks").all() as Row[]) {
      const list = by.get(r.device_id as string) ?? [];
      list.push({ check: r.check_id as CheckId, status: r.status as CheckStatus, detail: r.detail as string, since: r.since as string });
      by.set(r.device_id as string, list);
    }
    for (const list of by.values()) list.sort((a, b) => CHECKS.indexOf(a.check) - CHECKS.indexOf(b.check));
    return by;
  }

  const toDevice = (r: Row, checks: StoredCheck[], excepted: Set<CheckId>) => {
    const { posture, failing } = postureOf(checks, current, excepted, clock());
    return {
      id: r.id as string,
      uuid: r.uuid as string,
      name: r.name as string,
      hostname: r.hostname as string,
      serial: r.serial as string,
      hardware: { vendor: r.vendor as string, model: r.model as string, cpu: r.cpu as string, memoryBytes: (r.memory_bytes as number | null) ?? null },
      platform: r.platform as Platform,
      os: { name: r.os_name as string, version: r.os_version as string, build: r.os_build as string, platform: r.os_platform as string },
      osqueryVersion: r.osquery_version as string,
      packVersion: r.pack_version as string,
      owner: r.owner as string,
      enrolledAt: r.enrolled_at as string,
      lastSeenAt: r.last_seen_at as string,
      stale: Date.parse(r.last_seen_at as string) + current.staleDays * DAY <= clock(),
      reenrollUntil: (r.reenroll_until as string | null) && (r.reenroll_until as string) > iso() ? (r.reenroll_until as string) : null,
      posture,
      failing,
      checks: checks.map((c) => ({ check: c.check, status: c.status, detail: c.detail })),
    };
  };
  type Device = ReturnType<typeof toDevice>;

  function devices(): Device[] {
    const checks = storedChecks();
    const exceptions = new Map<string, Set<CheckId>>();
    for (const x of activeExceptions()) exceptions.set(x.deviceId, (exceptions.get(x.deviceId) ?? new Set()).add(x.check));
    return (db.prepare("SELECT * FROM devices ORDER BY name COLLATE NOCASE").all() as Row[]).map((r) =>
      toDevice(r, checks.get(r.id as string) ?? [], exceptions.get(r.id as string) ?? new Set()),
    );
  }

  function device(id: string) {
    const r = db.prepare("SELECT * FROM devices WHERE id = ?").get(id) as Row | undefined;
    if (!r) throw notFound("The device");
    const checks = storedChecks().get(id) ?? [];
    const exceptions = activeExceptions(id);
    const d = toDevice(r, checks, new Set(exceptions.map((x) => x.check)));
    const results = resultsOf(id);
    const users = USERS.flatMap((q) => results[q] ?? []).map((u) => ({ uid: u.uid ?? "", username: u.username ?? "", description: u.description ?? "" }));
    const secret = r.enroll_secret_id
      ? (db.prepare("SELECT id, name FROM enroll_secrets WHERE id = ?").get(r.enroll_secret_id as string) as { id: string; name: string } | undefined)
      : undefined;
    const software = (db.prepare("SELECT COUNT(*) AS n FROM software WHERE device_id = ?").get(id) as { n: number }).n;
    return {
      ...d,
      checks: checks.map((c): DeviceCheck => ({
        ...c,
        enabled: current.checks[c.check].enabled,
        onFailure: current.checks[c.check].onFailure,
        exception: exceptions.find((x) => x.check === c.check) ?? null,
      })),
      users,
      software,
      enrollSecret: secret ?? null,
    };
  }

  /** The person who uses the device, as an editor writes it, until Identity tells (ADR 0065). */
  function setOwner(id: string, body: Record<string, unknown>, actor: Actor) {
    const r = db.prepare("SELECT name FROM devices WHERE id = ?").get(id) as { name: string } | undefined;
    if (!r) throw notFound("The device");
    if (body.owner !== null && typeof body.owner !== "string") throw bad("owner is text, or null to clear it.");
    const owner = typeof body.owner === "string" ? body.owner.trim() : "";
    if (owner.length > 200) throw bad("owner is at most 200 characters.");
    db.prepare("UPDATE devices SET owner = ? WHERE id = ?").run(owner, id);
    record(actor.name, "device.owner", r.name, { detail: owner ? `owner set to ${owner}` : "owner cleared" });
    return device(id);
  }

  /** Forgets a device: its node key stops working. osquery on it enrols again as a new device if it still can. */
  function removeDevice(id: string, actor: Actor) {
    const r = db.prepare("SELECT name, uuid FROM devices WHERE id = ?").get(id) as { name: string; uuid: string } | undefined;
    if (!r) throw notFound("The device");
    db.prepare("DELETE FROM devices WHERE id = ?").run(id);
    record(actor.name, "device.remove", r.name, { detail: r.uuid });
  }

  /** Lets the same hardware UUID enrol once more within 7 days, as after osquery is installed again. */
  function allowReenrol(id: string, actor: Actor) {
    const r = db.prepare("SELECT name FROM devices WHERE id = ?").get(id) as { name: string } | undefined;
    if (!r) throw notFound("The device");
    db.prepare("UPDATE devices SET reenroll_until = ? WHERE id = ?").run(iso(clock() + REENROL_MS), id);
    record(actor.name, "device.reenrol-allow", r.name, { detail: "may enrol again within 7 days" });
    return device(id);
  }

  // ---------------------------------------------------------------- software

  /** Every application by name across devices, with its versions, the newest first. */
  function software(filter: { q?: string | null; platform?: string | null } = {}) {
    const where: string[] = [];
    const args: SQLInputValue[] = [];
    if (filter.q)
      (where.push("(s.name LIKE ? ESCAPE '\\' OR s.publisher LIKE ? ESCAPE '\\')"), args.push(...Array(2).fill(`%${filter.q.replace(/[%_\\]/g, "\\$&")}%`)));
    if (filter.platform) {
      if (!["darwin", "windows", "linux"].includes(filter.platform)) throw bad("platform is darwin, windows or linux.");
      where.push("d.platform = ?");
      args.push(filter.platform);
    }
    const w = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const rows = db
      .prepare(
        `SELECT s.name, s.version, COUNT(DISTINCT s.device_id) AS n, MAX(s.publisher) AS publisher, GROUP_CONCAT(DISTINCT d.platform) AS platforms
         FROM software s JOIN devices d ON d.id = s.device_id ${w} GROUP BY s.name, s.version`,
      )
      .all(...args) as Row[];
    const totals = new Map(
      (
        db
          .prepare(`SELECT s.name, COUNT(DISTINCT s.device_id) AS n FROM software s JOIN devices d ON d.id = s.device_id ${w} GROUP BY s.name`)
          .all(...args) as Row[]
      ).map((r) => [r.name as string, Number(r.n)]),
    );
    const titles = new Map<string, { name: string; publisher: string; platforms: Set<string>; versions: Array<{ version: string; devices: number }> }>();
    for (const r of rows) {
      const t = titles.get(r.name as string) ?? { name: r.name as string, publisher: "", platforms: new Set<string>(), versions: [] };
      if (!t.publisher && r.publisher) t.publisher = r.publisher as string;
      for (const p of String(r.platforms ?? "").split(",")) if (p) t.platforms.add(p);
      t.versions.push({ version: r.version as string, devices: Number(r.n) });
      titles.set(t.name, t);
    }
    const list = [...titles.values()].map((t) => {
      const versions = t.versions.sort((a, b) => compareVersions(b.version, a.version));
      const devices = totals.get(t.name) ?? 0;
      const newest = versions[0]?.version ?? "";
      return {
        name: t.name,
        publisher: t.publisher,
        platforms: [...t.platforms].sort(),
        devices,
        newest,
        // Devices on an older version than the newest any device has: a sign, not an advisory.
        notOnNewest: Math.max(0, devices - (versions[0]?.devices ?? 0)),
        versions,
      };
    });
    list.sort((a, b) => b.devices - a.devices || a.name.localeCompare(b.name));
    return { total: list.length, titles: list.slice(0, 1000) };
  }

  /** Where one application is installed, and which version. */
  function installs(name: string) {
    if (!name) throw bad("name is required.");
    return (
      db
        .prepare(
          "SELECT d.id, d.name AS device, d.owner, d.platform, s.version, s.path FROM software s JOIN devices d ON d.id = s.device_id WHERE s.name = ? ORDER BY d.name COLLATE NOCASE",
        )
        .all(name) as Row[]
    ).map((r) => ({
      device: { id: r.id as string, name: r.device as string, owner: r.owner as string, platform: r.platform as Platform },
      version: r.version as string,
      path: r.path as string,
    }));
  }

  function deviceSoftware(id: string) {
    if (!db.prepare("SELECT 1 FROM devices WHERE id = ?").get(id)) throw notFound("The device");
    return (
      db.prepare("SELECT source, name, version, publisher, identifier, path FROM software WHERE device_id = ? ORDER BY name COLLATE NOCASE").all(id) as Row[]
    ).map((r) => ({
      source: r.source as string,
      name: r.name as string,
      version: r.version as string,
      publisher: r.publisher as string,
      identifier: r.identifier as string,
      path: r.path as string,
    }));
  }

  // ---------------------------------------------------------------- compliance

  function checkStats(list: Device[]) {
    return CHECKS.map((check) => {
      const n = { passing: 0, failing: 0, excepted: 0, unknown: 0, notApplicable: 0 };
      for (const d of list) {
        const c = d.checks.find((x) => x.check === check);
        if (!c || c.status === "unknown") n.unknown++;
        else if (c.status === "not-applicable") n.notApplicable++;
        else if (c.status === "pass") n.passing++;
        else if (d.failing.some((f) => f.check === check)) n.failing++;
        else n.excepted++;
      }
      return { check, ...current.checks[check], ...n };
    });
  }

  const POSTURES: Posture[] = ["compliant", "at-risk", "non-compliant", "pending"];
  const countPostures = (list: Device[]) => Object.fromEntries(POSTURES.map((p) => [p, list.filter((d) => d.posture === p).length])) as Record<Posture, number>;

  function compliance() {
    const list = devices();
    const failing: Array<Failing & { device: { id: string; name: string; owner: string; platform: Platform; os: string } }> = [];
    for (const d of list)
      for (const f of d.failing)
        failing.push({ ...f, device: { id: d.id, name: d.name, owner: d.owner, platform: d.platform, os: `${d.os.name} ${d.os.version}`.trim() } });
    failing.sort((a, b) => Number(b.blocked) - Number(a.blocked) || a.since.localeCompare(b.since));
    const platforms = (["darwin", "windows", "linux"] as const).map((platform) => ({
      platform,
      ...countPostures(list.filter((d) => d.platform === platform)),
    }));
    return { checks: checkStats(list), platforms, failing };
  }

  // ---------------------------------------------------------------- exceptions

  const exceptions = () =>
    (
      db
        .prepare("SELECT x.*, d.name AS device FROM exceptions x JOIN devices d ON d.id = x.device_id ORDER BY x.expires_at <= ?, x.expires_at")
        .all(iso()) as Row[]
    ).map((r) => ({
      id: r.id as string,
      device: { id: r.device_id as string, name: r.device as string },
      check: r.check_id as CheckId,
      reason: r.reason as string,
      expiresAt: r.expires_at as string,
      active: (r.expires_at as string) > iso(),
      createdBy: r.created_by as string,
      createdAt: r.created_at as string,
    }));

  /** A failing check on one device counts as passing, for a reason, until a date within a year. */
  function createException(body: Record<string, unknown>, actor: Actor) {
    const deviceId = text(body.deviceId, "deviceId", 64);
    const d = db.prepare("SELECT name FROM devices WHERE id = ?").get(deviceId) as { name: string } | undefined;
    if (!d) throw notFound("The device");
    if (typeof body.check !== "string" || !(CHECKS as readonly string[]).includes(body.check)) throw bad(`check is one of ${CHECKS.join(", ")}.`);
    const reason = text(body.reason, "reason", 500);
    const days = whole(body.days, "days", 1, 365);
    if (activeExceptions(deviceId).some((x) => x.check === body.check)) throw conflict(`${d.name} has an exception for ${body.check} already.`);
    const id = randomUUID();
    db.prepare("INSERT INTO exceptions (id, device_id, check_id, reason, expires_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
      id,
      deviceId,
      body.check,
      reason,
      iso(clock() + days * DAY),
      actor.name,
      iso(),
    );
    record(actor.name, "exception.create", `${d.name} ${body.check}`, { detail: `${days} days: ${reason}` });
    return exceptions().find((x) => x.id === id)!;
  }

  function deleteException(id: string, actor: Actor) {
    const r = db.prepare("SELECT x.check_id, d.name FROM exceptions x JOIN devices d ON d.id = x.device_id WHERE x.id = ?").get(id) as Row | undefined;
    if (!r) throw notFound("The exception");
    db.prepare("DELETE FROM exceptions WHERE id = ?").run(id);
    record(actor.name, "exception.delete", `${r.name as string} ${r.check_id as string}`);
  }

  // ---------------------------------------------------------------- audit

  const toEvent = (r: Row): AuditEvent => ({
    id: Number(r.id),
    at: r.at as string,
    actor: r.actor as string,
    action: r.action as string,
    target: r.target as string,
    result: r.result as "success" | "denied",
    detail: r.detail as string,
  });

  /** Newest first, a page at a time: `next` is the cursor for the page after. */
  function events(filter: { kind?: string | null; cursor?: string | null } = {}, limit = 100) {
    if (filter.kind && !(AUDIT_KINDS as readonly string[]).includes(filter.kind)) throw bad(`kind is one of ${AUDIT_KINDS.join(", ")}.`);
    let before = Number.MAX_SAFE_INTEGER;
    if (filter.cursor) {
      before = Number(Buffer.from(filter.cursor, "base64url").toString("utf8"));
      if (!Number.isSafeInteger(before)) throw bad("cursor is not one this API gave.");
    }
    const where = ["id < ?"];
    const args: SQLInputValue[] = [before];
    if (filter.kind) (where.push("action LIKE ?"), args.push(`${filter.kind}.%`));
    const rows = (db.prepare(`SELECT * FROM audit WHERE ${where.join(" AND ")} ORDER BY id DESC LIMIT ?`).all(...args, limit + 1) as Row[]).map(toEvent);
    const page = rows.slice(0, limit);
    return { events: page, next: rows.length > limit ? Buffer.from(String(page.at(-1)!.id)).toString("base64url") : null };
  }

  // ---------------------------------------------------------------- setup, overview and metrics

  function setup() {
    const url = new URL(publicUrl);
    const platforms = Object.fromEntries(
      (["darwin", "linux", "windows"] as SetupPlatform[]).map((p) => [p, { flags: flagsFile(p, publicUrl), steps: installSteps(p) }]),
    ) as Record<SetupPlatform, { flags: string; steps: string }>;
    return { publicUrl, tlsHostname: url.host, https: url.protocol === "https:", packVersion: PACK_VERSION, pack: PACK_TEXT, platforms };
  }

  function summary() {
    const list = devices();
    const active = secrets().filter((s) => s.status === "active").length;
    return {
      devices: list.length,
      postures: countPostures(list),
      stale: list.filter((d) => d.stale).length,
      checks: checkStats(list),
      enrollSecrets: active,
      packVersion: PACK_VERSION,
      outdatedPack: list.filter((d) => d.packVersion && d.packVersion !== PACK_VERSION).length,
    };
  }

  function gauges() {
    const list = devices();
    return { postures: countPostures(list), stale: list.filter((d) => d.stale).length, ...counters };
  }

  return {
    record,
    recordAuth,
    policy,
    savePolicy,
    secrets,
    createSecret,
    revokeSecret,
    enroll,
    ingest,
    devices,
    device,
    setOwner,
    removeDevice,
    allowReenrol,
    deviceSoftware,
    software,
    installs,
    compliance,
    exceptions,
    createException,
    deleteException,
    events,
    setup,
    summary,
    gauges,
  };
}

export type Endpoints = ReturnType<typeof createEndpoints>;
