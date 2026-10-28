import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `-- What a compliant device is (ADR 0065). One row, the policy as JSON; it is read whole and validated on the way in.
   CREATE TABLE policy (
     id INTEGER PRIMARY KEY CHECK (id = 1),
     body TEXT NOT NULL,
     updated_at TEXT NOT NULL,
     updated_by TEXT NOT NULL
   );
   -- Secrets osquery enrols with. Only a hash is kept; the secret is shown once. A device enrolled with one keeps its own
   -- node key when the secret is revoked or expires.
   CREATE TABLE enroll_secrets (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     secret_hash TEXT NOT NULL UNIQUE,
     fingerprint TEXT NOT NULL,
     created_at TEXT NOT NULL,
     created_by TEXT NOT NULL,
     expires_at TEXT,
     revoked_at TEXT,
     last_used_at TEXT
   );
   -- A laptop or workstation, found again by its hardware UUID. node_key_hash is the hash of the key osquery got when it
   -- enrolled; reenroll_until lets the same UUID enrol again once, when an admin allowed it.
   CREATE TABLE devices (
     id TEXT PRIMARY KEY,
     uuid TEXT NOT NULL UNIQUE,
     node_key_hash TEXT UNIQUE,
     reenroll_until TEXT,
     enroll_secret_id TEXT REFERENCES enroll_secrets (id) ON DELETE SET NULL,
     name TEXT NOT NULL,
     hostname TEXT NOT NULL DEFAULT '',
     serial TEXT NOT NULL DEFAULT '',
     vendor TEXT NOT NULL DEFAULT '',
     model TEXT NOT NULL DEFAULT '',
     cpu TEXT NOT NULL DEFAULT '',
     memory_bytes INTEGER,
     platform TEXT NOT NULL CHECK (platform IN ('darwin', 'windows', 'linux', 'other')),
     os_name TEXT NOT NULL DEFAULT '',
     os_version TEXT NOT NULL DEFAULT '',
     os_build TEXT NOT NULL DEFAULT '',
     os_platform TEXT NOT NULL DEFAULT '',
     osquery_version TEXT NOT NULL DEFAULT '',
     pack_version TEXT NOT NULL DEFAULT '',
     owner TEXT NOT NULL DEFAULT '',
     enrolled_at TEXT NOT NULL,
     last_seen_at TEXT NOT NULL,
     created_at TEXT NOT NULL
   );
   CREATE INDEX devices_seen ON devices (last_seen_at);
   -- The last snapshot of each query of the pack, as osquery sent it, so a policy change is applied to what devices
   -- already reported. Software is kept in its own table instead.
   CREATE TABLE results (
     device_id TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
     query TEXT NOT NULL,
     rows TEXT NOT NULL,
     at TEXT NOT NULL,
     PRIMARY KEY (device_id, query)
   );
   -- Each posture check on each device, and since when it has had its status: a failing check's grace period starts there.
   CREATE TABLE checks (
     device_id TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
     check_id TEXT NOT NULL,
     status TEXT NOT NULL CHECK (status IN ('pass', 'fail', 'unknown', 'not-applicable')),
     detail TEXT NOT NULL,
     since TEXT NOT NULL,
     PRIMARY KEY (device_id, check_id)
   );
   -- Installed software, replaced whole for a device and source (macos, windows, deb, rpm) by each snapshot.
   CREATE TABLE software (
     device_id TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
     source TEXT NOT NULL,
     name TEXT NOT NULL,
     version TEXT NOT NULL,
     publisher TEXT NOT NULL DEFAULT '',
     identifier TEXT NOT NULL DEFAULT '',
     path TEXT NOT NULL DEFAULT ''
   );
   CREATE INDEX software_device ON software (device_id, source);
   CREATE INDEX software_name ON software (name, version);
   -- An approved deviation: a failing check on one device counts as passing until the exception ends.
   CREATE TABLE exceptions (
     id TEXT PRIMARY KEY,
     device_id TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
     check_id TEXT NOT NULL,
     reason TEXT NOT NULL,
     expires_at TEXT NOT NULL,
     created_by TEXT NOT NULL,
     created_at TEXT NOT NULL
   );
   CREATE INDEX exceptions_device ON exceptions (device_id, check_id);
   -- Every enrolment, change and sign-in (ADR 0013). Rows are added, never changed or removed.
   CREATE TABLE audit (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     at TEXT NOT NULL,
     actor TEXT NOT NULL,
     action TEXT NOT NULL,
     target TEXT NOT NULL,
     result TEXT NOT NULL CHECK (result IN ('success', 'denied')),
     detail TEXT NOT NULL DEFAULT ''
   );
   CREATE INDEX audit_action ON audit (action);
   CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
   CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
