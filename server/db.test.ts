import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "endpoints-")), "nested", "endpoints.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();
    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: 1 });
    second.close();
  });

  it("keeps the audit log append-only and one policy", () => {
    const db = openDb(":memory:");
    db.prepare("INSERT INTO audit (at, actor, action, target, result) VALUES ('now', 'a', 'policy.update', 'policy', 'success')").run();
    expect(() => db.prepare("UPDATE audit SET actor = 'b'").run()).toThrow(/append-only/);
    expect(() => db.prepare("DELETE FROM audit").run()).toThrow(/append-only/);
    expect(() => db.prepare("INSERT INTO policy (id, body, updated_at, updated_by) VALUES (2, '{}', 'now', 'a')").run()).toThrow(/CHECK/);
  });

  it("removes what a device reported with the device", () => {
    const db = openDb(":memory:");
    db.prepare("INSERT INTO devices (id, uuid, name, platform, enrolled_at, last_seen_at, created_at) VALUES ('d', 'U', 'n', 'darwin', 'a', 'a', 'a')").run();
    db.prepare("INSERT INTO results (device_id, query, rows, at) VALUES ('d', 'q', '[]', 'a')").run();
    db.prepare("INSERT INTO software (device_id, source, name, version) VALUES ('d', 'macos', 'Slack', '1')").run();
    db.prepare("DELETE FROM devices WHERE id = 'd'").run();
    expect(db.prepare("SELECT (SELECT COUNT(*) FROM results) + (SELECT COUNT(*) FROM software) AS n").get()).toEqual({ n: 0 });
  });
});
