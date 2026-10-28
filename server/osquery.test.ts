import { gzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fixture, hostDetails, startApp } from "./test-app.ts";

// osquery's own protocol (its TLS enroll and logger plugins), as osqueryd 5.24 speaks it: checked against a real
// osqueryd in e2e/run.sh. Every answer has osquery's shape; node_invalid makes it enrol again.

let app: Awaited<ReturnType<typeof startApp>>;
beforeEach(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterEach(() => app.close());

const DAY = 86_400_000;
const enrolBody = (secret: string, name: "macos" | "debian" | "windows" = "macos") => {
  const details = hostDetails(fixture(name));
  return { enroll_secret: secret, host_identifier: details.system_info.uuid, platform_type: "21", host_details: details };
};
const audit = async () => ((await app.get("/api/v1/audit?kind=device")).events as Array<{ action: string; result: string; detail: string }>).reverse();

describe("enrolment", () => {
  it("gives a node key for a secret Endpoints made, and creates the device from host_details", async () => {
    const secret = await app.newSecret();
    const { status, body } = await app.osquery("enroll", enrolBody(secret));
    expect(status).toBe(200);
    expect(body.node_invalid).toBe(false);
    expect(body.node_key).toMatch(/^oen_[\w-]{43}$/);
    const [d] = (await app.get("/api/v1/devices")).devices;
    expect(d).toMatchObject({
      name: "MBP-DKIM-14",
      serial: "C02FAKE0SN1",
      platform: "darwin",
      os: { name: "macOS", version: "26.6.2" },
      osqueryVersion: "5.24.0",
    });
    expect(d.posture).toBe("pending");
    const secrets = (await app.get("/api/v1/enroll-secrets")).secrets;
    expect(secrets[0]).toMatchObject({ name: "Laptops", devices: 1, status: "active" });
    expect(JSON.stringify(secrets)).not.toContain(secret);
    expect(JSON.stringify(app.db.prepare("SELECT * FROM devices").all())).not.toContain(body.node_key);
  });

  it("refuses unknown, revoked and expired secrets, and records each refusal once an hour", async () => {
    expect((await app.osquery("enroll", enrolBody("oee_guess"))).body).toEqual({ node_invalid: true });
    expect((await app.osquery("enroll", enrolBody("oee_guess"))).body).toEqual({ node_invalid: true });
    const secret = await app.newSecret();
    const id = (await app.get("/api/v1/enroll-secrets")).secrets[0].id;
    await app.send("POST", `/api/v1/enroll-secrets/${id}/revoke`);
    expect((await app.osquery("enroll", enrolBody(secret))).body.node_invalid).toBe(true);
    const later = await app.newSecret("Short");
    app.later(91 * DAY);
    expect((await app.osquery("enroll", enrolBody(later))).body.node_invalid).toBe(true);
    expect((await app.get("/api/v1/devices")).devices).toEqual([]);
    expect((await audit()).map((e) => `${e.result}: ${e.detail}`)).toEqual([
      "denied: unknown enrolment secret",
      "denied: enrolment secret Laptops is revoked",
      "denied: enrolment secret Short has expired",
    ]);
    expect(await (await fetch(`${app.base}/metrics`)).text()).toContain("openasy_endpoints_enrolments_refused_total 4");
  });

  it("does not let a second enrolment take over a device, until an admin allows it once", async () => {
    const secret = await app.newSecret();
    const first = (await app.osquery("enroll", enrolBody(secret))).body.node_key!;
    expect((await app.osquery("enroll", enrolBody(secret))).body).toEqual({ node_invalid: true });
    const [d] = (await app.get("/api/v1/devices")).devices;
    expect((await app.send("POST", `/api/v1/devices/${d.id}/reenroll`)).status).toBe(200);
    const second = (await app.osquery("enroll", enrolBody(secret))).body.node_key!;
    expect(second).not.toBe(first);
    expect((await app.osquery("log", { node_key: first, log_type: "result", data: [] })).body).toEqual({ node_invalid: true });
    expect((await app.osquery("enroll", enrolBody(secret))).body.node_invalid).toBe(true);
    expect((await app.get("/api/v1/devices")).devices).toHaveLength(1);
  });

  it("needs a hardware UUID, as --host_identifier=uuid gives", async () => {
    const secret = await app.newSecret();
    const body = { enroll_secret: secret, host_identifier: "my-laptop", host_details: {} };
    expect((await app.osquery("enroll", body)).body.node_invalid).toBe(true);
    expect((await audit()).at(-1)!.detail).toMatch(/--host_identifier=uuid/);
  });
});

describe("results", () => {
  it("keeps the pack's snapshots, gzipped as osquery sends them, and checks the device", async () => {
    const { id } = await app.enrolDevice("macos", await app.newSecret());
    const d = await app.get(`/api/v1/devices/${id}`);
    expect(d.posture).toBe("at-risk");
    expect(d.failing).toEqual([expect.objectContaining({ check: "firewall", detail: "The firewall is off.", blocked: false })]);
    expect(d.packVersion).toBe("1");
    expect(d.users).toEqual([{ uid: "501", username: "dkim", description: "Deniz Kim" }]);
    expect(d.software).toBe(8);
    const software = (await app.get(`/api/v1/devices/${id}/software`)).software as Array<{ name: string; version: string }>;
    expect(software.map((s) => s.name)).toContain("Google Chrome");
    expect(software.find((s) => s.name === "zoom.us")!.version).toBe("7.0.6 (84834)");
  });

  it("tells osquery to enrol again when it does not know the node key", async () => {
    expect((await app.osquery("log", { node_key: "oen_nope", log_type: "result", data: [] })).body).toEqual({ node_invalid: true });
    expect((await app.osquery("log", { log_type: "status", data: [] })).body).toEqual({ node_invalid: true });
    expect(await (await fetch(`${app.base}/metrics`)).text()).toContain("openasy_endpoints_invalid_node_keys_total 2");
  });

  it("never lets an older snapshot replace a newer one, and drops results of queries not in the pack", async () => {
    const { id, nodeKey, snapshots } = await app.enrolDevice("macos", await app.newSecret());
    const firewall = snapshots.find((s) => s.name === "endpoints_firewall_macos")!;
    const at = Math.floor(app.now() / 1000);
    const send = (global_state: string, unixTime: number) =>
      app.osquery("log", { node_key: nodeKey, log_type: "result", data: [{ ...firewall, snapshot: [{ global_state }], unixTime }] });
    await send("1", at - 3600);
    expect((await app.get(`/api/v1/devices/${id}`)).posture).toBe("at-risk");
    await send("1", at + 60);
    expect((await app.get(`/api/v1/devices/${id}`)).posture).toBe("compliant");
    await app.osquery("log", {
      node_key: nodeKey,
      log_type: "result",
      data: [
        { name: "pack_custom_shadow", action: "snapshot", snapshot: [{ secret: "x" }] },
        { ...firewall, action: "added" },
      ],
    });
    expect(app.db.prepare("SELECT COUNT(*) AS n FROM results WHERE query NOT LIKE 'endpoints_%'").get()).toEqual({ n: 0 });
    expect(await (await fetch(`${app.base}/metrics`)).text()).toContain("openasy_endpoints_unknown_queries_total 2");
  });

  it("replaces a device's software of one source with each snapshot, and keeps the others", async () => {
    const { id, nodeKey, snapshots } = await app.enrolDevice("debian", await app.newSecret());
    const deb = snapshots.find((s) => s.name === "endpoints_software_deb")!;
    const rpm = snapshots.find((s) => s.name === "endpoints_software_rpm")!;
    const at = Math.floor(app.now() / 1000) + 60;
    await app.osquery("log", {
      node_key: nodeKey,
      log_type: "result",
      data: [
        { ...deb, snapshot: [{ name: "bash", version: "5.2.37-2+b11", publisher: "Matthias Klose" }], unixTime: at },
        { ...rpm, snapshot: [{ name: "zsh", version: "5.9-1", publisher: "Fedora" }], unixTime: at },
      ],
    });
    expect((await app.get(`/api/v1/devices/${id}/software`)).software.map((s: { name: string }) => s.name)).toEqual(["bash", "zsh"]);
  });

  it("refuses a body that unpacks past the limit", async () => {
    const { nodeKey } = await app.enrolDevice("macos", await app.newSecret());
    const huge = gzipSync(JSON.stringify({ node_key: nodeKey, log_type: "result", data: [{ x: "a".repeat(17 * 1024 * 1024) }] }));
    expect(huge.length).toBeLessThan(100 * 1024);
    const res = await fetch(`${app.base}/api/v1/osquery/log`, { method: "POST", headers: { "content-encoding": "gzip" }, body: huge });
    expect(res.status).toBe(413);
    expect((await fetch(`${app.base}/api/v1/osquery/log`, { method: "POST", headers: { "content-encoding": "br" }, body: "{}" })).status).toBe(400);
  });

  it("cuts long values and keeps at most 20,000 rows of a snapshot", async () => {
    const { id, nodeKey, snapshots } = await app.enrolDevice("debian", await app.newSecret());
    const deb = snapshots.find((s) => s.name === "endpoints_software_deb")!;
    const rows = Array.from({ length: 20_500 }, (_, i) => ({ name: `pkg-${i}`, version: "1.0", publisher: i ? "Debian" : "x".repeat(5000) }));
    await app.osquery("log", { node_key: nodeKey, log_type: "result", data: [{ ...deb, snapshot: rows, unixTime: Math.floor(app.now() / 1000) + 60 }] }, true);
    expect((await app.get(`/api/v1/devices/${id}`)).software).toBe(20_000);
    expect(app.db.prepare("SELECT MAX(LENGTH(publisher)) AS n FROM software").get()).toEqual({ n: 1024 });
  });
});
