import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { startApp } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;
beforeEach(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterEach(() => app.close());

const DAY = 86_400_000;

describe("the product", () => {
  it("names itself, and has metrics for Prometheus", async () => {
    expect(await (await fetch(`${app.base}/api/v1/version`)).json()).toEqual({ product: "endpoints", version: "0.1.0" });
    await app.enrolDevice("macos", await app.newSecret());
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="endpoints",version="0.1.0"} 1');
    expect(metrics).toContain('openasy_endpoints_devices{posture="at-risk"} 1');
    expect(metrics).toContain("openasy_endpoints_devices_stale 0");
    expect(metrics).toContain("openasy_endpoints_snapshots_total 6");
  });

  it("shows nothing but its version without signing in", async () => {
    for (const path of ["/api/v1/summary", "/api/v1/devices", "/api/v1/software", "/api/v1/compliance", "/api/v1/policy", "/api/v1/setup", "/api/v1/audit"])
      expect((await fetch(app.base + path)).status, path).toBe(401);
  });

  it("sends security headers", async () => {
    const res = await fetch(`${app.base}/api/v1/version`);
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'self'");
  });

  it("falls back to the single-page app, and keeps API paths for the API", async () => {
    const webDir = mkdtempSync(join(tmpdir(), "endpoints-web-"));
    writeFileSync(join(webDir, "index.html"), '<!doctype html><div id="root"></div>');
    const ui = await startApp({ version: "0.1.0", webDir });
    expect(await (await fetch(`${ui.base}/devices/abc`)).text()).toContain('<div id="root">');
    expect((await fetch(`${ui.base}/api/v1/nope`)).status).toBe(404);
    await ui.close();
  });
});

describe("roles", () => {
  it("lets viewers read, editors set owners, and only admins keep the policy, exceptions, secrets and devices", async () => {
    const p = await app.people();
    const { id } = await app.enrolDevice("macos", await app.newSecret());
    expect((await p.viewer.json("/api/v1/devices")).status).toBe(200);
    expect((await p.viewer.json(`/api/v1/devices/${id}`, { method: "PUT", body: { owner: "me" } })).status).toBe(403);
    const owned = await p.editor.json(`/api/v1/devices/${id}`, { method: "PUT", body: { owner: "deniz.kim@example.com" } });
    expect(owned.body.owner).toBe("deniz.kim@example.com");
    expect((await p.editor.json("/api/v1/policy", { method: "PUT", body: { graceDays: 1 } })).status).toBe(403);
    expect((await p.editor.json("/api/v1/exceptions", { body: { deviceId: id, check: "firewall", reason: "x", days: 1 } })).status).toBe(403);
    expect((await p.editor.json("/api/v1/enroll-secrets", { body: { name: "Mine" } })).status).toBe(403);
    expect((await p.editor.json(`/api/v1/devices/${id}`, { method: "DELETE" })).status).toBe(403);
    expect((await p.owner.json("/api/v1/policy", { method: "PUT", body: { graceDays: 1 } })).status).toBe(200);
    const events = (await app.get("/api/v1/audit")).events as Array<{ actor: string; action: string }>;
    expect(events.find((e) => e.action === "device.owner")!.actor).toBe("Ece Editor <ece@example.com>");
    expect(events.find((e) => e.action === "policy.update")!.actor).toBe("Olivia Owner <owner@example.com>");
    expect(events.some((e) => e.action === "auth.sign-in")).toBe(true);
  });
});

describe("compliance", () => {
  it("applies a new policy to what devices already reported, with the grace period starting then", async () => {
    const { id } = await app.enrolDevice("macos", await app.newSecret());
    expect((await app.get(`/api/v1/devices/${id}`)).posture).toBe("at-risk");
    app.later(DAY);
    const policy = await (await app.send("PUT", "/api/v1/policy", { minimum: { macos: "27.0" }, checks: { firewall: { enabled: false } } })).json();
    expect(policy).toMatchObject({ minimum: { macos: "27.0" }, updatedBy: "admin token" });
    const d = await app.get(`/api/v1/devices/${id}`);
    expect(d.failing).toEqual([
      {
        check: "os-version",
        detail: "macOS 26.6.2 is older than 27.0.",
        since: new Date(app.now()).toISOString(),
        graceEndsAt: new Date(app.now() + 7 * DAY).toISOString(),
        blocked: false,
      },
    ]);
    app.later(7 * DAY);
    expect((await app.get(`/api/v1/devices/${id}`)).posture).toBe("non-compliant");
    const c = await app.get("/api/v1/compliance");
    expect(c.failing).toHaveLength(1);
    expect(c.checks.find((x: { check: string }) => x.check === "firewall")).toMatchObject({ enabled: false });
    expect(c.platforms[0]).toEqual({ platform: "darwin", compliant: 0, "at-risk": 0, "non-compliant": 1, pending: 0 });
    expect((await app.send("PUT", "/api/v1/policy", { graceDays: 99 })).status).toBe(422);
  });

  it("counts an exception as passing until it ends, and lets one check have one exception at a time", async () => {
    const { id } = await app.enrolDevice("macos", await app.newSecret());
    const body = { deviceId: id, check: "firewall", reason: "Lab machine on an isolated network", days: 30 };
    const x = (await (await app.send("POST", "/api/v1/exceptions", body)).json()) as { id: string };
    expect(x).toMatchObject({ device: { id }, check: "firewall", active: true, createdBy: "admin token" });
    expect((await app.send("POST", "/api/v1/exceptions", body)).status).toBe(409);
    expect((await app.get(`/api/v1/devices/${id}`)).posture).toBe("compliant");
    expect((await app.get("/api/v1/summary")).checks.find((c: { check: string }) => c.check === "firewall")).toMatchObject({ excepted: 1, failing: 0 });
    app.later(31 * DAY);
    expect((await app.get(`/api/v1/devices/${id}`)).posture).toBe("non-compliant");
    expect((await app.get("/api/v1/exceptions")).exceptions[0].active).toBe(false);
    expect((await app.send("POST", "/api/v1/exceptions", { ...body, days: 366 })).status).toBe(422);
    expect((await app.send("DELETE", `/api/v1/exceptions/${x.id}`)).status).toBe(204);
  });

  it("marks a device stale when it stops checking in, and keeps what it last reported", async () => {
    const { id } = await app.enrolDevice("windows", await app.newSecret());
    app.later(8 * DAY);
    const d = await app.get(`/api/v1/devices/${id}`);
    expect(d).toMatchObject({ stale: true, checks: expect.arrayContaining([expect.objectContaining({ check: "disk-encryption", status: "pass" })]) });
    expect((await app.get("/api/v1/summary")).stale).toBe(1);
  });
});

describe("software", () => {
  it("adds up each application across devices, with the newest version any device has", async () => {
    const secret = await app.newSecret();
    await app.enrolDevice("macos", secret);
    await app.enrolDevice("windows", secret);
    const { titles, total } = await app.get("/api/v1/software");
    expect(total).toBe(9);
    const slack = titles.find((t: { name: string }) => t.name === "Slack");
    expect(slack).toEqual({
      name: "Slack",
      publisher: "Slack Technologies Inc.",
      platforms: ["darwin", "windows"],
      devices: 2,
      newest: "4.52.182",
      notOnNewest: 1,
      versions: [
        { version: "4.52.182", devices: 1 },
        { version: "4.47.69", devices: 1 },
      ],
    });
    expect((await app.get("/api/v1/software?q=chro")).titles.map((t: { name: string }) => t.name)).toEqual(["Google Chrome"]);
    expect((await app.get("/api/v1/software?platform=windows")).total).toBe(3);
    const installs = (await app.get("/api/v1/software/installs?name=Slack")).installs;
    expect(installs.map((i: { device: { name: string }; version: string }) => `${i.device.name} ${i.version}`)).toEqual([
      "MBP-DKIM-14 4.52.182",
      "WIN-MWILSON-01 4.47.69",
    ]);
  });

  it("forgets a removed device and everything it reported", async () => {
    const { id } = await app.enrolDevice("macos", await app.newSecret());
    expect((await app.send("DELETE", `/api/v1/devices/${id}`)).status).toBe(204);
    expect((await app.get("/api/v1/software")).total).toBe(0);
    for (const t of ["results", "checks", "software"]) expect(app.db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get(), t).toEqual({ n: 0 });
  });
});

describe("setup", () => {
  it("gives the flags, the steps and the pack for each platform, and never a secret", async () => {
    await app.newSecret();
    const s = await app.get("/api/v1/setup");
    expect(s).toMatchObject({ tlsHostname: "endpoints.example.com", https: true, packVersion: "1" });
    expect(JSON.parse(s.pack).schedule.endpoints_inventory).toBeDefined();
    expect(Object.keys(s.platforms)).toEqual(["darwin", "linux", "windows"]);
    expect(JSON.stringify(s)).not.toMatch(/oee_/);
  });

  it("shows an enrolment secret once, with a fingerprint and an expiry after that", async () => {
    const created = (await (await app.send("POST", "/api/v1/enroll-secrets", { name: "Q4 laptops", expiresInDays: 30 })).json()) as {
      secret: string;
      fingerprint: string;
    };
    expect(created.secret).toMatch(/^oee_/);
    expect(created).toMatchObject({ name: "Q4 laptops", status: "active", expiresAt: new Date(app.now() + 30 * DAY).toISOString() });
    expect(created.fingerprint).toMatch(/^SHA256:[0-9a-f]{16}$/);
    expect((await app.send("POST", "/api/v1/enroll-secrets", { name: "Q4 laptops" })).status).toBe(409);
    expect((await app.send("POST", "/api/v1/enroll-secrets", { name: "Forever", expiresInDays: 400 })).status).toBe(422);
    expect((await app.get("/api/v1/enroll-secrets")).secrets[0].secret).toBeUndefined();
  });
});
