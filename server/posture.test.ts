import { describe, expect, it } from "vitest";
import { compareVersions, DEFAULT_POLICY, evaluate, parsePolicy, platformOf, postureOf, type DeviceFacts, type Rows, type StoredCheck } from "./posture.ts";
import { fixture, type Snapshot } from "./test-app.ts";

/** A fixture's snapshots by query name, and the device facts its inventory gives, as Endpoints keeps them. */
function device(snapshots: Snapshot[]): { facts: DeviceFacts; results: Record<string, Rows> } {
  const results = Object.fromEntries(snapshots.map((s) => [s.name, s.snapshot]));
  const r = results.endpoints_inventory![0]!;
  return {
    facts: { platform: platformOf(r.os_platform!), osName: r.os_name!, osVersion: r.os_version!, osBuild: r.os_build!, osPlatform: r.os_platform! },
    results,
  };
}
const statuses = (d: ReturnType<typeof device>, policy = DEFAULT_POLICY) =>
  Object.fromEntries(evaluate(d.facts, d.results, policy).map((c) => [c.check, `${c.status}: ${c.detail}`]));

describe("versions", () => {
  it("compares part by part, numbers as numbers", () => {
    expect(compareVersions("15.10", "15.9")).toBe(1);
    expect(compareVersions("22.04", "22.4")).toBe(0);
    expect(compareVersions("26.6.2", "15.0")).toBe(1);
    expect(compareVersions("14.6", "15.0")).toBe(-1);
    expect(compareVersions("15", "15.0.0")).toBe(0);
    expect(compareVersions("1:2.41.5-0+deb13u1", "1:2.41.5-0+deb13u2")).toBe(-1);
    expect(compareVersions("156.0.8078.48", "156.0.8078.47")).toBe(1);
  });

  it("knows the platforms osquery reports", () => {
    expect(platformOf("darwin")).toBe("darwin");
    expect(platformOf("windows")).toBe("windows");
    expect(platformOf("ubuntu")).toBe("linux");
    expect(platformOf("debian")).toBe("linux");
    expect(platformOf("freebsd")).toBe("other");
    expect(platformOf("")).toBe("other");
  });
});

describe("the checks, on what osquery 5.24 sent", () => {
  it("reads a Mac: FileVault on, firewall off, a password at once after sleep", () => {
    expect(statuses(device(fixture("macos")))).toEqual({
      "disk-encryption": "pass: FileVault is on.",
      "os-version": "pass: macOS 26.6.2.",
      firewall: "fail: The firewall is off.",
      "screen-lock": "pass: A password is asked at once after sleep or the screen saver.",
    });
  });

  it("reads Debian: / not on an encrypted disk, and leaves out what core osquery cannot read", () => {
    expect(statuses(device(fixture("debian")))).toEqual({
      "disk-encryption": "fail: The disk that holds / is not encrypted.",
      "os-version": "pass: Debian GNU/Linux 13.",
      firewall: "not-applicable: Not checked on Linux: core osquery cannot read ufw or nftables.",
      "screen-lock": "not-applicable: Not checked on Linux: core osquery cannot read the desktop's settings.",
    });
  });

  // Written from osquery's table schema, not captured: there is no Windows device in CI.
  it("reads Windows: BitLocker, Security Center's firewall, and the machine inactivity limit against the policy", () => {
    const d = device(fixture("windows"));
    expect(statuses(d)).toEqual({
      "disk-encryption": "pass: BitLocker protects C:.",
      "os-version": "pass: Build 22631.",
      firewall: "pass: Security Center reports the firewall on.",
      "screen-lock": "fail: Windows locks only after 15 min idle.",
    });
    expect(statuses(d, { ...DEFAULT_POLICY, screenLockMinutes: 15 })["screen-lock"]).toBe("pass: Windows locks after 15 min idle.");
    expect(statuses(d, { ...DEFAULT_POLICY, minimum: { ...DEFAULT_POLICY.minimum, windowsBuild: 26100 } })["os-version"]).toBe(
      "fail: Build 22631 is older than 26100.",
    );
  });

  it("fails what osquery found off, and waits for what it has not answered", () => {
    const mac = device(fixture("macos"));
    mac.results.endpoints_encryption_macos = [{ path: "/System/Volumes/Data", encrypted: "0", type: "", filevault_status: "off" }];
    mac.results.endpoints_screenlock_macos = [{ enabled: "1", grace_period: "3600" }];
    delete mac.results.endpoints_firewall_macos;
    mac.facts.osVersion = "14.6";
    expect(statuses(mac)).toEqual({
      "disk-encryption": "fail: FileVault is off.",
      "os-version": "fail: macOS 14.6 is older than 15.0.",
      firewall: "unknown: osquery has not answered this query yet.",
      "screen-lock": "fail: The password is asked only 60 min after sleep or the screen saver.",
    });
    const win = device(fixture("windows"));
    win.results.endpoints_encryption_windows = [];
    win.results.endpoints_screenlock_windows = [];
    expect(statuses(win)["disk-encryption"]).toBe("fail: BitLocker reports nothing for C:.");
    expect(statuses(win)["screen-lock"]).toBe("fail: No machine inactivity limit is set.");
  });

  it("checks Linux distributions the policy names, and only those", () => {
    const d = device(fixture("debian"));
    expect(statuses(d, { ...DEFAULT_POLICY, minimum: { ...DEFAULT_POLICY.minimum, linux: { debian: "14" } } })["os-version"]).toBe(
      "fail: Debian GNU/Linux 13 is older than 14.",
    );
    expect(statuses(d, { ...DEFAULT_POLICY, minimum: { ...DEFAULT_POLICY.minimum, linux: { ubuntu: "22.04" } } })["os-version"]).toBe(
      "not-applicable: The policy sets no minimum for Debian GNU/Linux.",
    );
    const ubuntu: DeviceFacts = { platform: "linux", osName: "Ubuntu", osVersion: "24.04.1 LTS (Noble Numbat)", osBuild: "", osPlatform: "ubuntu" };
    expect(evaluate(ubuntu, {}, DEFAULT_POLICY)[1]).toEqual({ check: "os-version", status: "pass", detail: "Ubuntu 24.04.1." });
  });
});

describe("posture", () => {
  const T = Date.parse("2026-10-28T09:00:00Z");
  const DAY = 86_400_000;
  const at = (ms: number) => new Date(ms).toISOString();
  const checks = (over: Partial<Record<string, Partial<StoredCheck>>> = {}): StoredCheck[] =>
    (["disk-encryption", "os-version", "firewall", "screen-lock"] as const).map((check) => ({
      check,
      status: "pass",
      detail: "",
      since: at(T),
      ...over[check],
    }));

  it("is compliant when every enabled check that applies passes", () => {
    expect(postureOf(checks({ firewall: { status: "not-applicable" } }), DEFAULT_POLICY, new Set(), T)).toEqual({ posture: "compliant", failing: [] });
  });

  it("blocks at once for a check that blocks, and gives the others a grace period", () => {
    const encryption = postureOf(checks({ "disk-encryption": { status: "fail", detail: "FileVault is off." } }), DEFAULT_POLICY, new Set(), T);
    expect(encryption.posture).toBe("non-compliant");
    expect(encryption.failing[0]).toMatchObject({ check: "disk-encryption", graceEndsAt: null, blocked: true });

    const firewall = checks({ firewall: { status: "fail", since: at(T - 2 * DAY) } });
    const early = postureOf(firewall, DEFAULT_POLICY, new Set(), T);
    expect(early.posture).toBe("at-risk");
    expect(early.failing[0]).toMatchObject({ graceEndsAt: at(T + 5 * DAY), blocked: false });
    expect(postureOf(firewall, DEFAULT_POLICY, new Set(), T + 5 * DAY).posture).toBe("non-compliant");
    expect(postureOf(firewall, { ...DEFAULT_POLICY, graceDays: 0 }, new Set(), T).posture).toBe("non-compliant");
  });

  it("counts an excepted check as passing, and leaves out checks the policy turns off", () => {
    const failing = checks({ "disk-encryption": { status: "fail" } });
    expect(postureOf(failing, DEFAULT_POLICY, new Set(["disk-encryption"]), T).posture).toBe("compliant");
    const off = { ...DEFAULT_POLICY, checks: { ...DEFAULT_POLICY.checks, "disk-encryption": { enabled: false, onFailure: "block" as const } } };
    expect(postureOf(failing, off, new Set(), T).posture).toBe("compliant");
  });

  it("waits while osquery has not answered, unless something already fails", () => {
    expect(postureOf(checks({ firewall: { status: "unknown" } }), DEFAULT_POLICY, new Set(), T).posture).toBe("pending");
    expect(postureOf(checks({ firewall: { status: "unknown" }, "screen-lock": { status: "fail" } }), DEFAULT_POLICY, new Set(), T).posture).toBe("at-risk");
  });
});

describe("the policy", () => {
  it("takes what is sent and keeps the rest", () => {
    const p = parsePolicy({ graceDays: 3, checks: { firewall: { onFailure: "block" } }, minimum: { macos: "15.1" } }, DEFAULT_POLICY);
    expect(p.graceDays).toBe(3);
    expect(p.checks.firewall).toEqual({ enabled: true, onFailure: "block" });
    expect(p.checks["disk-encryption"]).toEqual(DEFAULT_POLICY.checks["disk-encryption"]);
    expect(p.minimum).toEqual({ ...DEFAULT_POLICY.minimum, macos: "15.1" });
    expect(DEFAULT_POLICY.graceDays).toBe(7);
  });

  it("refuses what it cannot check", () => {
    const bad = (body: Record<string, unknown>) => () => parsePolicy(body, DEFAULT_POLICY);
    expect(bad({ checks: { edr: { enabled: true } } })).toThrow(/edr, which is not one of/);
    expect(bad({ checks: { firewall: { onFailure: "warn" } } })).toThrow(/block or grace/);
    expect(bad({ graceDays: 31 })).toThrow(/0 to 30/);
    expect(bad({ staleDays: 0 })).toThrow(/1 to 90/);
    expect(bad({ minimum: { macos: "fifteen" } })).toThrow(/a version such as/);
    expect(bad({ minimum: { linux: { "Ubuntu Linux": "22.04" } } })).toThrow(/not a distribution/);
    expect(bad({ minimum: { windowsBuild: 1.5 } })).toThrow(/whole number/);
  });
});
