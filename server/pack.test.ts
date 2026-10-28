import { describe, expect, it } from "vitest";
import { flagsFile, INVENTORY, PACK, PACK_VERSION, SOFTWARE_SOURCES, USERS } from "./pack.ts";

// The pack is all a device runs for Endpoints (ADR 0065). These tests keep it to reading the device.

describe("the query pack", () => {
  const queries = Object.entries(PACK.schedule);

  it("has a version every result carries", () => {
    expect(PACK_VERSION).toBe("1");
  });

  it("only reads, from tables that stay on the device", () => {
    for (const [name, q] of queries) {
      expect(q.query, name).toMatch(/^SELECT /);
      expect(q.query.match(/;/g)?.length, name).toBe(1);
      // Tables that reach the network, read file contents or carve files are never in it.
      expect(q.query, name).not.toMatch(/\b(curl|curl_certificate|carves|yara|file_lines|augeas|hash|magic|ATTACH|PRAGMA)\b/i);
    }
  });

  it("sends snapshots, at most every 15 minutes, on platforms osquery knows", () => {
    for (const [name, q] of queries) {
      expect(q.snapshot, name).toBe(true);
      expect(q.interval, name).toBeGreaterThanOrEqual(900);
      if (q.platform) expect(["darwin", "linux", "windows", "posix"], name).toContain(q.platform);
      expect(q.description, name).toMatch(/\.$/);
    }
  });

  it("has a use for every query: the inventory, users, a check or software", () => {
    const checks = /^endpoints_(encryption|firewall|screenlock)_(macos|linux|windows)$/;
    for (const [name] of queries) expect(name === INVENTORY || USERS.includes(name) || checks.test(name) || name in SOFTWARE_SOURCES, name).toBe(true);
  });
});

describe("the osquery flags", () => {
  it("point at Endpoints over TLS, read the local pack and turn off what would let the server ask for more", () => {
    const flags = flagsFile("linux", "https://endpoints.example.com");
    expect(flags).toContain("--tls_hostname=endpoints.example.com");
    expect(flags).toContain("--enroll_tls_endpoint=/api/v1/osquery/enroll");
    expect(flags).toContain("--logger_tls_endpoint=/api/v1/osquery/log");
    expect(flags).toContain("--config_plugin=filesystem");
    expect(flags).toContain("--config_path=/etc/osquery/osquery.conf");
    for (const off of ["distributed", "carver", "extensions", "events"]) expect(flags).toContain(`--disable_${off}=true`);
    expect(flags).not.toMatch(/config_plugin=tls|distributed_plugin/);
  });

  it("keep the proxy's port and path, and each platform's folder", () => {
    const mac = flagsFile("darwin", "https://example.com:8443/endpoints/");
    expect(mac).toContain("--tls_hostname=example.com:8443");
    expect(mac).toContain("--enroll_tls_endpoint=/endpoints/api/v1/osquery/enroll");
    expect(mac).toContain("--enroll_secret_path=/var/osquery/enroll_secret");
    expect(flagsFile("windows", "https://e.example.com")).toContain("--config_path=C:\\Program Files\\osquery\\osquery.conf");
  });
});
