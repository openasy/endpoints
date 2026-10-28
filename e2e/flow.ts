// The steps of e2e/run.sh that use the API and osquery: the owner signs in with a second factor, as in a browser, makes
// an enrolment secret, and puts the files from the setup page on the Debian container, where osqueryd runs as its
// systemd unit starts it.
import { execFileSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { copyFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [base, setupLink, dir] = process.argv.slice(2) as [string, string, string];
// The API is reached on its own port; requests carry the origin people open it at, behind the proxy.
const origin = new URL(setupLink).origin;
const PASSWORD = "correct horse battery";
let failed = false;
const check = (ok: boolean, what: string) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) failed = true;
};

const cookies = new Map<string, string>();
async function call(path: string, body?: unknown, method = body === undefined ? "GET" : "POST") {
  const res = await fetch(base + path, {
    method,
    headers: {
      origin,
      "user-agent": "Mozilla/5.0 (X11; Linux) Firefox/140.0",
      cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join("; "),
      ...(body !== undefined && { "content-type": "application/json" }),
    },
    ...(body !== undefined && { body: JSON.stringify(body) }),
  });
  for (const c of res.headers.getSetCookie()) {
    const [pair] = c.split(";");
    cookies.set(pair!.slice(0, pair!.indexOf("=")), pair!.slice(pair!.indexOf("=") + 1));
  }
  const type = res.headers.get("content-type") ?? "";
  return { status: res.status, body: (type.includes("json") ? await res.json() : await res.text()) as any };
}

const totp = (secret: string) => {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secret.replace(/=+$/, "")) bits += a.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const h = createHmac("sha1", key).update(msg).digest();
  return String((h.readUInt32BE(h[19]! & 15) & 0x7fffffff) % 1e6).padStart(6, "0");
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** Asks until the answer is what is wanted, for up to two minutes. */
async function until<T>(what: () => Promise<T>, ok: (v: T) => boolean): Promise<T> {
  let v = await what();
  for (let i = 0; i < 60 && !ok(v); i++) (await sleep(2000), (v = await what()));
  return v;
}

await call("/api/v1/auth/setup", { token: new URL(setupLink).searchParams.get("setup"), name: "Olivia Owner", email: "owner@example.com", password: PASSWORD });
const { body: factor } = await call("/api/v1/auth/me/totp", {});
await call("/api/v1/auth/me/totp/confirm", { code: totp(factor.secret) });

const made = await call("/api/v1/enroll-secrets", { name: "e2e laptops", expiresInDays: 1 });
check(made.status === 201 && made.body.secret.startsWith("oee_"), "an admin makes an enrolment secret");
const setup = (await call("/api/v1/setup")).body;
check(setup.https && setup.tlsHostname === "endpoints-tls:8443", "the setup page points osquery at the proxy's https address");

// The three files from the setup page, as an admin puts them on a device. The pack's intervals are cut to 10 seconds so
// the test does not wait 15 minutes; its queries are the ones every device runs.
const pack = JSON.parse(setup.pack) as { schedule: Record<string, { interval: number }> };
for (const q of Object.values(pack.schedule)) q.interval = 10;
writeFileSync(join(dir, "osquery", "osquery.flags"), `${setup.platforms.linux.flags}--tls_server_certs=/etc/osquery/ca.pem\n`);
writeFileSync(join(dir, "osquery", "osquery.conf"), JSON.stringify(pack));
writeFileSync(join(dir, "osquery", "enroll_secret"), made.body.secret);
copyFileSync(join(dir, "certs", "ca.pem"), join(dir, "osquery", "ca.pem"));
const docker = (...args: string[]) => execFileSync("docker", args, { encoding: "utf8" });
docker(
  "exec",
  "e2e-osquery",
  "sh",
  "-c",
  "cd /etc/osquery-files && install -m 600 enroll_secret /etc/osquery/ && install -m 644 osquery.flags osquery.conf ca.pem /etc/osquery/",
);
// As osquery's systemd unit starts it: the flag file, then the config path.
docker(
  "exec",
  "-d",
  "e2e-osquery",
  "sh",
  "-c",
  "/opt/osquery/bin/osqueryd --flagfile /etc/osquery/osquery.flags --config_path /etc/osquery/osquery.conf --logger_tls_period=5 >/tmp/osqueryd.log 2>&1",
);

const devices = async () => (await call("/api/v1/devices")).body.devices as Array<Record<string, any>>;
/** Ends the test with what osquery and the proxy said, when a step the rest needs failed. */
const stop = () => {
  console.log(docker("exec", "e2e-osquery", "tail", "-30", "/tmp/osqueryd.log"));
  console.log(execFileSync("sh", ["-c", "docker logs --tail 20 e2e-endpoints-tls 2>&1"], { encoding: "utf8" }));
  process.exit(1);
};
const enrolled = await until(devices, (d) => d.length === 1);
check(enrolled.length === 1 && enrolled[0]!.platform === "linux" && /Debian/.test(enrolled[0]!.os.name), "osquery enrols, and the device shows with its OS");
if (enrolled.length !== 1) stop();
const checked = await until(
  async () => (await call(`/api/v1/devices/${enrolled[0]!.id}`)).body,
  (d) => d.posture !== "pending" && d.software > 0,
);
const status = (id: string) => checked.checks.find((c: { check: string }) => c.check === id)?.status;
check(checked.packVersion === "1" && checked.osqueryVersion === "5.24.0", "results carry the pack's version, and osquery's");
check(status("os-version") === "pass", "Debian 13 passes the operating system check");
check(status("disk-encryption") === "fail" && checked.posture === "non-compliant", "a container's / is not encrypted, so the device is non-compliant");
check(status("firewall") === "not-applicable" && status("screen-lock") === "not-applicable", "firewall and screen lock are not checked on Linux");
check(checked.software > 50, `its Debian packages are listed (${checked.software})`);
const software = (await call("/api/v1/software?q=osquery")).body;
check(
  software.titles.some((t: { name: string; newest: string }) => t.name === "osquery" && t.newest.startsWith("5.24.0")),
  "osquery itself is in the software list",
);
const metrics = await (await fetch(`${base}/metrics`)).text();
check(
  /openasy_endpoints_snapshots_total [1-9]/.test(metrics) && metrics.includes('openasy_endpoints_devices{posture="non-compliant"} 1'),
  "metrics count the snapshots and the device",
);

// A removed device enrols again on its own: osquery is told its node key is unknown.
check((await call(`/api/v1/devices/${enrolled[0]!.id}`, undefined, "DELETE")).status === 204, "an admin removes the device");
const again = await until(devices, (d) => d.length === 1 && d[0]!.id !== enrolled[0]!.id);
check(again.length === 1 && again[0]!.uuid === enrolled[0]!.uuid, "osquery enrols again as a new device");

// With its secret revoked, a removed device cannot come back.
await call(`/api/v1/enroll-secrets/${made.body.id}/revoke`, {});
await call(`/api/v1/devices/${again[0]!.id}`, undefined, "DELETE");
const refused = await until(
  async () => (await call("/api/v1/audit?kind=device")).body.events as Array<{ result: string; detail: string }>,
  (e) => e.some((x) => x.result === "denied"),
);
check(
  refused.some((x) => x.detail.includes("is revoked")),
  "an enrolment with a revoked secret is refused and recorded",
);
check((await devices()).length === 0, "and the device stays removed");
check(!JSON.stringify((await call("/api/v1/audit")).body).includes(made.body.secret), "the secret is not in the audit log");

if (failed) stop();
console.log("e2e passed");
