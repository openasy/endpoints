// Starts the app on a random port for tests, with people signed in as a browser would be, and osquery as a device
// sends to it: the snapshots in testdata/ were captured from osqueryd 5.24 running the pack on macOS and Debian.
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { gzipSync } from "node:zlib";
import { createAuth } from "@openasy/auth";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { createEndpoints, type EndpointsOptions } from "./endpoints.ts";

export const ADMIN_TOKEN = "test-admin-token";
export const KEK = Buffer.alloc(32, 7);
export const T0 = Date.parse("2026-10-28T09:00:00Z");
export const UA = "Mozilla/5.0 (Macintosh) Chrome/141.0";
export const PASSWORD = "correct horse battery";

export type Snapshot = { name: string; snapshot: Array<Record<string, string>>; unixTime: number; decorations: Record<string, string>; [k: string]: unknown };
export const fixture = (name: "macos" | "debian" | "windows") =>
  JSON.parse(readFileSync(new URL(`./testdata/${name}.json`, import.meta.url), "utf8")) as Snapshot[];

/** osquery's host_details at enrolment, from a fixture's inventory snapshot. */
export function hostDetails(snapshots: Snapshot[]) {
  const r = snapshots.find((s) => s.name === "endpoints_inventory")!.snapshot[0]!;
  return {
    system_info: {
      uuid: r.uuid,
      hostname: r.hostname,
      computer_name: r.computer_name,
      hardware_serial: r.hardware_serial,
      hardware_vendor: r.hardware_vendor,
      hardware_model: r.hardware_model,
      cpu_brand: r.cpu_brand,
      physical_memory: r.physical_memory,
    },
    os_version: { name: r.os_name, version: r.os_version, major: r.os_major, minor: r.os_minor, build: r.os_build, platform: r.os_platform },
    osquery_info: { version: r.osquery_version },
  };
}

/** fetch with a cookie jar, as a browser: cookies are kept by name, which is enough for one host. */
export class Browser {
  readonly cookies = new Map<string, string>();
  readonly base: string;
  constructor(base: string) {
    this.base = base;
  }
  async fetch(path: string, init: { method?: string; body?: unknown } = {}) {
    const res = await fetch(this.base + path, {
      method: init.method ?? (init.body === undefined ? "GET" : "POST"),
      redirect: "manual",
      headers: {
        origin: this.base,
        "user-agent": UA,
        cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "),
        ...(init.body !== undefined && { "content-type": "application/json" }),
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      const name = pair!.slice(0, pair!.indexOf("="));
      const value = pair!.slice(pair!.indexOf("=") + 1);
      if (/max-age=0|expires=thu, 01 jan 1970/i.test(c)) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return res;
  }
  async json<T = any>(path: string, init: { method?: string; body?: unknown } = {}) {
    const res = await this.fetch(path, init);
    return { status: res.status, body: (res.status === 204 ? {} : await res.json()) as T };
  }
}

export const totp = (secret: string) => {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secret.replace(/=+$/, "")) bits += a.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const h = createHmac("sha1", key).update(msg).digest();
  return String((h.readUInt32BE(h[19]! & 15) & 0x7fffffff) % 1e6).padStart(6, "0");
};

export async function startApp(opts: Partial<AppOptions> & { version: string; endpointsOptions?: Partial<EndpointsOptions> }) {
  const db = openDb(":memory:");
  let now = T0;
  const { endpointsOptions, ...appOptions } = opts;
  const endpoints = createEndpoints(db, { publicUrl: "https://endpoints.example.com", clock: () => now, ...endpointsOptions });
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "endpoints", productName: "OpenAsy Endpoints", origin: base, secretsKey: KEK, onEvent: endpoints.recordAuth });
  handler = createApp({ db, endpoints, auth, adminToken: ADMIN_TOKEN, ...appOptions });
  const admin = (path: string, init: RequestInit = {}) =>
    fetch(base + path, { ...init, headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json", ...init.headers } });
  const get = async (path: string) => (await (await admin(path)).json()) as any;
  const send = (method: string, path: string, body?: unknown) => admin(path, { method, ...(body !== undefined && { body: JSON.stringify(body) }) });
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));

  /** As osquery's TLS plugins post: JSON, gzipped when osquery is started with --logger_tls_compress. */
  const osquery = async (path: "enroll" | "log", body: unknown, gzip = false) => {
    const res = await fetch(`${base}/api/v1/osquery/${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(gzip && { "content-encoding": "gzip" }) },
      body: gzip ? gzipSync(JSON.stringify(body)) : JSON.stringify(body),
    });
    return { status: res.status, body: (await res.json()) as { node_key?: string; node_invalid?: boolean } };
  };

  /** A new enrolment secret, as an admin makes it. */
  const newSecret = async (name = "Laptops") =>
    ((await (await send("POST", "/api/v1/enroll-secrets", { name })).json()) as { secret: string; id: string }).secret;

  /** Enrols a device from a fixture and sends its snapshots, at the time of the test's clock. */
  async function enrolDevice(name: "macos" | "debian" | "windows", secret: string, change: (s: Snapshot[]) => void = () => {}) {
    const snapshots = fixture(name);
    change(snapshots);
    const details = hostDetails(snapshots);
    const { body } = await osquery("enroll", { enroll_secret: secret, host_identifier: details.system_info.uuid, platform_type: "21", host_details: details });
    const at = Math.floor(now / 1000);
    await osquery("log", { node_key: body.node_key, log_type: "result", data: snapshots.map((s) => ({ ...s, unixTime: at })) }, true);
    const id = ((await get("/api/v1/devices")).devices as Array<{ id: string; uuid: string }>).find(
      (d) => d.uuid === details.system_info.uuid!.toUpperCase(),
    )!.id;
    return { id, nodeKey: body.node_key!, snapshots };
  }

  /** The owner from the first-start link, then members invited by them, each signed in from their own browser. */
  async function people() {
    const owner = new Browser(base);
    const token = new URL(auth.setupLink()!).searchParams.get("setup");
    await owner.json("/api/v1/auth/setup", { body: { token, name: "Olivia Owner", email: "owner@example.com", password: PASSWORD } });
    // Owners and admins need a second factor (ADR 0002).
    const { body: t } = await owner.json<{ secret: string }>("/api/v1/auth/me/totp", { body: {} });
    await owner.json("/api/v1/auth/me/totp/confirm", { body: { code: totp(t.secret) } });
    const invite = async (name: string, email: string, role: string) => {
      const { body } = await owner.json<{ link: string }>("/api/v1/auth/members", { body: { email, name, role } });
      const b = new Browser(base);
      await b.json(`/api/v1/auth/links/${new URL(body.link).searchParams.get("link")}`, { body: { password: PASSWORD } });
      return b;
    };
    return { owner, editor: await invite("Ece Editor", "ece@example.com", "editor"), viewer: await invite("Veli Viewer", "veli@example.com", "viewer") };
  }

  return { db, endpoints, auth, base, admin, get, send, close, osquery, newSecret, enrolDevice, people, later: (ms: number) => (now += ms), now: () => now };
}
