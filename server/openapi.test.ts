import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_TOKEN, fixture, hostDetails, startApp, UA, type Browser } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "endpoints-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
let p: Awaited<ReturnType<Awaited<ReturnType<typeof startApp>>["people"]>>;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
  p = await app.people();
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const json = (body: unknown) => (body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) });
const admin = (body?: unknown): RequestInit => ({ headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" }, ...json(body) });
/** As a person in their browser: their session cookie, from the product's own origin. */
const as = (b: Browser, body?: unknown): RequestInit => ({
  headers: { cookie: [...b.cookies].map(([k, v]) => `${k}=${v}`).join("; "), origin: base, "user-agent": UA, "content-type": "application/json" },
  ...json(body),
});
const osquery = (body: unknown): RequestInit => ({ headers: { "content-type": "application/json" }, ...json(body) });

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // Endpoints' own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((path) => !path.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let secretId = "";
  let secret = "";
  let device = "";
  let exception = "";

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("enrolment secrets and setup", async () => {
    const created = (await call("POST", "/api/v1/enroll-secrets", admin({ name: "Laptops" }))).body as { id: string; secret: string };
    secretId = created.id;
    secret = created.secret;
    await call("POST", "/api/v1/enroll-secrets", admin({ name: "Laptops" }));
    await call("POST", "/api/v1/enroll-secrets", admin({ name: "" }));
    await call("POST", "/api/v1/enroll-secrets", admin("nope"));
    await call("POST", "/api/v1/enroll-secrets", as(p.editor, { name: "Mine" }));
    await call("POST", "/api/v1/enroll-secrets", {});
    await call("GET", "/api/v1/enroll-secrets", as(p.viewer));
    await call("GET", "/api/v1/enroll-secrets", {});
    await call("GET", "/api/v1/setup", as(p.viewer));
    await call("GET", "/api/v1/setup", {});
  });

  it("osquery's enrolment and results", async () => {
    const snapshots = fixture("macos");
    const details = hostDetails(snapshots);
    const enrol = { enroll_secret: secret, host_identifier: details.system_info.uuid, host_details: details };
    const { node_key } = (await call("POST", "/api/v1/osquery/enroll", osquery(enrol))).body as { node_key: string };
    await call("POST", "/api/v1/osquery/enroll", osquery(enrol));
    await call("POST", "/api/v1/osquery/enroll", osquery("nope"));
    await call("POST", "/api/v1/osquery/log", {
      headers: { "content-encoding": "gzip" },
      body: gzipSync(JSON.stringify({ node_key, log_type: "result", data: snapshots })),
    });
    await call("POST", "/api/v1/osquery/log", osquery({ node_key, log_type: "status", data: [{ severity: "0", message: "osqueryd started" }] }));
    await call("POST", "/api/v1/osquery/log", osquery({ node_key: "oen_unknown", log_type: "result", data: [] }));
    await call("POST", "/api/v1/osquery/log", { headers: { "content-encoding": "gzip" }, body: gzipSync("x".repeat(17 * 1024 * 1024)) });
    await call("POST", "/api/v1/osquery/log", { headers: { "content-encoding": "br" }, body: "{}" });
  });

  it("devices", async () => {
    device = ((await call("GET", "/api/v1/devices", as(p.viewer))).body as { devices: Array<{ id: string }> }).devices[0]!.id;
    await call("GET", "/api/v1/devices", {});
    const d = "/api/v1/devices/{id}";
    await call("GET", d, as(p.viewer), `/api/v1/devices/${device}`);
    await call("GET", d, admin(), "/api/v1/devices/missing");
    await call("GET", d, {}, `/api/v1/devices/${device}`);
    await call("PUT", d, as(p.editor, { owner: "deniz.kim@example.com" }), `/api/v1/devices/${device}`);
    await call("PUT", d, as(p.editor, { owner: 5 }), `/api/v1/devices/${device}`);
    await call("PUT", d, as(p.editor, "nope"), `/api/v1/devices/${device}`);
    await call("PUT", d, as(p.editor, { owner: null }), "/api/v1/devices/missing");
    await call("PUT", d, as(p.viewer, { owner: null }), `/api/v1/devices/${device}`);
    await call("PUT", d, {}, `/api/v1/devices/${device}`);
    const r = "/api/v1/devices/{id}/reenroll";
    await call("POST", r, admin(), `/api/v1/devices/${device}/reenroll`);
    await call("POST", r, admin(), "/api/v1/devices/missing/reenroll");
    await call("POST", r, as(p.editor), `/api/v1/devices/${device}/reenroll`);
    await call("POST", r, {}, `/api/v1/devices/${device}/reenroll`);
    const s = "/api/v1/devices/{id}/software";
    await call("GET", s, as(p.viewer), `/api/v1/devices/${device}/software`);
    await call("GET", s, admin(), "/api/v1/devices/missing/software");
    await call("GET", s, {}, `/api/v1/devices/${device}/software`);
  });

  it("software", async () => {
    await call("GET", "/api/v1/software", as(p.viewer));
    await call("GET", "/api/v1/software", as(p.viewer), "/api/v1/software?q=slack&platform=darwin");
    await call("GET", "/api/v1/software", as(p.viewer), "/api/v1/software?platform=beos");
    await call("GET", "/api/v1/software", {});
    await call("GET", "/api/v1/software/installs", as(p.viewer), "/api/v1/software/installs?name=Slack");
    await call("GET", "/api/v1/software/installs", as(p.viewer));
    await call("GET", "/api/v1/software/installs", {}, "/api/v1/software/installs?name=Slack");
  });

  it("compliance, the policy and exceptions", async () => {
    await call("GET", "/api/v1/compliance", as(p.viewer));
    await call("GET", "/api/v1/compliance", {});
    await call("GET", "/api/v1/policy", as(p.viewer));
    await call("GET", "/api/v1/policy", {});
    await call("PUT", "/api/v1/policy", admin({ graceDays: 3, checks: { firewall: { onFailure: "block" } }, minimum: { linux: { ubuntu: "24.04" } } }));
    await call("PUT", "/api/v1/policy", admin({ graceDays: 300 }));
    await call("PUT", "/api/v1/policy", admin("nope"));
    await call("PUT", "/api/v1/policy", as(p.editor, { graceDays: 1 }));
    await call("PUT", "/api/v1/policy", {});
    const x = { deviceId: device, check: "firewall", reason: "Lab machine", days: 30 };
    exception = ((await call("POST", "/api/v1/exceptions", admin(x))).body as { id: string }).id;
    await call("POST", "/api/v1/exceptions", admin(x));
    await call("POST", "/api/v1/exceptions", admin({ ...x, deviceId: "missing" }));
    await call("POST", "/api/v1/exceptions", admin({ ...x, check: "edr" }));
    await call("POST", "/api/v1/exceptions", admin("nope"));
    await call("POST", "/api/v1/exceptions", as(p.editor, x));
    await call("POST", "/api/v1/exceptions", {});
    await call("GET", "/api/v1/exceptions", as(p.viewer));
    await call("GET", "/api/v1/exceptions", {});
    await call("GET", "/api/v1/devices/{id}", admin(), `/api/v1/devices/${device}`);
    const e = "/api/v1/exceptions/{id}";
    await call("DELETE", e, as(p.editor), `/api/v1/exceptions/${exception}`);
    await call("DELETE", e, admin(), `/api/v1/exceptions/${exception}`);
    await call("DELETE", e, admin(), `/api/v1/exceptions/${exception}`);
    await call("DELETE", e, {}, `/api/v1/exceptions/${exception}`);
  });

  it("the audit log and the overview", async () => {
    const page = (await call("GET", "/api/v1/audit", admin(), "/api/v1/audit?limit=2")).body as { next: string };
    await call("GET", "/api/v1/audit", admin(), `/api/v1/audit?limit=2&cursor=${page.next}&kind=device`);
    await call("GET", "/api/v1/audit", admin(), "/api/v1/audit?kind=nope");
    await call("GET", "/api/v1/audit", admin(), "/api/v1/audit?limit=0");
    await call("GET", "/api/v1/audit", {});
    await call("GET", "/api/v1/summary", as(p.viewer));
    await call("GET", "/api/v1/summary", {});
  });

  it("revokes secrets and removes devices, and refuses what is not there", async () => {
    const revoke = "/api/v1/enroll-secrets/{id}/revoke";
    await call("POST", revoke, as(p.editor), `/api/v1/enroll-secrets/${secretId}/revoke`);
    await call("POST", revoke, admin(), `/api/v1/enroll-secrets/${secretId}/revoke`);
    await call("POST", revoke, admin(), "/api/v1/enroll-secrets/missing/revoke");
    await call("POST", revoke, {}, `/api/v1/enroll-secrets/${secretId}/revoke`);
    const d = "/api/v1/devices/{id}";
    await call("DELETE", d, as(p.editor), `/api/v1/devices/${device}`);
    await call("DELETE", d, admin(), `/api/v1/devices/${device}`);
    await call("DELETE", d, admin(), `/api/v1/devices/${device}`);
    await call("DELETE", d, {}, `/api/v1/devices/${device}`);
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
