import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { createGunzip } from "node:zlib";
import { AuthError, identityOrigin, mergeOpenApi, sendProblem, type Auth, type Role } from "@openasy/auth";
import { EndpointsError, type Actor, type Endpoints, type ProblemCode } from "./endpoints.ts";
import { log } from "./log.ts";
import { countRequest, renderMetrics } from "./metrics.ts";
import type { ProductLink } from "./products.ts";

export interface AppOptions {
  db: DatabaseSync;
  endpoints: Endpoints;
  version: string;
  /** Sign-in, sessions, members and API tokens (ADR 0002, 0003). */
  auth: Auth;
  /** For tests and local scripts: one shared token with the admin role. main.ts never sets it. */
  adminToken?: string;
  /** Built web UI; omit to run headless (ADR 0018). */
  webDir?: string;
  /** Built API reference (Swagger UI), served at /api/docs. */
  docsDir?: string;
  /** The OpenAPI description, served at /api/openapi.json with this release's version. */
  openapi?: Record<string, unknown>;
  /** false when /metrics is served on its own port instead (ADR 0026). */
  serveMetrics?: boolean;
  /** The install's OpenAsy products and their addresses, from OPENASY_PRODUCTS, for the product switcher. */
  products?: ProductLink[];
}

/** osquery sends a device's software in one result log; a laptop's packages fit well within this once unpacked. */
const OSQUERY_LIMIT = 16 * 1024 * 1024;

function metricsText(endpoints: Endpoints, version: string) {
  return renderMetrics(version, endpoints.gauges());
}

/** Serves only /metrics, for a port that is not exposed with the rest (ENDPOINTS_METRICS_PORT). */
export function createMetricsHandler(endpoints: Endpoints, version: string) {
  return (req: IncomingMessage, res: ServerResponse) => {
    if (new URL(req.url ?? "/", "http://localhost").pathname !== "/metrics") return problem(res, 404, "not-found");
    send(res, 200, metricsText(endpoints, version), "text/plain; version=0.0.4");
  };
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".json": "application/json",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

// Identity keeps people's theme and language when they sign in through it; the pages read them there (ADR 0033).
const IDENTITY = identityOrigin(process.env);

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "content-security-policy": `default-src 'self'; connect-src 'self'${IDENTITY ? ` ${IDENTITY}` : ""}; img-src 'self' data:; style-src 'self' 'unsafe-inline'`,
};

function send(res: ServerResponse, status: number, body: string | Buffer, type = "application/json", headers: Record<string, string> = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers, "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

const json = (res: ServerResponse, status: number, data: unknown) => send(res, status, JSON.stringify(data));

const TITLES: Record<ProblemCode, string> = {
  "invalid-json": "Invalid JSON",
  "invalid-body": "Invalid request body",
  "not-found": "Not found",
  conflict: "Conflict",
  "payload-too-large": "Payload too large",
  "internal-error": "Internal error",
};

/** RFC 9457 Problem Details (ADR 0024). `code` is the stable part clients match on. */
function problem(res: ServerResponse, status: number, code: ProblemCode, detail?: string) {
  const body = { type: `https://openasy.github.io/problems/${code}`, title: TITLES[code], status, code, ...(detail && { detail }) };
  send(res, status, JSON.stringify(body), "application/problem+json");
}

/** Serves a file from dir, or returns false when the path is outside it or missing. */
async function serveFile(res: ServerResponse, dir: string, relative: string): Promise<boolean> {
  const file = normalize(join(dir, relative));
  if (!file.startsWith(normalize(dir)) || !extname(file)) return false;
  try {
    send(res, 200, await readFile(file), TYPES[extname(file)] ?? "application/octet-stream");
    return true;
  } catch {
    return false;
  }
}

/**
 * Reads a JSON object, gunzipping it when it is sent gzipped (osquery's --logger_tls_compress). The limit counts the
 * unpacked bytes, so a small gzip that unpacks to gigabytes is refused at the limit.
 */
async function readJson(req: IncomingMessage, limit = 64 * 1024): Promise<Record<string, unknown>> {
  const encoding = req.headers["content-encoding"];
  if (encoding && encoding !== "gzip" && encoding !== "identity") throw new EndpointsError(400, "invalid-json", "Content-Encoding must be gzip or absent.");
  const source = encoding === "gzip" ? req.pipe(createGunzip()) : req;
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of source as AsyncIterable<Buffer>) {
      size += chunk.length;
      if (size > limit) {
        req.unpipe();
        throw new EndpointsError(413, "payload-too-large", `The body must be JSON, at most ${Math.round(limit / 1024)} KiB.`);
      }
      chunks.push(chunk);
    }
  } catch (err) {
    if (err instanceof EndpointsError) throw err;
    throw new EndpointsError(400, "invalid-json", "The gzip body could not be read.");
  }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
    return body as Record<string, unknown>;
  } catch {
    throw new EndpointsError(400, "invalid-json", "The body must be a JSON object.");
  }
}

function tokenMatches(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header?.startsWith("Bearer ")) return false;
  const a = Buffer.from(header.slice(7));
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The role a route needs (ADR 0003). osquery's own routes carry their secret in the body. */
type Need = "none" | Role;
interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: string[];
  body: (limit?: number) => Promise<Record<string, unknown>>;
  actor: () => Actor;
}
interface Route {
  method: string;
  /** Path pattern; each `:name` matches one segment. */
  path: string;
  auth: Need;
  handle: (ctx: Ctx) => unknown;
}

export function createApp({ db, endpoints, version, auth, adminToken, webDir, docsDir, openapi, serveMetrics = true, products = [] }: AppOptions) {
  // The served description includes /api/v1/auth from @openasy/auth, so the API reference documents sign-in too.
  const spec = openapi && JSON.stringify({ ...mergeOpenApi(openapi), info: { ...(openapi.info as object), version } });
  const noContent = (res: ServerResponse) => {
    res.writeHead(204, SECURITY_HEADERS).end();
  };

  const routes: Route[] = [
    { method: "GET", path: "/api/v1/version", auth: "none", handle: () => ({ product: "endpoints", version }) },
    { method: "GET", path: "/api/v1/products", auth: "viewer", handle: () => ({ products }) },
    { method: "GET", path: "/api/v1/summary", auth: "viewer", handle: () => endpoints.summary() },

    // What osquery calls on each device (its TLS enroll and logger plugins). It sends; Endpoints never sends it a query.
    { method: "POST", path: "/api/v1/osquery/enroll", auth: "none", handle: async ({ body }) => endpoints.enroll(await body()) },
    { method: "POST", path: "/api/v1/osquery/log", auth: "none", handle: async ({ body }) => endpoints.ingest(await body(OSQUERY_LIMIT)) },

    // Devices, found by what osquery reports. No form adds one: a device enrols itself.
    { method: "GET", path: "/api/v1/devices", auth: "viewer", handle: () => ({ devices: endpoints.devices() }) },
    { method: "GET", path: "/api/v1/devices/:id", auth: "viewer", handle: ({ params }) => endpoints.device(params[0]!) },
    {
      method: "PUT",
      path: "/api/v1/devices/:id",
      auth: "editor",
      handle: async ({ params, body, actor }) => endpoints.setOwner(params[0]!, await body(), actor()),
    },
    {
      method: "DELETE",
      path: "/api/v1/devices/:id",
      auth: "admin",
      handle: ({ res, params, actor }) => (endpoints.removeDevice(params[0]!, actor()), noContent(res)),
    },
    { method: "POST", path: "/api/v1/devices/:id/reenroll", auth: "admin", handle: ({ params, actor }) => endpoints.allowReenrol(params[0]!, actor()) },
    { method: "GET", path: "/api/v1/devices/:id/software", auth: "viewer", handle: ({ params }) => ({ software: endpoints.deviceSoftware(params[0]!) }) },

    // Software across devices.
    {
      method: "GET",
      path: "/api/v1/software",
      auth: "viewer",
      handle: ({ url }) => endpoints.software({ q: url.searchParams.get("q"), platform: url.searchParams.get("platform") }),
    },
    {
      method: "GET",
      path: "/api/v1/software/installs",
      auth: "viewer",
      handle: ({ url }) => ({ installs: endpoints.installs(url.searchParams.get("name") ?? "") }),
    },

    // Compliance, the policy and its exceptions. Admins keep the policy.
    { method: "GET", path: "/api/v1/compliance", auth: "viewer", handle: () => endpoints.compliance() },
    { method: "GET", path: "/api/v1/policy", auth: "viewer", handle: () => endpoints.policy() },
    { method: "PUT", path: "/api/v1/policy", auth: "admin", handle: async ({ body, actor }) => endpoints.savePolicy(await body(), actor()) },
    { method: "GET", path: "/api/v1/exceptions", auth: "viewer", handle: () => ({ exceptions: endpoints.exceptions() }) },
    {
      method: "POST",
      path: "/api/v1/exceptions",
      auth: "admin",
      handle: async ({ res, body, actor }) => json(res, 201, endpoints.createException(await body(), actor())),
    },
    {
      method: "DELETE",
      path: "/api/v1/exceptions/:id",
      auth: "admin",
      handle: ({ res, params, actor }) => (endpoints.deleteException(params[0]!, actor()), noContent(res)),
    },

    // Enrolment: secrets osquery enrols with, and the files each device needs.
    { method: "GET", path: "/api/v1/enroll-secrets", auth: "viewer", handle: () => ({ secrets: endpoints.secrets() }) },
    {
      method: "POST",
      path: "/api/v1/enroll-secrets",
      auth: "admin",
      handle: async ({ res, body, actor }) => json(res, 201, endpoints.createSecret(await body(), actor())),
    },
    { method: "POST", path: "/api/v1/enroll-secrets/:id/revoke", auth: "admin", handle: ({ params, actor }) => endpoints.revokeSecret(params[0]!, actor()) },
    { method: "GET", path: "/api/v1/setup", auth: "viewer", handle: () => endpoints.setup() },

    // The audit log, for auditors and for a SIEM.
    {
      method: "GET",
      path: "/api/v1/audit",
      auth: "viewer",
      handle: ({ url }) => {
        const limit = Number(url.searchParams.get("limit") ?? 100);
        if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw new EndpointsError(422, "invalid-body", "limit is a whole number from 1 to 500.");
        return endpoints.events({ kind: url.searchParams.get("kind"), cursor: url.searchParams.get("cursor") }, limit);
      },
    },
  ];

  const compiled = routes.map((r) => ({ ...r, re: new RegExp(`^${r.path.replace(/[.]/g, "\\.").replace(/:[A-Za-z]+/g, "([^/]+)")}$`) }));

  /** Returns who is calling, or null for a route that needs nobody. */
  function authorize(req: IncomingMessage, need: Need): Actor | null {
    if (need === "none") return null;
    if (tokenMatches(req.headers.authorization, adminToken)) return { name: "admin token", role: "admin" };
    const p = auth.authorize(req, need);
    if (p.kind === "token") return { name: `API token ${p.name}`, role: p.role };
    return { name: `${p.user.name} <${p.user.email}>`, role: p.role };
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    if (path === "/healthz") return (json(res, 200, { status: "ok" }), "/healthz");

    if (path === "/readyz") {
      try {
        db.prepare("SELECT 1").get();
        json(res, 200, { status: "ready" });
      } catch {
        json(res, 503, { status: "database unavailable" });
      }
      return "/readyz";
    }

    if (path === "/metrics") {
      // Not even the web UI's fallback answers here when metrics have their own port.
      if (serveMetrics) send(res, 200, metricsText(endpoints, version), "text/plain; version=0.0.4");
      else problem(res, 404, "not-found");
      return "/metrics";
    }

    if (path === "/api/openapi.json" && spec) return (send(res, 200, spec), "/api/openapi.json");

    if (docsDir && (path === "/api/docs" || path.startsWith("/api/docs/"))) {
      if (path === "/api/docs") {
        res.writeHead(301, { ...SECURITY_HEADERS, location: "/api/docs/" }).end();
        return "/api/docs";
      }
      const relative = path.slice("/api/docs/".length) || "index.html";
      if (!(await serveFile(res, docsDir, relative))) problem(res, 404, "not-found");
      return "/api/docs";
    }

    if (await auth.handle(req, res)) return auth.routeName(req) ?? "/api/v1/auth/*";

    for (const r of compiled) {
      const m = path.match(r.re);
      if (!m || r.method !== req.method) continue;
      try {
        const actor = authorize(req, r.auth);
        const params = m.slice(1).map(decodeURIComponent);
        const result = await r.handle({
          req,
          res,
          url,
          params,
          body: (limit) => readJson(req, limit),
          actor: () => actor ?? { name: "unknown", role: "viewer" },
        });
        if (!res.headersSent && result !== undefined) json(res, 200, result);
      } catch (err) {
        if (err instanceof AuthError) {
          sendProblem(res, err);
          if (!req.complete) req.resume();
          return r.path;
        }
        if (!(err instanceof EndpointsError)) throw err;
        problem(res, err.status, err.code, err.message);
        // Unread request bodies would otherwise hold the connection.
        if (!req.complete) req.resume();
      }
      return r.path;
    }

    if (path.startsWith("/api/")) return (problem(res, 404, "not-found"), "/api/*");

    if (webDir && (req.method === "GET" || req.method === "HEAD")) {
      // Unknown paths fall back to the single-page app.
      if (!(await serveFile(res, webDir, path === "/" ? "index.html" : path))) send(res, 200, await readFile(join(webDir, "index.html")), TYPES[".html"]);
      return "/web";
    }

    problem(res, 404, "not-found");
    return "unmatched";
  }

  return async (req: IncomingMessage, res: ServerResponse) => {
    const started = performance.now();
    let routeName = "error";
    try {
      routeName = await route(req, res);
    } catch (err) {
      log("error", "request failed", { error: String(err), path: req.url });
      if (!res.headersSent) problem(res, 500, "internal-error");
    }
    countRequest(req.method ?? "GET", routeName, res.statusCode);
    // osquery sends results every minute from every device; those requests are counted in /metrics, not logged.
    if (routeName !== "/healthz" && routeName !== "/metrics" && routeName !== "/api/v1/osquery/log") {
      log("info", "request", { method: req.method, path: url(req), status: res.statusCode, ms: Math.round(performance.now() - started) });
    }
  };
}

/** The path without the query string. */
const url = (req: IncomingMessage) => (req.url ?? "/").split("?")[0];
