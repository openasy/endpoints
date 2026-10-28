import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAuth, oidcFromEnv, readSecretsKey } from "@openasy/auth";
import { createApp, createMetricsHandler } from "./app.ts";
import { openDb } from "./db.ts";
import { createEndpoints } from "./endpoints.ts";
import { log } from "./log.ts";
import { PACK_VERSION } from "./pack.ts";
import { parseProducts } from "./products.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const port = Number(process.env.PORT ?? 8080);
const dbPath = process.env.ENDPOINTS_DB ?? "/data/endpoints.db";
const webDir = new URL("../dist/web", import.meta.url).pathname;
const docsDir = new URL("../dist/docs", import.meta.url).pathname;
const openapi = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Record<string, unknown>;
const headless = process.env.ENDPOINTS_HEADLESS === "true";
// Set it to keep /metrics off the port that is published or behind an ingress (ADR 0026).
const metricsPort = process.env.ENDPOINTS_METRICS_PORT ? Number(process.env.ENDPOINTS_METRICS_PORT) : undefined;

// Sign-in secrets are sealed with it (ADR 0021): Endpoints does not start without it.
const secretsKeyFile = process.env.ENDPOINTS_SECRETS_KEY_FILE ?? "/run/secrets/openasy-kek";
const kek = readSecretsKey(secretsKeyFile);
if (!kek) {
  log("error", "no key-encryption key: mount 32 random bytes (openssl rand -hex 32) and set ENDPOINTS_SECRETS_KEY_FILE if not at the default", {
    file: secretsKeyFile,
  });
  process.exit(1);
}

const db = openDb(dbPath);
// The address people open Endpoints at, behind the TLS proxy (ADR 0026). Cookies, passkeys and OIDC redirects use it,
// and osquery on every device is pointed at its host.
const publicUrl = (process.env.ENDPOINTS_PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, "");
// Every event of the audit log also goes to stdout, for a SIEM to collect (ADR 0013, 0017).
const endpoints = createEndpoints(db, { publicUrl, onEvent: (event) => log(event.result === "denied" ? "warn" : "info", "audit", { event }) });
const auth = createAuth({
  db,
  product: "endpoints",
  productName: "OpenAsy Endpoints",
  origin: publicUrl,
  // Locally the same Endpoints is often opened as 127.0.0.1 too.
  trustedOrigins: publicUrl.startsWith("http://localhost:") ? [publicUrl.replace("localhost", "127.0.0.1")] : [],
  passwords: process.env.ENDPOINTS_PASSWORD_SIGN_IN !== "false",
  oidc: oidcFromEnv(process.env, "ENDPOINTS_"),
  secretsKey: kek,
  // Every sign-in, failure and change to members and tokens joins the audit log (ADR 0013).
  onEvent: (event) => endpoints.recordAuth(event),
});
const products = parseProducts(process.env.OPENASY_PRODUCTS);
if (products.invalid.length) log("warn", "OPENASY_PRODUCTS: left out entries that are not id=https://address", { entries: products.invalid });

const server = createServer(
  createApp({
    db,
    endpoints,
    version,
    auth,
    webDir: !headless && existsSync(webDir) ? webDir : undefined,
    docsDir: existsSync(docsDir) ? docsDir : undefined,
    openapi,
    serveMetrics: metricsPort === undefined,
    products: products.products,
  }),
);
const metricsServer = metricsPort !== undefined ? createServer(createMetricsHandler(endpoints, version)) : undefined;
metricsServer?.listen(metricsPort, () => log("info", "metrics on their own port", { port: metricsPort }));

server.listen(port, () => log("info", "endpoints started", { version, port, db: dbPath, headless, pack: PACK_VERSION }));
if (!publicUrl.startsWith("https://")) {
  // osquery speaks only HTTPS: devices reach Endpoints through the TLS proxy, at ENDPOINTS_PUBLIC_URL's host.
  log(
    "warn",
    "ENDPOINTS_PUBLIC_URL is not https: osquery connects only over TLS, and browsers will not keep secure cookies. Put Endpoints behind TLS (ADR 0026)",
    {
      url: publicUrl,
    },
  );
}
const setup = auth.setupLink();
// No default password (ADR 0013): the first person to open this link becomes the owner.
if (setup) log("info", "no owner yet: open this link once to create the owner account", { url: setup });

const timers: NodeJS.Timeout[] = [setInterval(() => auth.purge(), 5 * 60_000)];

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  metricsServer?.close();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
