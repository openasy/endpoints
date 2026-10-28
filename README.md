# endpoints

[![CI](https://github.com/openasy/endpoints/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/endpoints/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Endpoints product: **every laptop and workstation, encrypted, updated and
locked** (ADR 0065). [osquery](https://osquery.io/) on each device reads it with a fixed query pack and sends what it
finds; Endpoints checks it against one policy and lists the hardware, the local accounts and the software.

```
osquery on a laptop ──enrol (secret)──▶  TLS proxy  ──▶  endpoints  ──▶ checks ──▶ compliant, at risk, non-compliant
  osquery.conf: the pack ──results───▶                      └── software, hardware, accounts
```

## What it does and does not do

- **osquery is the agent.** Nothing of OpenAsy is installed on a device: osquery's own package, with three files next
  to it. There is no `endpoints-agent`.
- **Endpoints never sends a device a query.** The queries are in `osquery/osquery.conf`, the pack, which is a file on
  each device (`--config_plugin=filesystem`). osquery's distributed (live) queries, file carving and extensions are
  turned off in the flags. A compromised Endpoints can refuse or forget a device; it cannot make one read anything
  else, run a command, lock it or wipe it.
- **It only reads.** Every query in the pack is a `SELECT` on tables that stay on the device; `server/pack.test.ts`
  keeps it so. The setup page shows each query and its SQL, so a device's owner can read what is collected.

## The checks

| Check | macOS | Windows | Linux |
| --- | --- | --- | --- |
| Disk encryption | FileVault on the data volume (`disk_encryption`) | BitLocker protects C: (`bitlocker_info`) | The disk that holds `/` is encrypted, such as LUKS |
| Operating system up to date | At least the policy's macOS version | At least the policy's build number | At least the policy's version for that distribution (`ubuntu 22.04, debian 12`); others are not checked |
| Firewall | The application firewall (`alf`) | Security Center reports the firewall on | Not checked: core osquery cannot read ufw or nftables |
| Screen lock | A password within the policy's minutes after sleep or the screen saver (`screenlock`) | The machine inactivity limit is set and within the policy's minutes | Not checked: core osquery cannot read the desktop's settings |

A device is **compliant** when every enabled check that applies passes. A failing check that **blocks**, disk
encryption by default, makes it **non-compliant** at once; the others leave it **at risk** for the grace period (7
days) and then make it non-compliant. A device waits as **pending** until osquery has answered every check; the checks
run every 15 minutes, the inventory and software every hour. A device that has not checked in for the policy's stale
days (7) is **stale**, and keeps what it last reported. An admin can grant an **exception**: a failing check on one
device counts as passing, for a reason, until a date within a year.

## Enrol a device

1. Under Enrolment, an admin makes an **enrolment secret** (90 days unless set). It is shown once and stored only as a
   hash. Many devices enrol with one secret; each gets a node key of its own, so revoking the secret stops new devices
   and leaves enrolled ones working.
2. Install osquery from [osquery.io/downloads](https://osquery.io/downloads) and put three files in its folder
   (`/var/osquery`, `/etc/osquery` or `C:\Program Files\osquery`): `osquery.flags` from the setup page, `osquery.conf`
   (the pack) and `enroll_secret`. The setup page has the commands for each platform; device management can roll them
   out the same way.
3. The device shows at once. A hardware UUID that is enrolled already does not enrol again, so a copied secret cannot
   take over a device's record; after osquery is reinstalled, an admin allows it once on the device's page.

osquery connects only over HTTPS, to the host of `ENDPOINTS_PUBLIC_URL`. If the proxy's certificate comes from an
internal CA, add `--tls_server_certs=<the CA file>` to `osquery.flags`.

## Run

```bash
openssl rand -hex 32 > openasy-kek
export ENDPOINTS_PUBLIC_URL=https://endpoints.example.com
docker compose up -d
docker compose logs endpoints | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080 behind your TLS proxy, the API reference at `/api/docs/`.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `ENDPOINTS_PUBLIC_URL` | `http://localhost:8080` | The `https://` address of the TLS proxy in front: people open it, and osquery connects to its host |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher |
| `ENDPOINTS_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key; Endpoints does not start without it |
| `ENDPOINTS_DB` | `/data/endpoints.db` | SQLite file (WAL), on the `/data` volume |
| `ENDPOINTS_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `ENDPOINTS_HEADLESS` | `false` | `true` serves only the API |
| `ENDPOINTS_PASSWORD_SIGN_IN`, `OPENASY_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)) |

Endpoints does not read the install's endpoints file (`OPENASY_ENDPOINTS`, ADR 0052): those are addresses Uptime and
Certificates check, not devices. Devices enrol themselves, so no file and no form lists them.

`/metrics` has `openasy_endpoints_devices{posture}`, `openasy_endpoints_devices_stale`,
`openasy_endpoints_enrolments_refused_total`, `openasy_endpoints_invalid_node_keys_total` and
`openasy_endpoints_snapshots_total`. Every enrolment, refusal, change and sign-in is in the append-only audit log and
on stdout.

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`.

## Roles

Viewers see everything; editors also set who uses a device; admins also keep the policy, exceptions and enrolment
secrets, remove devices and allow them to enrol again, and manage members and API tokens (ADR 0003).

## Not yet

Live queries and saved queries are not built, on purpose: they would let the server send a device SQL. The firewall
and screen lock on Linux, pending operating system updates, EDR and secure boot checks, more than one policy, owners
from Identity, revoking a lost laptop's VPN device, vulnerable software from Vulnerabilities, notifying owners and
exporting the inventory are planned. The Windows queries follow osquery's table schema and are tested against a
fixture, not yet against a Windows device.

## Develop

```bash
npm install
npm test        # the checks against snapshots osqueryd 5.24 sent on macOS and Debian, osquery's protocol, the pack, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
e2e/run.sh endpoints:dev   # a real osqueryd enrols through Caddy over TLS and reports (needs Docker)
```

## Licence

AGPL-3.0 (ADR 0008).
