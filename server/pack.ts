// The query pack every device runs (osquery/osquery.conf) and the osquery flags that point a device at Endpoints
// (ADR 0065). The pack is a file on the device: Endpoints never sends a query, so a compromised Endpoints cannot make a
// device read anything else.
import { readFileSync } from "node:fs";

export interface Pack {
  decorators: { load: string[] };
  schedule: Record<string, { query: string; interval: number; platform?: string; snapshot: true; description: string }>;
}

export const PACK_TEXT = readFileSync(new URL("../osquery/osquery.conf", import.meta.url), "utf8");
export const PACK = JSON.parse(PACK_TEXT) as Pack;
/** The version the pack's decorator adds to every result, so Endpoints knows which pack a device runs. */
export const PACK_VERSION = /'(\d+)' AS endpoints_pack/.exec(PACK.decorators.load.join(" "))?.[1] ?? "";

/** Where each query's answer goes: a posture check reads it, or it replaces the device's software of one source. */
export const SOFTWARE_SOURCES: Record<string, string> = {
  endpoints_software_macos: "macos",
  endpoints_software_windows: "windows",
  endpoints_software_deb: "deb",
  endpoints_software_rpm: "rpm",
};
export const INVENTORY = "endpoints_inventory";
export const USERS = ["endpoints_users", "endpoints_users_windows"];

/** The folder osquery's installer reads its flags from, on each platform. */
const FOLDERS = { darwin: "/var/osquery", linux: "/etc/osquery", windows: "C:\\Program Files\\osquery" } as const;
export type SetupPlatform = keyof typeof FOLDERS;

/** The osquery flags file for one platform: enrol with the secret in a file, read the local pack, send results only. */
export function flagsFile(platform: SetupPlatform, publicUrl: string): string {
  const url = new URL(publicUrl);
  const dir = FOLDERS[platform];
  const sep = platform === "windows" ? "\\" : "/";
  const base = url.pathname.replace(/\/$/, "");
  return [
    `# osquery flags for OpenAsy Endpoints at ${url.origin}${base} (ADR 0065).`,
    `# The queries are in osquery.conf next to this file; Endpoints cannot send any other.`,
    "--host_identifier=uuid",
    `--tls_hostname=${url.host}`,
    `--enroll_tls_endpoint=${base}/api/v1/osquery/enroll`,
    `--enroll_secret_path=${dir}${sep}enroll_secret`,
    "--config_plugin=filesystem",
    `--config_path=${dir}${sep}osquery.conf`,
    "--logger_plugin=tls",
    `--logger_tls_endpoint=${base}/api/v1/osquery/log`,
    "--logger_tls_period=60",
    "--logger_tls_compress=true",
    "--disable_distributed=true",
    "--disable_carver=true",
    "--disable_extensions=true",
    "--disable_events=true",
    "",
  ].join("\n");
}

/** What to run on a device once the three files are in place, as root or an administrator. */
export function installSteps(platform: SetupPlatform): string {
  if (platform === "darwin")
    return [
      "# Install osquery's .pkg from https://osquery.io/downloads, then put the three files in /var/osquery:",
      "sudo install -m 600 enroll_secret /var/osquery/enroll_secret",
      "sudo install -m 644 osquery.flags osquery.conf /var/osquery/",
      "sudo cp /var/osquery/io.osquery.agent.plist /Library/LaunchDaemons/",
      "sudo launchctl bootstrap system /Library/LaunchDaemons/io.osquery.agent.plist",
      "",
    ].join("\n");
  if (platform === "linux")
    return [
      "# Install osquery's .deb or .rpm from https://osquery.io/downloads, then put the three files in /etc/osquery:",
      "sudo install -m 600 enroll_secret /etc/osquery/enroll_secret",
      "sudo install -m 644 osquery.flags osquery.conf /etc/osquery/",
      "sudo systemctl enable --now osqueryd",
      "",
    ].join("\n");
  return [
    "# Install osquery's .msi from https://osquery.io/downloads, then, in PowerShell as an administrator, next to the three files:",
    'Copy-Item osquery.flags, osquery.conf, enroll_secret "C:\\Program Files\\osquery\\"',
    'icacls "C:\\Program Files\\osquery\\enroll_secret" /inheritance:r /grant:r "SYSTEM:R" "Administrators:R"',
    "Restart-Service osqueryd",
    "",
  ].join("\n");
}
