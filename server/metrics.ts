// Prometheus text exposition, written by hand: a few lines, no client library needed.
import type { Posture } from "./posture.ts";

const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export interface Gauges {
  postures: Record<Posture, number>;
  stale: number;
  enrolmentsRefused: number;
  invalidNodeKeys: number;
  snapshots: number;
  unknownQueries: number;
}

export function renderMetrics(version: string, g: Gauges): string {
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="endpoints",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_endpoints_devices Devices by posture.",
    "# TYPE openasy_endpoints_devices gauge",
    ...Object.entries(g.postures).map(([p, n]) => `openasy_endpoints_devices{posture="${p}"} ${n}`),
    "# HELP openasy_endpoints_devices_stale Devices that have not checked in within the policy's stale days.",
    "# TYPE openasy_endpoints_devices_stale gauge",
    `openasy_endpoints_devices_stale ${g.stale}`,
    "# HELP openasy_endpoints_enrolments_refused_total Enrolments refused: an unknown, revoked or expired secret, or a device enrolled already.",
    "# TYPE openasy_endpoints_enrolments_refused_total counter",
    `openasy_endpoints_enrolments_refused_total ${g.enrolmentsRefused}`,
    "# HELP openasy_endpoints_invalid_node_keys_total Results sent with a node key Endpoints does not know.",
    "# TYPE openasy_endpoints_invalid_node_keys_total counter",
    `openasy_endpoints_invalid_node_keys_total ${g.invalidNodeKeys}`,
    "# HELP openasy_endpoints_snapshots_total Snapshots of the pack's queries received.",
    "# TYPE openasy_endpoints_snapshots_total counter",
    `openasy_endpoints_snapshots_total ${g.snapshots}`,
    "# HELP openasy_endpoints_unknown_queries_total Results of queries that are not in the pack, which are dropped.",
    "# TYPE openasy_endpoints_unknown_queries_total counter",
    `openasy_endpoints_unknown_queries_total ${g.unknownQueries}`,
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
