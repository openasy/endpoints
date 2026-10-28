// What the search window (Cmd+K) finds in Endpoints: devices by name, owner, serial and hardware UUID, and
// applications by name. They are read whole and filtered here.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { AppWindow, Laptop } from "lucide-react";
import type { Device, SoftwareTitle } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const [{ devices }, { titles }] = await Promise.all([
      call<{ devices: Device[] }>("/api/v1/devices", { signal }),
      call<{ titles: SoftwareTitle[] }>(`/api/v1/software?q=${encodeURIComponent(q)}`, { signal }),
    ]);
    const has = (...v: string[]) => v.some((x) => x.toLowerCase().includes(q));
    return [
      ...devices
        .filter((d) => has(d.name, d.hostname, d.owner, d.serial, d.uuid))
        .slice(0, 6)
        .map((d): SearchResult => ({
          id: `device:${d.id}`,
          label: d.name,
          detail: [d.owner, `${d.os.name} ${d.os.version}`].filter(Boolean).join(" · "),
          kind: t("search.device"),
          icon: Laptop,
          severity: d.posture === "non-compliant" ? "high" : d.posture === "at-risk" ? "medium" : undefined,
          href: `/devices/${d.id}`,
        })),
      ...titles.slice(0, 6).map((s): SearchResult => ({
        id: `software:${s.name}`,
        label: s.name,
        detail: t("search.onDevices", { count: s.devices }),
        kind: t("search.software"),
        icon: AppWindow,
        href: `/software?name=${encodeURIComponent(s.name)}`,
      })),
    ];
  };
}
