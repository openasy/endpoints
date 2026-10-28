import {
  AppShell,
  Avatar,
  Badge,
  BarList,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  Dialog,
  EmptyState,
  FacetFilter,
  FilterBar,
  KpiCard,
  KpiGrid,
  navigate,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  SearchInput,
  SelectField,
  StackedBarChart,
  StatusBadge,
  Switch,
  Tabs,
  TextField,
  TONE_COLORS,
  toLocale,
  useAgo,
  useLocalePreference,
  usePath,
  useThemePreference,
  type Column,
  type ProductId,
  type Tone,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAccountMenu, useAuth, useInstallBrand } from "@openasy/auth/react";
import colophon from "virtual:openasy-colophon";
import {
  AppWindow,
  ClipboardCheck,
  Download,
  KeyRound,
  Laptop,
  LogIn,
  LogOut,
  Plus,
  RotateCcw,
  ScrollText,
  ShieldCheck,
  ShieldOff,
  Trash2,
  UserRound,
  Users,
  Wrench,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  CHECKS,
  MfaSetupRequired,
  Unauthorized,
  type AuditEvent,
  type CheckId,
  type CheckStats,
  type CheckStatus,
  type Compliance,
  type Device,
  type DeviceDetail,
  type EnrollSecret,
  type Install,
  type Installed,
  type Platform,
  type Policy,
  type PolicyException,
  type Posture,
  type ProductLink,
  type Setup,
  type SetupPlatform,
  type SoftwareTitle,
  type Summary,
} from "./api.ts";
import { useT, type T } from "./i18n.ts";
import { search } from "./search.ts";

const PAGES = ["compliance", "software", "policy", "setup", "audit", "account", "members", "signin", "tokens", "about"] as const;
type Route = { page: "devices" | (typeof PAGES)[number] } | { page: "device"; id: string };
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = ["devices", ...PAGES];
function parseRoute(path: string): Route {
  const [page, id] = path.replace(/^\//, "").split("/");
  if (page === "devices" && id) return { page: "device", id: decodeURIComponent(id) };
  if ((PAGES as readonly string[]).includes(page ?? "")) return { page: page as (typeof PAGES)[number] };
  return { page: "devices" };
}

/** A query parameter of the address. */
const param = (name: string) => new URLSearchParams(window.location.search).get(name);

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <R,>(path: string, init?: RequestInit): Promise<R> => {
      try {
        return await api<R>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

/** Loads one answer once and on demand. undefined while loading, null when it failed. */
function useLoad<R>(call: Call, path: string) {
  const [data, setData] = useState<R | null>();
  const load = useCallback(() => void call<R>(path).then(setData, () => setData(null)), [call, path]);
  useEffect(load, [load]);
  return [data, load] as const;
}

const when = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const date = (iso: string) => new Date(iso).toLocaleDateString(undefined, { dateStyle: "medium" });

/** Runs a change and reports its error, the way every form here does. */
function useAction(after: () => void) {
  const [error, setError] = useState<string>();
  const run = useCallback(
    async (fn: () => Promise<unknown>) => {
      try {
        await fn();
        setError(undefined);
        after();
        return true;
      } catch (err) {
        setError((err as Error).message);
        return false;
      }
    },
    [after],
  );
  return [run, error] as const;
}

/** Saves text as a file, for the files a device needs. */
function download(name: string, text: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

const POSTURE_TONE: Record<Posture, Tone> = { compliant: "success", "at-risk": "warning", "non-compliant": "danger", pending: "neutral" };
const STATUS_TONE: Record<CheckStatus, Tone> = { pass: "success", fail: "danger", unknown: "neutral", "not-applicable": "neutral" };
const PLATFORMS: Platform[] = ["darwin", "windows", "linux", "other"];

function PostureBadge({ posture }: { posture: Posture }) {
  const t = useT();
  return <StatusBadge tone={POSTURE_TONE[posture]}>{t(`postures.${posture}`)}</StatusBadge>;
}

function Code({ children, label }: { children: ReactNode; label?: string }) {
  return (
    <pre
      tabIndex={0}
      aria-label={label}
      className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs whitespace-pre-wrap break-all text-fg"
    >
      {children}
    </pre>
  );
}

function ErrorText({ message }: { message?: string }) {
  return message ? <p className="m-0 text-xs text-danger">{message}</p> : null;
}

function Owner({ owner }: { owner: string }) {
  const t = useT();
  if (!owner) return <span className="text-xs text-fg-muted">{t("devicesPage.noOwner")}</span>;
  return (
    <span className="flex min-w-0 items-center gap-2">
      <Avatar name={owner} size="sm" />
      <span className="truncate">{owner}</span>
    </span>
  );
}

function Facts({ facts }: { facts: Array<[string, ReactNode]> }) {
  return (
    <dl className="endpoints-facts text-sm">
      {facts.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-fg-muted">{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/** A check's share of the devices it applies to, for the KPI cards. */
function share(c: CheckStats | undefined) {
  if (!c) return { pct: "–", passing: 0, applies: 0 };
  const applies = c.passing + c.failing + c.excepted + c.unknown;
  return { pct: applies ? `${Math.round(((c.passing + c.excepted) / applies) * 100)}%` : "–", passing: c.passing + c.excepted, applies };
}

function CheckKpis({ checks }: { checks: CheckStats[] }) {
  const t = useT();
  return (
    <KpiGrid>
      {CHECKS.map((id) => {
        const c = checks.find((x) => x.check === id);
        const s = share(c);
        return (
          <KpiCard
            key={id}
            label={t(`checks.${id}`)}
            value={s.pct}
            unit={s.applies ? t("kpi.ofDevices", { n: s.passing, of: s.applies }) : t("kpi.noDevices")}
            tone={!c?.enabled ? "neutral" : c.failing ? (c.onFailure === "block" ? "danger" : "warning") : "success"}
            delta={
              c && !c.enabled ? { label: t("kpi.offInPolicy") } : c?.failing ? { label: t("kpi.failing", { count: c.failing }), intent: "bad" } : undefined
            }
          />
        );
      })}
    </KpiGrid>
  );
}

// ---------------------------------------------------------------- Devices

function WelcomePage({ summary }: { summary: Summary }) {
  const t = useT();
  const { can } = useAuth();
  return (
    <>
      <PageHeader title={t("welcomePage.title")} description={t("welcomePage.description")} />
      <Panel title={t("welcomePage.steps")}>
        <ol className="endpoints-steps text-sm">
          <li>{t("welcomePage.step1")}</li>
          <li>{t("welcomePage.step2")}</li>
          <li>{t("welcomePage.step3")}</li>
          <li>{t("welcomePage.step4")}</li>
        </ol>
        <div className="mt-3 flex flex-wrap gap-2">
          {can("admin") || summary.enrollSecrets ? (
            <Button variant="primary" icon={<Download />} onClick={() => navigate("/setup")}>
              {t("welcomePage.enrol")}
            </Button>
          ) : (
            <p className="m-0 text-sm text-fg-muted">{t("welcomePage.askAdmin")}</p>
          )}
        </div>
      </Panel>
      <Callout tone="info" title={t("welcomePage.readOnlyTitle")}>
        {t("welcomePage.readOnly")}
      </Callout>
    </>
  );
}

function EncryptionCell({ d }: { d: Device }) {
  const t = useT();
  const c = d.checks.find((x) => x.check === "disk-encryption");
  if (!c || c.status === "unknown") return <span className="text-xs text-fg-muted">{t("statuses.unknown")}</span>;
  if (c.status === "pass") return <span className="text-xs text-success">{t("devicesPage.encrypted")}</span>;
  if (c.status === "fail") return <span className="text-xs font-medium text-danger">{t("devicesPage.notEncrypted")}</span>;
  return <span className="text-xs text-fg-muted">{t("statuses.not-applicable")}</span>;
}

function DevicesPage({ call, summary }: { call: Call; summary: Summary }) {
  const t = useT();
  const ago = useAgo();
  const [data] = useLoad<{ devices: Device[] }>(call, "/api/v1/devices");
  const [posture, setPosture] = useState<string[]>(param("posture") ? [param("posture")!] : []);
  const [platform, setPlatform] = useState<string[]>([]);
  const [q, setQ] = useState("");
  const all = data?.devices ?? [];
  const rows = all.filter(
    (d) =>
      (posture.length === 0 || posture.includes(d.posture) || (posture.includes("stale") && d.stale)) &&
      (platform.length === 0 || platform.includes(d.platform)) &&
      (!q || `${d.name} ${d.hostname} ${d.owner} ${d.serial}`.toLowerCase().includes(q.toLowerCase())),
  );
  const columns: Column<Device>[] = [
    {
      id: "name",
      header: t("devicesPage.device"),
      mono: true,
      sortValue: (d) => d.name,
      cell: (d) => (
        <a href={`/devices/${d.id}`} className="text-fg no-underline hover:underline">
          {d.name}
        </a>
      ),
    },
    { id: "owner", header: t("devicesPage.owner"), width: "20%", sortValue: (d) => d.owner, cell: (d) => <Owner owner={d.owner} /> },
    {
      id: "os",
      header: t("devicesPage.os"),
      sortValue: (d) => `${d.os.name} ${d.os.version}`,
      cell: (d) => (
        <span className="whitespace-nowrap">
          {d.os.name || t(`platforms.${d.platform}`)} <span className="font-mono text-xs text-fg-muted">{d.os.version}</span>
        </span>
      ),
    },
    { id: "enc", header: t("checks.disk-encryption"), cell: (d) => <EncryptionCell d={d} /> },
    {
      id: "seen",
      header: t("devicesPage.lastSeen"),
      sortValue: (d) => d.lastSeenAt,
      cell: (d) => (
        <span className="flex items-center gap-1.5 whitespace-nowrap text-fg-muted">
          {ago(d.lastSeenAt)}
          {d.stale && <Badge tone="warning">{t("devicesPage.stale")}</Badge>}
        </span>
      ),
    },
    {
      id: "posture",
      header: t("devicesPage.posture"),
      sortValue: (d) => ["compliant", "pending", "at-risk", "non-compliant"].indexOf(d.posture),
      cell: (d) => (
        <span className="flex flex-col items-start gap-0.5">
          <PostureBadge posture={d.posture} />
          {d.failing[0] && <span className="text-2xs text-fg-muted">{d.failing[0].detail}</span>}
        </span>
      ),
    },
  ];
  const nonCompliant = summary.postures["non-compliant"];
  return (
    <>
      <PageHeader
        title={t("devicesPage.title")}
        description={t("devicesPage.description", { count: summary.devices })}
        meta={nonCompliant ? <StatusBadge tone="danger">{t("devicesPage.nonCompliant", { count: nonCompliant })}</StatusBadge> : undefined}
        actions={
          <Button icon={<Download />} onClick={() => navigate("/setup")}>
            {t("devicesPage.enrol")}
          </Button>
        }
      />
      <CheckKpis checks={summary.checks} />
      {summary.outdatedPack > 0 && (
        <Callout tone="warning" title={t("devicesPage.outdatedPackTitle")}>
          {t("devicesPage.outdatedPack", { count: summary.outdatedPack, version: summary.packVersion })}
        </Callout>
      )}
      <FilterBar
        onClear={
          posture.length || platform.length || q
            ? () => {
                setPosture([]);
                setPlatform([]);
                setQ("");
              }
            : undefined
        }
      >
        <FacetFilter
          label={t("devicesPage.posture")}
          selected={posture}
          onChange={setPosture}
          options={[
            ...(["compliant", "at-risk", "non-compliant", "pending"] as Posture[]).map((p) => ({
              value: p,
              label: t(`postures.${p}`),
              count: all.filter((d) => d.posture === p).length,
            })),
            { value: "stale", label: t("devicesPage.stale"), count: all.filter((d) => d.stale).length },
          ]}
        />
        <FacetFilter
          label={t("devicesPage.os")}
          selected={platform}
          onChange={setPlatform}
          options={PLATFORMS.filter((p) => all.some((d) => d.platform === p)).map((p) => ({
            value: p,
            label: t(`platforms.${p}`),
            count: all.filter((d) => d.platform === p).length,
          }))}
        />
        <SearchInput label={t("devicesPage.search")} className="w-64" value={q} onChange={(e) => setQ(e.target.value)} />
      </FilterBar>
      <Panel title={t("devicesPage.title")} description={t("devicesPage.shown", { n: rows.length, of: all.length })} flush>
        <DataTable
          label={t("devicesPage.title")}
          columns={columns}
          rows={rows}
          getRowId={(d) => d.id}
          onRowClick={(d) => navigate(`/devices/${d.id}`)}
          defaultSort={{ id: "posture", direction: "desc" }}
          loading={data === undefined}
          minWidth={880}
          pageSize={50}
          empty={<EmptyState title={t("devicesPage.none")} />}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- One device

function ExceptionDialog({ call, device, check, onClose }: { call: Call; device: DeviceDetail; check: CheckId; onClose: (changed: boolean) => void }) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [days, setDays] = useState("30");
  const [run, error] = useAction(() => onClose(true));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(() => call("/api/v1/exceptions", { method: "POST", body: JSON.stringify({ deviceId: device.id, check, reason, days: Number(days) }) }));
  };
  return (
    <Dialog
      open
      onOpenChange={(open) => !open && onClose(false)}
      title={t("devicePage.exceptionTitle", { check: t(`checks.${check}`), device: device.name })}
      description={t("devicePage.exceptionDetail")}
      onSubmit={submit}
      footer={
        <>
          <Button onClick={() => onClose(false)}>{t("common.cancel")}</Button>
          <Button type="submit" variant="primary" disabled={!reason.trim()}>
            {t("devicePage.addException")}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <TextField
          label={t("policyPage.reason")}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder={t("devicePage.reasonPlaceholder")}
          required
        />
        <SelectField
          label={t("devicePage.for")}
          value={days}
          onChange={(e) => setDays(e.target.value)}
          options={["7", "30", "90", "180", "365"].map((d) => ({ value: d, label: t("time.days", { count: Number(d) }) }))}
        />
        <ErrorText message={error} />
      </div>
    </Dialog>
  );
}

function OwnerForm({ call, device, onDone }: { call: Call; device: DeviceDetail; onDone: () => void }) {
  const t = useT();
  const [owner, setOwner] = useState(device.owner);
  const [run, error] = useAction(onDone);
  return (
    <form
      className="flex flex-wrap items-end gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        void run(() => call(`/api/v1/devices/${device.id}`, { method: "PUT", body: JSON.stringify({ owner }) }));
      }}
    >
      <TextField
        label={<span className="sr-only">{t("devicesPage.owner")}</span>}
        value={owner}
        onChange={(e) => setOwner(e.target.value)}
        placeholder={t("devicePage.ownerPlaceholder")}
      />
      <Button type="submit" size="md" disabled={owner === device.owner}>
        {t("common.save")}
      </Button>
      <ErrorText message={error} />
    </form>
  );
}

function DevicePage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const t = useT();
  const ago = useAgo();
  const { can } = useAuth();
  const [d, load] = useLoad<DeviceDetail>(call, `/api/v1/devices/${encodeURIComponent(id)}`);
  const [software] = useLoad<{ software: Installed[] }>(call, `/api/v1/devices/${encodeURIComponent(id)}/software`);
  const [q, setQ] = useState("");
  const [excepting, setExcepting] = useState<CheckId>();
  const [removing, setRemoving] = useState(false);
  const after = useCallback(() => {
    load();
    reload();
  }, [load, reload]);
  const [run, error] = useAction(after);
  if (d === null)
    return (
      <EmptyState title={t("devicePage.notFound")} action={<Button onClick={() => navigate("/")}>{t("devicePage.back")}</Button>}>
        {t("devicePage.notFoundDetail")}
      </EmptyState>
    );
  if (!d) return <EmptyState title={t("product.loading")} icon={<Laptop />} />;
  const memory = d.hardware.memoryBytes ? `${Math.round(d.hardware.memoryBytes / 2 ** 30)} GiB` : "";
  const facts: Array<[string, ReactNode]> = [
    [t("devicesPage.owner"), can("editor") ? <OwnerForm key={d.owner} call={call} device={d} onDone={after} /> : <Owner key="o" owner={d.owner} />],
    [t("devicesPage.os"), `${d.os.name} ${d.os.version}${d.os.build ? ` (${d.os.build})` : ""}`],
    [t("devicePage.hardware"), [d.hardware.vendor, d.hardware.model, d.hardware.cpu, memory].filter(Boolean).join(" · ") || "–"],
    [
      t("devicePage.serial"),
      <span key="s" className="font-mono">
        {d.serial || "–"}
      </span>,
    ],
    [
      t("devicePage.uuid"),
      <span key="u" className="font-mono text-xs">
        {d.uuid}
      </span>,
    ],
    [
      t("devicePage.hostname"),
      <span key="h" className="font-mono">
        {d.hostname || "–"}
      </span>,
    ],
    [t("devicePage.osquery"), t("devicePage.osqueryDetail", { version: d.osqueryVersion || "–", pack: d.packVersion || "–" })],
    [t("devicePage.enrolled"), `${when(d.enrolledAt)}${d.enrollSecret ? ` · ${d.enrollSecret.name}` : ""}`],
    [t("devicesPage.lastSeen"), `${when(d.lastSeenAt)} (${ago(d.lastSeenAt)})`],
  ];
  const checkColumns: Column<DeviceDetail["checks"][number]>[] = [
    {
      id: "check",
      header: t("compliancePage.check"),
      width: "22%",
      cell: (c) => (
        <span className="flex min-w-0 flex-col">
          <span className="font-medium">{t(`checks.${c.check}`)}</span>
          {!c.enabled && <span className="text-2xs text-fg-muted">{t("kpi.offInPolicy")}</span>}
        </span>
      ),
    },
    {
      id: "status",
      header: t("devicePage.status"),
      width: "130px",
      cell: (c) =>
        c.status === "fail" && c.exception ? (
          <Badge tone="info">{t("devicePage.excepted")}</Badge>
        ) : (
          <StatusBadge tone={STATUS_TONE[c.status]}>{t(`statuses.${c.status}`)}</StatusBadge>
        ),
    },
    {
      id: "detail",
      header: t("devicePage.detail"),
      cell: (c) => (
        <span className="flex min-w-0 flex-col">
          <span className="text-sm">{c.detail}</span>
          {c.exception && (
            <span className="text-2xs text-fg-muted">{t("devicePage.exceptionUntil", { reason: c.exception.reason, date: date(c.exception.expiresAt) })}</span>
          )}
        </span>
      ),
    },
    {
      id: "since",
      header: t("devicePage.since"),
      width: "130px",
      cell: (c) => <span className="whitespace-nowrap text-xs text-fg-muted">{ago(c.since)}</span>,
    },
    {
      id: "act",
      header: <span className="sr-only">{t("common.actions")}</span>,
      label: t("common.actions"),
      width: "130px",
      align: "right",
      hideable: false,
      cell: (c) =>
        can("admin") &&
        c.status === "fail" &&
        !c.exception && (
          <Button size="xs" icon={<ShieldOff />} onClick={() => setExcepting(c.check)}>
            {t("devicePage.except")}
          </Button>
        ),
    },
  ];
  const shown = (software?.software ?? []).filter((s) => !q || `${s.name} ${s.publisher}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      <PageHeader
        title={d.name}
        breadcrumbs={[{ label: t("devicesPage.title"), href: "/" }, { label: d.name }]}
        description={d.failing[0]?.detail ?? t(`postureDetail.${d.posture}`)}
        meta={
          <>
            <PostureBadge posture={d.posture} />
            {d.stale && <Badge tone="warning">{t("devicesPage.stale")}</Badge>}
          </>
        }
        actions={
          can("admin") && (
            <>
              <Button
                icon={<RotateCcw />}
                disabled={!!d.reenrollUntil}
                onClick={() => void run(() => call(`/api/v1/devices/${d.id}/reenroll`, { method: "POST" }))}
              >
                {d.reenrollUntil ? t("devicePage.reenrolAllowed") : t("devicePage.reenrol")}
              </Button>
              <Button variant="danger" icon={<Trash2 />} onClick={() => setRemoving(true)}>
                {t("devicePage.remove")}
              </Button>
            </>
          )
        }
      />
      <ErrorText message={error} />
      {d.reenrollUntil && (
        <Callout tone="info" title={t("devicePage.reenrolTitle")}>
          {t("devicePage.reenrolDetail", { date: when(d.reenrollUntil) })}
        </Callout>
      )}
      <Panel title={t("devicePage.checks")} description={t("devicePage.checksDetail")} flush>
        <DataTable label={t("devicePage.checks")} columns={checkColumns} rows={d.checks} getRowId={(c) => c.check} minWidth={760} />
      </Panel>
      <div className="endpoints-split">
        <Panel title={t("devicePage.device")}>
          <Facts facts={facts} />
        </Panel>
        <Panel title={t("devicePage.users")} description={t("devicePage.usersDetail")} flush>
          <DataTable
            label={t("devicePage.users")}
            columns={[
              { id: "username", header: t("devicePage.username"), mono: true, cell: (u) => u.username },
              { id: "name", header: t("devicePage.name"), cell: (u) => u.description },
              { id: "uid", header: "UID", width: "80px", mono: true, align: "right", cell: (u) => u.uid },
            ]}
            rows={d.users}
            getRowId={(u) => `${u.uid}:${u.username}`}
            empty={<EmptyState title={t("devicePage.noUsers")} />}
          />
        </Panel>
      </div>
      <Panel
        title={t("devicePage.software")}
        description={t("devicePage.softwareCount", { count: d.software })}
        actions={<SearchInput label={t("softwarePage.search")} className="w-56" value={q} onChange={(e) => setQ(e.target.value)} />}
        flush
      >
        <DataTable
          label={t("devicePage.software")}
          columns={[
            {
              id: "name",
              header: t("softwarePage.application"),
              sortValue: (s) => s.name,
              cell: (s) => (
                <a href={`/software?name=${encodeURIComponent(s.name)}`} className="text-fg no-underline hover:underline">
                  {s.name}
                </a>
              ),
            },
            { id: "version", header: t("softwarePage.version"), mono: true, cell: (s) => s.version },
            { id: "publisher", header: t("softwarePage.publisher"), cell: (s) => <span className="text-xs">{s.publisher}</span> },
            { id: "source", header: t("softwarePage.source"), width: "90px", cell: (s) => <Badge mono>{s.source}</Badge> },
          ]}
          rows={shown}
          getRowId={(s) => `${s.source}:${s.name}:${s.version}:${s.path}`}
          loading={software === undefined}
          pageSize={25}
          minWidth={640}
          empty={<EmptyState title={t("devicePage.noSoftware")} />}
        />
      </Panel>
      {excepting && (
        <ExceptionDialog
          call={call}
          device={d}
          check={excepting}
          onClose={(changed) => {
            setExcepting(undefined);
            if (changed) after();
          }}
        />
      )}
      <Dialog
        open={removing}
        onOpenChange={setRemoving}
        title={t("devicePage.removeTitle", { device: d.name })}
        description={t("devicePage.removeDetail")}
        footer={
          <>
            <Button onClick={() => setRemoving(false)}>{t("common.cancel")}</Button>
            <Button
              variant="danger"
              icon={<Trash2 />}
              onClick={() =>
                void run(async () => {
                  await call(`/api/v1/devices/${d.id}`, { method: "DELETE" });
                  navigate("/");
                })
              }
            >
              {t("devicePage.remove")}
            </Button>
          </>
        }
      />
    </>
  );
}

// ---------------------------------------------------------------- Compliance

function CompliancePage({ call, summary }: { call: Call; summary: Summary }) {
  const t = useT();
  const ago = useAgo();
  const [c] = useLoad<Compliance>(call, "/api/v1/compliance");
  const [check, setCheck] = useState<CheckId | null>(null);
  if (!c) return <EmptyState title={t("product.loading")} icon={<ClipboardCheck />} />;
  const rows = c.failing.filter((f) => !check || f.check === check);
  const total = summary.devices;
  const compliant = summary.postures.compliant;
  const graceLeft = (iso: string | null, blocked: boolean) => {
    if (!iso) return t("compliancePage.noGrace");
    if (blocked) return t("compliancePage.graceOver");
    return t("compliancePage.graceEnds", { count: Math.max(1, Math.ceil((Date.parse(iso) - Date.now()) / 86_400_000)) });
  };
  const checkColumns: Column<CheckStats>[] = [
    {
      id: "name",
      header: t("compliancePage.check"),
      width: "34%",
      cell: (x) => (
        <span className="flex min-w-0 flex-col">
          <span className="font-medium">{t(`checks.${x.check}`)}</span>
          <span className="text-2xs text-fg-muted">{t(`checkDetail.${x.check}`)}</span>
        </span>
      ),
    },
    {
      id: "pass",
      header: t("compliancePage.passing"),
      align: "right",
      sortValue: (x) => share(x).passing,
      cell: (x) => <span className="font-mono text-xs">{x.enabled ? share(x).pct : "–"}</span>,
    },
    {
      id: "failing",
      header: t("compliancePage.failing"),
      align: "right",
      mono: true,
      sortValue: (x) => x.failing,
      cell: (x) => <span className={x.failing ? "text-danger" : "text-fg-muted"}>{x.failing}</span>,
    },
    {
      id: "na",
      header: t("compliancePage.notChecked"),
      description: t("compliancePage.notCheckedDetail"),
      align: "right",
      mono: true,
      cell: (x) => <span className="text-fg-muted">{x.notApplicable + x.unknown}</span>,
    },
    {
      id: "rule",
      header: t("compliancePage.onFailure"),
      description: t("compliancePage.onFailureDetail"),
      cell: (x) =>
        !x.enabled ? (
          <Badge>{t("kpi.offInPolicy")}</Badge>
        ) : x.onFailure === "block" ? (
          <Badge tone="danger">{t("onFailure.block")}</Badge>
        ) : (
          <Badge tone="warning">{t("onFailure.grace")}</Badge>
        ),
    },
  ];
  const failingColumns: Column<Compliance["failing"][number]>[] = [
    {
      id: "device",
      header: t("devicesPage.device"),
      mono: true,
      sortValue: (f) => f.device.name,
      cell: (f) => (
        <a href={`/devices/${f.device.id}`} className="text-fg no-underline hover:underline">
          {f.device.name}
        </a>
      ),
    },
    { id: "owner", header: t("devicesPage.owner"), width: "20%", cell: (f) => <Owner owner={f.device.owner} /> },
    {
      id: "check",
      header: t("compliancePage.failingCheck"),
      cell: (f) => (
        <span className="flex min-w-0 flex-col">
          <span>{t(`checks.${f.check}`)}</span>
          <span className="text-2xs text-fg-muted">{f.detail}</span>
        </span>
      ),
    },
    {
      id: "since",
      header: t("compliancePage.failingFor"),
      sortValue: (f) => f.since,
      cell: (f) => <span className="text-xs whitespace-nowrap">{ago(f.since)}</span>,
    },
    {
      id: "grace",
      header: t("compliancePage.grace"),
      cell: (f) => <span className={f.blocked ? "text-xs text-danger" : "text-xs"}>{graceLeft(f.graceEndsAt, f.blocked)}</span>,
    },
    {
      id: "state",
      header: t("devicesPage.posture"),
      cell: (f) =>
        f.blocked ? <StatusBadge tone="danger">{t("postures.non-compliant")}</StatusBadge> : <StatusBadge tone="warning">{t("postures.at-risk")}</StatusBadge>,
    },
  ];
  return (
    <>
      <PageHeader
        title={t("compliancePage.title")}
        description={t("compliancePage.description")}
        meta={
          total ? (
            <StatusBadge tone={compliant === total ? "success" : "warning"}>{t("compliancePage.compliantOf", { n: compliant, of: total })}</StatusBadge>
          ) : undefined
        }
      />
      <KpiGrid>
        <KpiCard
          label={t("postures.compliant")}
          value={total ? `${Math.round((compliant / total) * 100)}%` : "–"}
          unit={t("kpi.ofDevices", { n: compliant, of: total })}
          tone="success"
        />
        <KpiCard
          label={t("postures.non-compliant")}
          value={summary.postures["non-compliant"]}
          unit={t("kpi.devices")}
          tone="danger"
          href="/?posture=non-compliant"
        />
        <KpiCard label={t("compliancePage.inGrace")} value={summary.postures["at-risk"]} unit={t("kpi.devices")} tone="warning" href="/?posture=at-risk" />
        <KpiCard label={t("devicesPage.stale")} value={summary.stale} unit={t("kpi.devices")} href="/?posture=stale" />
      </KpiGrid>
      <div className="endpoints-split">
        <Panel title={t("compliancePage.checks")} description={t("compliancePage.checksDetail")} flush>
          <DataTable
            label={t("compliancePage.checks")}
            columns={checkColumns}
            rows={c.checks}
            getRowId={(x) => x.check}
            onRowClick={(x) => setCheck(check === x.check ? null : x.check)}
            activeRowId={check ?? undefined}
            minWidth={640}
          />
        </Panel>
        <Panel title={t("compliancePage.byOs")} description={t("compliancePage.byOsDetail")}>
          <StackedBarChart
            label={t("compliancePage.byOs")}
            categories={c.platforms.map((p) => t(`platforms.${p.platform}`))}
            segments={[
              { id: "ok", name: t("postures.compliant"), color: TONE_COLORS.success },
              { id: "risk", name: t("postures.at-risk"), color: TONE_COLORS.warning },
              { id: "bad", name: t("postures.non-compliant"), color: TONE_COLORS.danger },
              { id: "wait", name: t("postures.pending"), color: TONE_COLORS.neutral },
            ]}
            values={c.platforms.map((p) => [p.compliant, p["at-risk"], p["non-compliant"], p.pending])}
            xTicks={c.platforms.length}
            height={180}
          />
        </Panel>
      </div>
      <Panel
        title={t("compliancePage.failingDevices")}
        description={check ? t("compliancePage.failingOne", { check: t(`checks.${check}`) }) : t("compliancePage.failingAll", { count: c.failing.length })}
        actions={
          check && (
            <Button size="sm" variant="ghost" onClick={() => setCheck(null)}>
              {t("compliancePage.showAll")}
            </Button>
          )
        }
        flush
      >
        <DataTable
          label={t("compliancePage.failingDevices")}
          columns={failingColumns}
          rows={rows}
          getRowId={(f) => `${f.device.id}:${f.check}`}
          minWidth={900}
          pageSize={50}
          empty={<EmptyState title={t("compliancePage.noneFailing")} />}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Software

function SoftwarePage({ call }: { call: Call }) {
  const t = useT();
  const [q, setQ] = useState(param("name") ?? "");
  const [platform, setPlatform] = useState<string[]>([]);
  const [tab, setTab] = useState<"all" | "behind">("all");
  const [data, setData] = useState<{ total: number; titles: SoftwareTitle[] }>();
  const [active, setActive] = useState<string | null>(param("name"));
  const [installs, setInstalls] = useState<Install[]>();
  useEffect(() => {
    const ctl = new AbortController();
    const timer = setTimeout(() => {
      const qs = new URLSearchParams({ ...(q && { q }), ...(platform.length === 1 && { platform: platform[0]! }) });
      void call<{ total: number; titles: SoftwareTitle[] }>(`/api/v1/software?${qs}`, { signal: ctl.signal }).then(setData, () => {});
    }, 200);
    return () => (clearTimeout(timer), ctl.abort());
  }, [call, q, platform]);
  useEffect(() => {
    if (!active) return setInstalls(undefined);
    void call<{ installs: Install[] }>(`/api/v1/software/installs?name=${encodeURIComponent(active)}`).then(
      (r) => setInstalls(r.installs),
      () => setInstalls([]),
    );
  }, [call, active]);
  const titles = data?.titles ?? [];
  const rows = titles.filter((s) => tab === "all" || s.notOnNewest > 0);
  const cur = titles.find((s) => s.name === active);
  const columns: Column<SoftwareTitle>[] = [
    {
      id: "name",
      header: t("softwarePage.application"),
      width: "30%",
      sortValue: (s) => s.name,
      cell: (s) => (
        <span className="flex min-w-0 flex-col">
          <span className="truncate font-medium">{s.name}</span>
          <span className="truncate text-2xs text-fg-muted">
            {[s.publisher, s.platforms.map((p) => t(`platforms.${p as Platform}`)).join(", ")].filter(Boolean).join(" · ")}
          </span>
        </span>
      ),
    },
    { id: "devices", header: t("kpi.devices"), align: "right", mono: true, sortValue: (s) => s.devices, cell: (s) => s.devices },
    { id: "versions", header: t("softwarePage.versions"), align: "right", mono: true, sortValue: (s) => s.versions.length, cell: (s) => s.versions.length },
    { id: "newest", header: t("softwarePage.newest"), mono: true, cell: (s) => s.newest },
    {
      id: "behind",
      header: t("softwarePage.behind"),
      description: t("softwarePage.behindDetail"),
      align: "right",
      sortValue: (s) => s.notOnNewest,
      cell: (s) => <span className={s.notOnNewest ? "font-mono text-warning" : "font-mono text-fg-muted"}>{s.notOnNewest}</span>,
    },
  ];
  return (
    <>
      <PageHeader title={t("softwarePage.title")} description={t("softwarePage.description")}>
        <Tabs
          label={t("softwarePage.filter")}
          value={tab}
          onChange={setTab}
          items={[
            { value: "all", label: t("softwarePage.all"), count: titles.length },
            { value: "behind", label: t("softwarePage.behind"), count: titles.filter((s) => s.notOnNewest > 0).length },
          ]}
        />
      </PageHeader>
      <FilterBar onClear={q || platform.length ? () => (setQ(""), setPlatform([])) : undefined}>
        <SearchInput label={t("softwarePage.search")} className="w-64" value={q} onChange={(e) => setQ(e.target.value)} />
        <FacetFilter
          label={t("devicesPage.os")}
          selected={platform}
          onChange={(v) => setPlatform(v.slice(-1))}
          options={(["darwin", "windows", "linux"] as const).map((p) => ({ value: p, label: t(`platforms.${p}`) }))}
        />
      </FilterBar>
      <div className="endpoints-split">
        <Panel title={t("softwarePage.inventory")} description={data ? t("softwarePage.shown", { n: rows.length, of: data.total }) : undefined} flush>
          <DataTable
            label={t("softwarePage.inventory")}
            columns={columns}
            rows={rows}
            getRowId={(s) => s.name}
            onRowClick={(s) => setActive(s.name)}
            activeRowId={active ?? undefined}
            loading={!data}
            pageSize={50}
            minWidth={720}
            empty={<EmptyState title={t("softwarePage.none")}>{t("softwarePage.noneDetail")}</EmptyState>}
          />
        </Panel>
        <Panel
          title={cur?.name ?? t("softwarePage.pick")}
          description={cur ? t("softwarePage.versionsOf", { newest: cur.newest }) : undefined}
          aria-label={t("softwarePage.detail")}
        >
          {cur ? (
            <div className="flex flex-col gap-3">
              <BarList
                label={t("softwarePage.versionsLabel", { name: cur.name })}
                items={cur.versions.map((v) => ({
                  id: v.version,
                  label: v.version || "–",
                  value: v.devices,
                  color: v.version === cur.newest ? TONE_COLORS.success : TONE_COLORS.warning,
                }))}
              />
              <DataTable
                label={t("softwarePage.where")}
                columns={[
                  {
                    id: "device",
                    header: t("devicesPage.device"),
                    mono: true,
                    cell: (i) => (
                      <a href={`/devices/${i.device.id}`} className="text-fg no-underline hover:underline">
                        {i.device.name}
                      </a>
                    ),
                  },
                  { id: "version", header: t("softwarePage.version"), mono: true, cell: (i) => i.version },
                  { id: "owner", header: t("devicesPage.owner"), cell: (i) => <span className="text-xs">{i.device.owner}</span> },
                ]}
                rows={installs ?? []}
                getRowId={(i) => `${i.device.id}:${i.version}:${i.path}`}
                loading={installs === undefined}
                pageSize={10}
              />
            </div>
          ) : (
            <p className="m-0 text-sm text-fg-muted">{t("softwarePage.pickDetail")}</p>
          )}
        </Panel>
      </div>
    </>
  );
}

// ---------------------------------------------------------------- Policy

const WINDOWS_BUILDS = [
  { value: "19045", label: "Windows 10 22H2 (19045)" },
  { value: "22621", label: "Windows 11 22H2 (22621)" },
  { value: "22631", label: "Windows 11 23H2 (22631)" },
  { value: "26100", label: "Windows 11 24H2 (26100)" },
  { value: "26200", label: "Windows 11 25H2 (26200)" },
];

const linuxText = (m: Record<string, string>) =>
  Object.entries(m)
    .map(([k, v]) => `${k} ${v}`)
    .join(", ");
const parseLinux = (s: string) =>
  Object.fromEntries(
    s
      .split(",")
      .map((x) => x.trim().split(/\s+/))
      .filter((x) => x.length === 2 && x[0] && x[1])
      .map(([k, v]) => [k!.toLowerCase(), v!]),
  );

function PolicyForm({ call, policy, onSaved }: { call: Call; policy: Policy; onSaved: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const admin = can("admin");
  const [p, setP] = useState(policy);
  const [linux, setLinux] = useState(linuxText(policy.minimum.linux));
  const [saved, setSaved] = useState("");
  const [run, error] = useAction(onSaved);
  const set = (change: Partial<Policy>) => (setP((x) => ({ ...x, ...change })), setSaved(""));
  const rule = (id: CheckId, change: Partial<Policy["checks"][CheckId]>) => set({ checks: { ...p.checks, [id]: { ...p.checks[id], ...change } } });
  const builds = WINDOWS_BUILDS.some((b) => Number(b.value) === p.minimum.windowsBuild)
    ? WINDOWS_BUILDS
    : [...WINDOWS_BUILDS, { value: String(p.minimum.windowsBuild), label: String(p.minimum.windowsBuild) }];
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const body = { ...p, minimum: { ...p.minimum, linux: parseLinux(linux) }, updatedAt: undefined, updatedBy: undefined };
    if (await run(() => call("/api/v1/policy", { method: "PUT", body: JSON.stringify(body) }))) setSaved(t("policyPage.saved"));
  };
  return (
    <form className="flex flex-col gap-2.5" onSubmit={(e) => void submit(e)}>
      <div className="endpoints-split">
        <Panel title={t("policyPage.requirements")} description={t("policyPage.requirementsDetail")}>
          <fieldset disabled={!admin} className="m-0 flex flex-col gap-3 border-0 p-0">
            <div className="endpoints-cols">
              <TextField
                label={t("policyPage.minMacos")}
                value={p.minimum.macos}
                onChange={(e) => set({ minimum: { ...p.minimum, macos: e.target.value } })}
                mono
              />
              <SelectField
                label={t("policyPage.minWindows")}
                value={String(p.minimum.windowsBuild)}
                onChange={(e) => set({ minimum: { ...p.minimum, windowsBuild: Number(e.target.value) } })}
                options={builds}
              />
              <TextField
                label={t("policyPage.minLinux")}
                hint={t("policyPage.minLinuxHint")}
                value={linux}
                onChange={(e) => (setLinux(e.target.value), setSaved(""))}
                mono
              />
            </div>
            <div className="endpoints-cols">
              <SelectField
                label={t("policyPage.screenLock")}
                value={String(p.screenLockMinutes)}
                onChange={(e) => set({ screenLockMinutes: Number(e.target.value) })}
                options={[1, 2, 5, 10, 15, 30].map((m) => ({ value: String(m), label: t("time.minutes", { count: m }) }))}
              />
              <SelectField
                label={t("policyPage.grace")}
                value={String(p.graceDays)}
                onChange={(e) => set({ graceDays: Number(e.target.value) })}
                options={[0, 3, 7, 14, 30].map((d) => ({ value: String(d), label: d ? t("time.days", { count: d }) : t("policyPage.noGrace") }))}
              />
              <SelectField
                label={t("policyPage.stale")}
                value={String(p.staleDays)}
                onChange={(e) => set({ staleDays: Number(e.target.value) })}
                options={[1, 3, 7, 14, 30].map((d) => ({ value: String(d), label: t("time.days", { count: d }) }))}
              />
            </div>
          </fieldset>
        </Panel>
        <Panel title={t("policyPage.checks")} description={t("policyPage.checksDetail")}>
          <div className="flex flex-col gap-3">
            {CHECKS.map((id) => (
              <div key={id} className="flex flex-wrap items-center justify-between gap-2">
                <Switch
                  checked={p.checks[id].enabled}
                  onCheckedChange={(v) => rule(id, { enabled: v })}
                  label={t(`checks.${id}`)}
                  description={t(`checkDetail.${id}`)}
                  disabled={!admin}
                />
                <SelectField
                  aria-label={t("policyPage.onFailureOf", { check: t(`checks.${id}`) })}
                  value={p.checks[id].onFailure}
                  onChange={(e) => rule(id, { onFailure: e.target.value as "block" | "grace" })}
                  disabled={!admin || !p.checks[id].enabled}
                  options={[
                    { value: "block", label: t("onFailure.block") },
                    { value: "grace", label: t("onFailure.grace") },
                  ]}
                />
              </div>
            ))}
          </div>
        </Panel>
      </div>
      {admin ? (
        <div className="flex flex-wrap items-center gap-2">
          <Button type="submit" variant="primary" icon={<ShieldCheck />}>
            {t("policyPage.save")}
          </Button>
          {saved && (
            <span role="status" className="text-xs text-success">
              {saved}
            </span>
          )}
          <ErrorText message={error} />
        </div>
      ) : (
        <p className="m-0 text-xs text-fg-muted">{t("policyPage.adminsChange")}</p>
      )}
    </form>
  );
}

function PolicyPage({ call, reload }: { call: Call; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [policy, loadPolicy] = useLoad<Policy>(call, "/api/v1/policy");
  const [exceptions, loadExceptions] = useLoad<{ exceptions: PolicyException[] }>(call, "/api/v1/exceptions");
  const after = useCallback(() => {
    loadPolicy();
    loadExceptions();
    reload();
  }, [loadPolicy, loadExceptions, reload]);
  const [run, error] = useAction(after);
  if (!policy) return <EmptyState title={t("product.loading")} icon={<ShieldCheck />} />;
  return (
    <>
      <PageHeader
        title={t("policyPage.title")}
        description={policy.updatedAt ? t("policyPage.updated", { by: policy.updatedBy ?? "", when: when(policy.updatedAt) }) : t("policyPage.description")}
      />
      <PolicyForm key={policy.updatedAt ?? "default"} call={call} policy={policy} onSaved={after} />
      <Panel title={t("policyPage.exceptions")} description={t("policyPage.exceptionsDetail")} flush>
        <ErrorText message={error} />
        <DataTable
          label={t("policyPage.exceptions")}
          rows={exceptions?.exceptions ?? []}
          getRowId={(x) => x.id}
          loading={exceptions === undefined}
          minWidth={760}
          empty={<EmptyState title={t("policyPage.noExceptions")}>{t("policyPage.noExceptionsDetail")}</EmptyState>}
          columns={[
            {
              id: "device",
              header: t("devicesPage.device"),
              mono: true,
              cell: (x) => (
                <a href={`/devices/${x.device.id}`} className="text-fg no-underline hover:underline">
                  {x.device.name}
                </a>
              ),
            },
            { id: "check", header: t("compliancePage.check"), cell: (x) => t(`checks.${x.check}`) },
            { id: "reason", header: t("policyPage.reason"), width: "32%", cell: (x) => <span className="text-xs">{x.reason}</span> },
            { id: "by", header: t("policyPage.approvedBy"), cell: (x) => <span className="text-xs">{x.createdBy}</span> },
            {
              id: "expires",
              header: t("policyPage.expires"),
              cell: (x) => (x.active ? <span className="text-xs">{date(x.expiresAt)}</span> : <Badge>{t("policyPage.ended")}</Badge>),
            },
            {
              id: "act",
              header: <span className="sr-only">{t("common.actions")}</span>,
              label: t("common.actions"),
              width: "90px",
              align: "right",
              hideable: false,
              cell: (x) =>
                can("admin") &&
                x.active && (
                  <Button
                    size="xs"
                    aria-label={t("policyPage.endFor", { device: x.device.name })}
                    onClick={() => void run(() => call(`/api/v1/exceptions/${x.id}`, { method: "DELETE" }))}
                  >
                    {t("policyPage.end")}
                  </Button>
                ),
            },
          ]}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Setup: enrolment

const SETUP_PLATFORMS: SetupPlatform[] = ["darwin", "linux", "windows"];

function SetupPage({ call, reload }: { call: Call; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [setup] = useLoad<Setup>(call, "/api/v1/setup");
  const [secrets, loadSecrets] = useLoad<{ secrets: EnrollSecret[] }>(call, "/api/v1/enroll-secrets");
  const [platform, setPlatform] = useState<SetupPlatform>("darwin");
  const [name, setName] = useState("");
  const [days, setDays] = useState("90");
  const [made, setMade] = useState<string>();
  const after = useCallback(() => {
    loadSecrets();
    reload();
  }, [loadSecrets, reload]);
  const [run, error] = useAction(after);
  const pack = useMemo(() => {
    if (!setup) return [];
    const p = JSON.parse(setup.pack) as { schedule: Record<string, { query: string; interval: number; platform?: string; description: string }> };
    return Object.entries(p.schedule).map(([id, q]) => ({ id, ...q }));
  }, [setup]);
  const create = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const r = await call<{ secret: string }>("/api/v1/enroll-secrets", { method: "POST", body: JSON.stringify({ name, expiresInDays: Number(days) }) });
      setMade(r.secret);
      setName("");
    });
  };
  const ago = useAgo();
  const packPlatform = (p?: string) =>
    !p ? t("setupPage.allPlatforms") : p === "posix" ? `${t("platforms.darwin")}, ${t("platforms.linux")}` : t(`platforms.${p as Platform}`);
  return (
    <>
      <PageHeader title={t("setupPage.title")} description={t("setupPage.description")} />
      {setup && !setup.https && (
        <Callout tone="warning" title={t("setupPage.httpsTitle")}>
          {t("setupPage.https", { url: setup.publicUrl })}
        </Callout>
      )}
      <Panel title={t("setupPage.secrets")} description={t("setupPage.secretsDetail")} flush>
        {can("admin") && (
          <form className="flex flex-wrap items-end gap-2 px-3 py-2.5" onSubmit={create}>
            <TextField
              label={t("setupPage.secretName")}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t("setupPage.secretNamePlaceholder")}
              required
            />
            <SelectField
              label={t("setupPage.expires")}
              value={days}
              onChange={(e) => setDays(e.target.value)}
              options={["30", "90", "180", "365"].map((d) => ({ value: d, label: t("time.days", { count: Number(d) }) }))}
            />
            <Button type="submit" variant="primary" size="md" icon={<Plus />} disabled={!name.trim()}>
              {t("setupPage.make")}
            </Button>
            <ErrorText message={error} />
          </form>
        )}
        {made && (
          <div className="px-3 pb-2.5">
            <Callout tone="success" title={t("setupPage.madeTitle")}>
              <div className="flex flex-col gap-2">
                <span>{t("setupPage.made")}</span>
                <Code label={t("setupPage.secret")}>{made}</Code>
                <div>
                  <Button size="sm" icon={<Download />} onClick={() => download("enroll_secret", made)}>
                    enroll_secret
                  </Button>
                </div>
              </div>
            </Callout>
          </div>
        )}
        <DataTable
          label={t("setupPage.secrets")}
          rows={secrets?.secrets ?? []}
          getRowId={(s) => s.id}
          loading={secrets === undefined}
          minWidth={760}
          empty={<EmptyState title={t("setupPage.noSecrets")}>{can("admin") ? t("setupPage.noSecretsAdmin") : t("setupPage.noSecretsDetail")}</EmptyState>}
          columns={[
            {
              id: "name",
              header: t("setupPage.secretName"),
              cell: (s) => (
                <span className="flex min-w-0 flex-col">
                  <span className="font-medium">{s.name}</span>
                  <span className="font-mono text-2xs text-fg-muted">{s.fingerprint}</span>
                </span>
              ),
            },
            {
              id: "status",
              header: t("devicePage.status"),
              cell: (s) => <StatusBadge tone={s.status === "active" ? "success" : "neutral"}>{t(`secretStatus.${s.status}`)}</StatusBadge>,
            },
            { id: "devices", header: t("kpi.devices"), align: "right", mono: true, cell: (s) => s.devices },
            { id: "used", header: t("setupPage.lastUsed"), cell: (s) => <span className="text-xs text-fg-muted">{ago(s.lastUsedAt)}</span> },
            { id: "expires", header: t("setupPage.expires"), cell: (s) => <span className="text-xs">{s.expiresAt ? date(s.expiresAt) : "–"}</span> },
            {
              id: "act",
              header: <span className="sr-only">{t("common.actions")}</span>,
              label: t("common.actions"),
              width: "100px",
              align: "right",
              hideable: false,
              cell: (s) =>
                can("admin") &&
                s.status === "active" && (
                  <Button
                    size="xs"
                    variant="danger"
                    aria-label={t("setupPage.revokeOf", { name: s.name })}
                    onClick={() => void run(() => call(`/api/v1/enroll-secrets/${s.id}/revoke`, { method: "POST" }))}
                  >
                    {t("setupPage.revoke")}
                  </Button>
                ),
            },
          ]}
        />
      </Panel>
      {setup && (
        <Panel
          title={t("setupPage.device")}
          description={t("setupPage.deviceDetail")}
          actions={
            <Tabs
              label={t("setupPage.platform")}
              value={platform}
              onChange={setPlatform}
              items={SETUP_PLATFORMS.map((p) => ({ value: p, label: t(`platforms.${p}`) }))}
            />
          }
        >
          <div className="flex flex-col gap-3">
            <ol className="endpoints-steps text-sm">
              <li>{t("setupPage.step1")}</li>
              <li>{t("setupPage.step2")}</li>
              <li>{t("setupPage.step3")}</li>
            </ol>
            <div className="flex flex-wrap gap-2">
              <Button icon={<Download />} onClick={() => download("osquery.flags", setup.platforms[platform].flags)}>
                osquery.flags
              </Button>
              <Button icon={<Download />} onClick={() => download("osquery.conf", setup.pack)}>
                osquery.conf
              </Button>
            </div>
            <Code label="osquery.flags">{setup.platforms[platform].flags}</Code>
            <Code label={t("setupPage.steps")}>{setup.platforms[platform].steps}</Code>
            <p className="m-0 text-xs text-fg-muted">{t("setupPage.proxyCa")}</p>
          </div>
        </Panel>
      )}
      <Panel title={t("setupPage.pack", { version: setup?.packVersion ?? "" })} description={t("setupPage.packDetail")} flush>
        <DataTable
          label={t("setupPage.packLabel")}
          rows={pack}
          getRowId={(q) => q.id}
          minWidth={760}
          columns={[
            {
              id: "query",
              header: t("setupPage.query"),
              width: "38%",
              cell: (q) => (
                <span className="flex min-w-0 flex-col">
                  <span className="font-medium">{q.description}</span>
                  <span className="font-mono text-2xs text-fg-muted">{q.id}</span>
                </span>
              ),
            },
            { id: "platform", header: t("devicesPage.os"), cell: (q) => <span className="text-xs">{packPlatform(q.platform)}</span> },
            {
              id: "every",
              header: t("setupPage.every"),
              cell: (q) => <span className="text-xs whitespace-nowrap">{t("time.minutes", { count: q.interval / 60 })}</span>,
            },
            { id: "sql", header: "SQL", cell: (q) => <span className="font-mono text-2xs break-all">{q.query}</span> },
          ]}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Audit

const AUDIT_KINDS = ["all", "device", "policy", "exception", "secret", "auth"] as const;

function AuditPage({ call }: { call: Call }) {
  const t = useT();
  const [kind, setKind] = useState<(typeof AUDIT_KINDS)[number]>("all");
  const [events, setEvents] = useState<AuditEvent[]>();
  const [next, setNext] = useState<string | null>(null);
  const page = useCallback(
    (cursor: string | null) => {
      const qs = new URLSearchParams({ limit: "100", ...(kind !== "all" && { kind }), ...(cursor && { cursor }) });
      void call<{ events: AuditEvent[]; next: string | null }>(`/api/v1/audit?${qs}`).then(
        (r) => {
          setEvents((e) => (cursor ? [...(e ?? []), ...r.events] : r.events));
          setNext(r.next);
        },
        () => setEvents([]),
      );
    },
    [call, kind],
  );
  useEffect(() => page(null), [page]);
  return (
    <>
      <PageHeader title={t("auditPage.title")} description={t("auditPage.description")}>
        <Tabs label={t("auditPage.kind")} value={kind} onChange={setKind} items={AUDIT_KINDS.map((k) => ({ value: k, label: t(`auditPage.kinds.${k}`) }))} />
      </PageHeader>
      <Panel title={t("auditPage.title")} flush footer={next && <Button onClick={() => page(next)}>{t("auditPage.more")}</Button>}>
        <DataTable
          label={t("auditPage.title")}
          rows={events ?? []}
          getRowId={(e) => String(e.id)}
          loading={events === undefined}
          minWidth={900}
          columns={[
            { id: "at", header: t("auditPage.at"), width: "170px", cell: (e) => <span className="text-xs whitespace-nowrap">{when(e.at)}</span> },
            { id: "actor", header: t("auditPage.actor"), cell: (e) => <span className="text-xs">{e.actor}</span> },
            {
              id: "action",
              header: t("auditPage.action"),
              cell: (e) => (
                <Badge mono tone={e.result === "denied" ? "danger" : "neutral"}>
                  {e.action}
                </Badge>
              ),
            },
            { id: "target", header: t("auditPage.target"), cell: (e) => <span className="font-mono text-xs">{e.target}</span> },
            { id: "detail", header: t("devicePage.detail"), width: "30%", cell: (e) => <span className="text-xs text-fg-muted">{e.detail}</span> },
          ]}
          empty={<EmptyState title={t("auditPage.none")} />}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdmin")}</EmptyState>;
  return (
    <>
      <PageHeader
        title={t(`settingsPage.${page}.title`)}
        description={t(`settingsPage.${page}.description`)}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const msg: T = useT();
  const [theme, setTheme] = useThemePreference();
  const [, setLocale] = useLocalePreference();
  const { me, can } = useAuth();
  const account = useAccountMenu();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();
  const onSearch = useMemo(() => search(call, msg), [call, msg]);

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) =>
        setProducts(r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "endpoints" && (PRODUCT_IDS as readonly string[]).includes(p.id))),
      () => {},
    );
  }, [call]);

  const reload = useCallback(() => void call<Summary>("/api/v1/summary").then(setSummary, () => {}), [call]);
  useEffect(() => {
    reload();
    const timer = setInterval(reload, 30_000);
    return () => clearInterval(timer);
  }, [reload]);

  const nav = [
    { id: "devices", label: msg("product.devices"), icon: Laptop, count: summary?.devices || undefined },
    { id: "compliance", label: msg("product.compliance"), icon: ClipboardCheck, count: summary?.postures["non-compliant"] || undefined },
    { id: "software", label: msg("product.software"), icon: AppWindow },
    { id: "policy", label: msg("product.policy"), icon: ShieldCheck },
    { id: "setup", label: msg("product.setup"), icon: Wrench },
    { id: "audit", label: msg("product.audit"), icon: ScrollText },
  ];
  const footerNav = [
    ...(can("admin")
      ? [
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
  ];
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);
  const settings = route.page === "account" || route.page === "members" || route.page === "signin" || route.page === "tokens";

  return (
    <AppShell
      product="endpoints"
      onSearch={onSearch}
      about={colophon}
      nav={nav}
      activeNav={route.page === "device" ? "devices" : route.page}
      onNavigate={(id) => navigate(id === "devices" ? "/" : `/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={account.settings(footerNav)}
      setup
      user={{ name: me.user.name, role: roleName, ...account.user }}
      theme={theme}
      onThemeChange={setTheme}
      onLanguageChange={(code) => setLocale(toLocale(code))}
    >
      {settings ? (
        <SettingsPage page={route.page as "account" | "members" | "signin" | "tokens"} />
      ) : !summary ? (
        <EmptyState title={msg("product.loading")} icon={<Laptop />}>
          {msg("product.reading")}
        </EmptyState>
      ) : route.page === "devices" && !summary.devices ? (
        <WelcomePage summary={summary} />
      ) : route.page === "devices" ? (
        <DevicesPage call={call} summary={summary} />
      ) : route.page === "device" ? (
        <DevicePage key={route.id} call={call} id={route.id} reload={reload} />
      ) : route.page === "compliance" ? (
        <CompliancePage call={call} summary={summary} />
      ) : route.page === "software" ? (
        <SoftwarePage key={window.location.search} call={call} />
      ) : route.page === "policy" ? (
        <PolicyPage call={call} reload={reload} />
      ) : route.page === "audit" ? (
        <AuditPage call={call} />
      ) : (
        <SetupPage call={call} reload={reload} />
      )}
    </AppShell>
  );
}

export function App() {
  const installBrand = useInstallBrand();
  const [theme] = useThemePreference();
  const [locale] = useLocalePreference();
  return (
    // The install's brand from config/brand.env (ADR 0053); OpenAsy's own look where it sets none.
    <BrandProvider theme={theme} locale={locale} brand={{ name: "OpenAsy", organization: undefined, ...installBrand }} className="min-h-screen">
      <AuthGate product="OpenAsy Endpoints">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
