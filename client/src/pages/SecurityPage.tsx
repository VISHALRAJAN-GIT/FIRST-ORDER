import { Link } from "wouter";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  BarChart3,
  CheckCircle2,
  Clock3,
  LogOut,
  Radar,
  ShieldCheck,
  Ticket,
  Users,
} from "lucide-react";
import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { trpc } from "@/lib/trpc";

type MetricProps = {
  icon: typeof Activity;
  label: string;
  value: string;
  detail: string;
  tone: "purple" | "lime" | "orange" | "red";
};

function Metric({ icon: Icon, label, value, detail, tone }: MetricProps) {
  const styles = {
    purple: "bg-[#f0effa] text-[#7b3ff2]",
    lime: "bg-[#ecf7c7] text-[#526b16]",
    orange: "bg-[#fff2dc] text-[#935b16]",
    red: "bg-[#fee7e7] text-[#b42318]",
  };
  return (
    <div className="rounded-[1.5rem] border border-[#dedcd2] bg-white p-5">
      <div className={`grid h-10 w-10 place-items-center rounded-xl ${styles[tone]}`}>
        <Icon className="h-5 w-5" />
      </div>
      <p className="mt-6 text-sm text-[#68675d]">{label}</p>
      <p className="mt-1 text-3xl font-semibold tracking-[-.06em]">{value}</p>
      <p className="mt-2 text-xs text-[#aaa99e]">{detail}</p>
    </div>
  );
}

function formatDate(value: Date | string | null | undefined) {
  if (!value) return "—";
  return new Date(value).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function SecurityPage() {
  const { user, loading, logout } = useAuth();
  const securityQuery = trpc.security.status.useQuery(undefined, {
    enabled: user?.role === "admin",
    refetchInterval: 15_000,
    retry: false,
  });

  if (loading) {
    return <div className="grid min-h-screen place-items-center bg-[#f7f5ef]">Loading security monitor…</div>;
  }

  if (!user || user.role !== "admin") {
    return (
      <div className="grid min-h-screen place-items-center bg-[#f7f5ef] px-5 text-center">
        <div>
          <ShieldCheck className="mx-auto h-10 w-10 text-[#7b3ff2]" />
          <h1 className="mt-5 text-3xl font-semibold">Admin access required.</h1>
          <p className="mt-3 text-[#68675d]">Security metrics are protected server-side.</p>
          <Link href="/" className="mt-6 inline-block text-[#7b3ff2]">Return home</Link>
        </div>
      </div>
    );
  }

  const dashboard = securityQuery.data;
  const hasThreats = Boolean(dashboard && dashboard.blockedRequests > 0);

  return (
    <div className="min-h-screen bg-[#f7f5ef] text-[#171814]">
      <aside className="fixed inset-y-0 left-0 hidden w-64 border-r border-[#dedcd2] bg-white p-6 lg:block">
        <Link href="/" className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-[#171814] text-[#ddff5a]"><Ticket className="h-5 w-5" /></div>
          <span className="text-xl font-semibold tracking-[-.04em]">tixify<span className="text-[#7b3ff2]">.</span></span>
        </Link>
        <nav className="mt-14 space-y-2 text-sm">
          <Link href="/admin" className="flex items-center gap-3 rounded-xl px-4 py-3 text-[#68675d] hover:bg-[#f7f5ef]"><BarChart3 className="h-4 w-4" /> Operations</Link>
          <Link href="/admin/security" className="flex items-center gap-3 rounded-xl bg-[#f0effa] px-4 py-3 font-medium text-[#7b3ff2]"><ShieldCheck className="h-4 w-4" /> Security monitor</Link>
        </nav>
        <Button onClick={logout} variant="ghost" className="absolute bottom-6 left-6 text-[#68675d]"><LogOut className="mr-2 h-4 w-4" /> Sign out</Button>
      </aside>

      <main className="lg:pl-64">
        <div className="mx-auto max-w-7xl px-5 py-8 lg:px-10">
          <Link href="/admin" className="inline-flex items-center gap-2 text-sm text-[#68675d] hover:text-[#171814]"><ArrowLeft className="h-4 w-4" /> Back to operations</Link>
          <div className="mt-8 flex flex-wrap items-end justify-between gap-5">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[.2em] text-[#7b3ff2]">Trust & safety</p>
              <h1 className="mt-3 text-5xl font-semibold tracking-[-.07em]">Security<br /><span className="text-[#7b3ff2]">monitor.</span></h1>
              <p className="mt-4 max-w-xl text-[#68675d]">Live signals from ticket verification, rate limits, audit logs, and the event queue.</p>
            </div>
            <div className="inline-flex items-center gap-2 rounded-full border border-[#d9e99b] bg-[#f5fadf] px-3 py-2 text-xs font-semibold text-[#526b16]"><span className="h-2 w-2 rounded-full bg-[#7da21c]" /> Refreshes every 15 seconds</div>
          </div>

          {securityQuery.isError && <div className="mt-8 flex items-start gap-3 rounded-2xl bg-[#fff2dc] px-4 py-3 text-sm text-[#935b16]"><AlertTriangle className="mt-0.5 h-4 w-4" /> Unable to load security metrics. Check database connectivity and your admin permissions.</div>}

          <section className="mt-10 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Metric icon={Activity} label="Requests / second" value={String(dashboard?.requestsPerSecond ?? 0)} detail={`${dashboard?.totalRequests ?? 0} total audit requests`} tone="purple" />
            <Metric icon={Ticket} label="Ticket scans" value={String(dashboard?.ticketVerificationAttempts ?? 0)} detail={`${dashboard?.invalidTickets ?? 0} invalid signatures`} tone="lime" />
            <Metric icon={Users} label="Queue size" value={String(dashboard?.queueSize ?? 0)} detail={`${dashboard?.activeReservations ?? 0} valid tickets active`} tone="orange" />
            <Metric icon={AlertTriangle} label="Blocked requests" value={String(dashboard?.blockedRequests ?? 0)} detail={`${dashboard?.replayAttempts ?? 0} replay attempts`} tone={hasThreats ? "red" : "lime"} />
          </section>

          <section className="mt-6 rounded-[2rem] border border-[#dedcd2] bg-white p-6 sm:p-8">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div><h2 className="text-xl font-semibold tracking-[-.04em]">Recent security events</h2><p className="mt-1 text-sm text-[#68675d]">Newest events are shown first. IP addresses remain hashed.</p></div>
              <div className="flex items-center gap-2 text-xs text-[#68675d]"><Clock3 className="h-4 w-4 text-[#7b3ff2]" /> Live operational view</div>
            </div>
            <div className="mt-7 overflow-x-auto">
              <table className="w-full min-w-[680px] text-left text-sm">
                <thead className="border-b border-[#eeece5] text-xs uppercase tracking-[.14em] text-[#aaa99e]"><tr><th className="pb-3">Event</th><th className="pb-3">Severity</th><th className="pb-3">Endpoint</th><th className="pb-3 text-right">Time</th></tr></thead>
                <tbody>
                  {dashboard?.recentEvents?.map((event) => <tr key={event.id} className="border-b border-[#f2f0e9]"><td className="py-4 font-medium"><span className="inline-flex items-center gap-2"><Radar className="h-4 w-4 text-[#7b3ff2]" />{event.eventType}</span></td><td className="py-4"><span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${event.severity === "HIGH" || event.severity === "CRITICAL" ? "bg-[#fee7e7] text-[#b42318]" : "bg-[#fff2dc] text-[#935b16]"}`}>{event.severity}</span></td><td className="py-4 text-[#68675d]">{event.endpoint ?? "—"}</td><td className="py-4 text-right text-[#68675d]">{formatDate(event.createdAt)}</td></tr>)}
                  {!dashboard?.recentEvents?.length && <tr><td colSpan={4} className="py-12 text-center text-[#68675d]"><CheckCircle2 className="mx-auto h-8 w-8 text-[#7da21c]" /><p className="mt-3">No security events recorded.</p></td></tr>}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}
