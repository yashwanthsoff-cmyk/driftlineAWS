import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDownUp,
  ArrowLeft,
  ArrowUpRight,
  Ban,
  CalendarDays,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  CircleHelp,
  Clock3,
  CloudCog,
  Database,
  Download,
  Eye,
  FileClock,
  FileText,
  Filter,
  Gauge,
  GitBranch,
  History,
  Info,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  PanelLeft,
  PanelLeftClose,
  RefreshCw,
  Search,
  Server,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  X,
  XCircle,
} from "lucide-react";
import { Toaster, toast } from "sonner";
import { Link, useLocation } from "wouter";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import ErrorBoundary from "./components/ErrorBoundary";

// -----------------------------------------------------------------------------
// Typed replay-mode data. This mirrors the eventual backend shape deliberately.
// -----------------------------------------------------------------------------

type RiskLevel = "approve" | "review" | "block";
type Decision = "approve" | "approve_with_conditions" | "block";
type Outcome = "fine" | "caused_incident" | "false_positive" | "pending" | "unknown";
type Service = "S3" | "IAM" | "EC2" | "RDS";

type DriftPattern = {
  id: string;
  pattern_key: string;
  description: string;
  trust_score: number;
  updated_at: string;
};

type DriftEvent = {
  id: string;
  pattern_id: string;
  resource: string;
  service: Service;
  risk_level: RiskLevel;
  summary: string;
  evidence: string[];
  recommendation: string;
  iam_flag: null | { new_scope: string; historical_scope: string; flagged_permissions: string[] };
  evidence_source: "aws_config" | "replay_fixture";
  created_at: string;
};

type HistoricalMatch = {
  id: string;
  drift_event_id: string;
  matched_event_summary: string;
  similarity: number;
  outcome: Outcome;
  matched_date: string;
};

type AuditLog = {
  id: string;
  drift_event_id: string;
  decision: Decision;
  outcome: Outcome;
  evidence_snapshot: string;
  timestamp: string;
};

const patterns: DriftPattern[] = [
  {
    id: "pattern-s3-public-read",
    pattern_key: "s3-public-read-drift",
    description: "S3 bucket policy diverges from the last-applied IaC state and expands public access.",
    trust_score: 25,
    updated_at: "2026-09-20T18:14:00Z",
  },
  {
    id: "pattern-ec2-ssh-cidr",
    pattern_key: "ec2-wide-ssh-cidr",
    description: "EC2 security group ingress opens SSH to a wider CIDR than the declared Terraform scope.",
    trust_score: 55,
    updated_at: "2026-09-20T17:42:00Z",
  },
  {
    id: "pattern-rds-logging",
    pattern_key: "rds-logging-parameter",
    description: "RDS parameter group changes a low-risk logging setting without changing access posture.",
    trust_score: 90,
    updated_at: "2026-09-20T16:09:00Z",
  },
];

const seedEvents: DriftEvent[] = [
  {
    id: "evt-7f3c1a",
    pattern_id: "pattern-s3-public-read",
    resource: "s3://checkout-assets",
    service: "S3",
    risk_level: "block",
    summary: "Bucket policy gained public read access outside the change pipeline.",
    evidence: [
      "Principal * added to s3:GetObject on checkout-assets/*",
      "CloudTrail shows PutBucketPolicy from arn:aws:iam::4821:user/ci-replay",
      "No matching commit or approved change set in the last 24 hours",
      "Last-applied IaC state: private bucket with CloudFront OAC",
    ],
    recommendation: "Reconcile policy before the next deploy and invalidate the exposed object path.",
    iam_flag: {
      new_scope: "Principal: * · Action: s3:GetObject · Resource: checkout-assets/*",
      historical_scope: "CloudFront OAC only · Action: s3:GetObject · Resource: checkout-assets/*",
      flagged_permissions: ["Principal: *", "s3:GetObject"],
    },
    evidence_source: "replay_fixture",
    created_at: "2026-09-20T20:42:00Z",
  },
  {
    id: "evt-82ab0d",
    pattern_id: "pattern-ec2-ssh-cidr",
    resource: "sg-0a8c2f1d / checkout-api",
    service: "EC2",
    risk_level: "review",
    summary: "SSH ingress widened from the declared office CIDR to a broader network range.",
    evidence: [
      "Ingress changed from 10.22.0.0/16 to 0.0.0.0/0 on port 22",
      "CloudTrail actor: arn:aws:iam::4821:role/platform-deployer",
      "Terraform state still declares 10.22.0.0/16",
    ],
    recommendation: "Confirm the access window with the platform owner, then reconcile the security group.",
    iam_flag: null,
    evidence_source: "aws_config",
    created_at: "2026-09-20T19:18:00Z",
  },
  {
    id: "evt-64d9ef",
    pattern_id: "pattern-rds-logging",
    resource: "rds://orders-prod/parameter-group",
    service: "RDS",
    risk_level: "approve",
    summary: "Log retention parameter drifted from the last-applied IaC state.",
    evidence: [
      "log_statement changed from 'none' to 'ddl'",
      "Change originated from the approved observability runbook",
      "Pattern previously confirmed safe twice in the last 30 days",
    ],
    recommendation: "Approve deployment; preserve the updated logging setting in the next IaC apply.",
    iam_flag: null,
    evidence_source: "replay_fixture",
    created_at: "2026-09-20T16:57:00Z",
  },
];

const seedMatches: HistoricalMatch[] = [
  {
    id: "match-41aa",
    drift_event_id: "evt-7f3c1a",
    matched_event_summary: "Public read policy on media-assets caused a 2-hour checkout image outage after cache invalidation.",
    similarity: 0.89,
    outcome: "caused_incident",
    matched_date: "2026-08-08",
  },
  {
    id: "match-82bb",
    drift_event_id: "evt-64d9ef",
    matched_event_summary: "RDS logging verbosity updated during the July observability rollout; no customer impact.",
    similarity: 0.81,
    outcome: "fine",
    matched_date: "2026-08-23",
  },
];

const seedAudits: AuditLog[] = [
  {
    id: "audit-01",
    drift_event_id: "evt-64d9ef",
    decision: "approve",
    outcome: "fine",
    evidence_snapshot: JSON.stringify({ source: "replay_fixture", risk: "approve", evidence_count: 3, recommendation: "Approve deployment" }, null, 2),
    timestamp: "2026-09-20T17:02:00Z",
  },
];

const seedSignalSeries = [
  { time: "09:00", block: 2, review: 4, approve: 8 },
  { time: "10:00", block: 3, review: 5, approve: 9 },
  { time: "11:00", block: 2, review: 7, approve: 8 },
  { time: "12:00", block: 4, review: 6, approve: 10 },
  { time: "13:00", block: 5, review: 8, approve: 11 },
  { time: "14:00", block: 4, review: 7, approve: 13 },
  { time: "15:00", block: 6, review: 9, approve: 12 },
  { time: "16:00", block: 5, review: 10, approve: 15 },
];

const riskMeta: Record<RiskLevel, { label: string; icon: typeof ShieldAlert; className: string; eyebrow: string }> = {
  block: { label: "Block", icon: XCircle, className: "status-block", eyebrow: "HIGH RISK" },
  review: { label: "Review", icon: AlertTriangle, className: "status-review", eyebrow: "MEDIUM-HIGH" },
  approve: { label: "Approve", icon: CheckCircle2, className: "status-approve", eyebrow: "LOW RISK" },
};

const outcomeMeta: Record<Outcome, { label: string; className: string }> = {
  fine: { label: "Fine", className: "outcome-fine" },
  caused_incident: { label: "Caused incident", className: "outcome-incident" },
  false_positive: { label: "False positive", className: "outcome-neutral" },
  pending: { label: "Pending", className: "outcome-pending" },
  unknown: { label: "Unknown", className: "outcome-neutral" },
};

const decisionLabel: Record<Decision, string> = {
  approve: "Approved",
  approve_with_conditions: "Approved with conditions",
  block: "Blocked",
};

function formatRelative(date: string) {
  const mins = Math.max(1, Math.round((Date.now() - new Date(date).getTime()) / 60000));
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function formatDate(date: string) {
  return new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", year: "numeric" }).format(new Date(date));
}

function cn(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

// -----------------------------------------------------------------------------
// App state
// -----------------------------------------------------------------------------

type AppState = {
  patterns: DriftPattern[];
  events: DriftEvent[];
  matches: HistoricalMatch[];
  audits: AuditLog[];
  failureMode: boolean;
};

function useDriftlineState() {
  const [state, setState] = useState<AppState>({
    patterns,
    events: seedEvents,
    matches: seedMatches,
    audits: seedAudits,
    failureMode: false,
  });

  const setDecision = (eventId: string, decision: Decision) => {
    const event = state.events.find((item) => item.id === eventId);
    if (!event) return;
    const newAudit: AuditLog = {
      id: `audit-${Date.now()}`,
      drift_event_id: eventId,
      decision,
      outcome: "pending",
      evidence_snapshot: JSON.stringify({
        event_id: event.id,
        risk_level: event.risk_level,
        evidence_source: event.evidence_source,
        evidence: event.evidence,
        recommendation: event.recommendation,
      }, null, 2),
      timestamp: new Date().toISOString(),
    };
    setState((current) => ({ ...current, audits: [newAudit, ...current.audits.filter((audit) => audit.drift_event_id !== eventId)] }));
    toast.success(`Decision recorded: ${decisionLabel[decision]}`, { description: `${event.resource} is now reflected in the evidence trail.` });
  };

  const setOutcome = (eventId: string, outcome: Outcome) => {
    const event = state.events.find((item) => item.id === eventId);
    if (!event) return;
    const delta = outcome === "fine" ? 4 : outcome === "caused_incident" ? -18 : 0;
    setState((current) => {
      const patternId = event.pattern_id;
      const nextPatterns = current.patterns.map((pattern) => pattern.id === patternId
        ? { ...pattern, trust_score: Math.max(0, Math.min(100, pattern.trust_score + delta)), updated_at: new Date().toISOString() }
        : pattern);
      const existing = current.audits.find((audit) => audit.drift_event_id === eventId);
      const nextAudit: AuditLog = existing
        ? { ...existing, outcome, timestamp: new Date().toISOString() }
        : {
            id: `audit-${Date.now()}`,
            drift_event_id: eventId,
            decision: "approve_with_conditions",
            outcome,
            evidence_snapshot: JSON.stringify({ event_id: eventId, outcome, evidence_source: event.evidence_source }, null, 2),
            timestamp: new Date().toISOString(),
          };
      return { ...current, patterns: nextPatterns, audits: [nextAudit, ...current.audits.filter((audit) => audit.drift_event_id !== eventId)] };
    });
    toast.success("Outcome recorded — trust score updated", { description: outcome === "fine" ? "Pattern confidence increased by 4 points." : "Pattern confidence reduced to reflect the incident." });
  };

  return { state, setState, setDecision, setOutcome };
}

// -----------------------------------------------------------------------------
// Shared visual primitives
// -----------------------------------------------------------------------------

function StatusBadge({ risk, compact = false }: { risk: RiskLevel; compact?: boolean }) {
  const meta = riskMeta[risk];
  const Icon = meta.icon;
  return <span className={cn("status-badge", meta.className, compact && "status-badge-compact")}><Icon size={compact ? 13 : 14} strokeWidth={2.2} />{meta.label}</span>;
}

function OutcomeBadge({ outcome }: { outcome: Outcome }) {
  const meta = outcomeMeta[outcome];
  return <span className={cn("outcome-badge", meta.className)}>{meta.label}</span>;
}

function SectionHeading({ kicker, title, action }: { kicker?: string; title: string; action?: ReactNode }) {
  return <div className="section-heading">
    <div>
      {kicker && <p className="section-kicker">{kicker}</p>}
      <h2>{title}</h2>
    </div>
    {action}
  </div>;
}

function InlineFailureBanner() {
  return <div className="failure-banner" role="status">
    <RefreshCw size={16} />
    <span><strong>Couldn't reach the data source</strong> — showing last known state</span>
    <span className="failure-dot">REPLAY FALLBACK</span>
  </div>;
}

function PageTitle({ eyebrow, title, description, children }: { eyebrow: string; title: string; description: string; children?: ReactNode }) {
  return <div className="page-title-row">
    <div>
      <div className="eyebrow-row"><span className="live-dot" />{eyebrow}</div>
      <h1>{title}</h1>
      <p>{description}</p>
    </div>
    {children}
  </div>;
}

function RiskIcon({ risk }: { risk: RiskLevel }) {
  const Icon = riskMeta[risk].icon;
  return <span className={cn("risk-icon", riskMeta[risk].className)}><Icon size={18} /></span>;
}

function Sidebar({ currentPath, failureMode, collapsed, onToggleCollapse, onToggleMenu }: { currentPath: string; failureMode: boolean; collapsed: boolean; onToggleCollapse: () => void; onToggleMenu: () => void }) {
  const items = [
    { href: "/console", label: "Drift Feed", icon: Activity, count: 3 },
    { href: "/audit", label: "Audit Log", icon: FileClock },
    { href: "/settings", label: "Settings", icon: Settings2 },
  ];
  return <aside className={cn("sidebar", collapsed && "sidebar-collapsed")}>
    <div className="brand-row">
      <Link href="/" className="brand-home-link" aria-label="Back to Driftline home"><div className="brand-mark"><GitBranch size={19} strokeWidth={2.3} /></div><div><div className="brand-name">DRIFTLINE</div><div className="brand-sub">DECISION INTELLIGENCE</div></div></Link>
      <button className="sidebar-collapse-button" onClick={onToggleCollapse} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>{collapsed ? <PanelLeft size={16} /> : <PanelLeftClose size={16} />}</button>
      <button className="mobile-menu-button" onClick={onToggleMenu} aria-label="Toggle navigation"><Menu size={18} /></button>
    </div>
    <div className="workspace-switcher">
      <div className="workspace-icon"><CloudCog size={15} /></div>
      <div><div className="workspace-label">WORKSPACE</div><div className="workspace-name">platform-prod</div></div>
      <ChevronRight size={15} className="muted-icon" />
    </div>
    <nav className="side-nav" aria-label="Primary">
      <div className="nav-label">OPERATIONS</div>
      {items.map((item) => {
        const Icon = item.icon;
        const active = currentPath === item.href || (item.href === "/console" && currentPath === "/");
        return <Link key={item.href} href={item.href} className={cn("nav-item", active && "nav-item-active")}>
          <Icon size={17} strokeWidth={active ? 2.2 : 1.8} /><span>{item.label}</span>{item.count && <span className="nav-count">{item.count}</span>}
        </Link>;
      })}
    </nav>
    <div className="sidebar-bottom">
      <div className="source-card">
        <div className="source-card-top"><span className="source-status-dot" /> <span>REPLAY MODE</span><span className="source-live">LIVE</span></div>
        <p>Fixture-backed evidence. Same shape as AWS Config + CloudTrail.</p>
        <div className="source-metrics"><span><Database size={13} /> 3 events</span><span><Clock3 size={13} /> synced now</span></div>
      </div>
      <div className="user-row"><div className="avatar">AK</div><div><div className="user-name">Alex Kim</div><div className="user-role">Platform engineering</div></div><MoreHorizontalIcon /></div>
      {failureMode && <div className="failure-mode-label"><AlertTriangle size={13} /> failure simulation on</div>}
    </div>
  </aside>;
}

function MoreHorizontalIcon() {
  return <span className="more-icon">•••</span>;
}

function Topbar({ currentPath, onMobileMenu }: { currentPath: string; onMobileMenu: () => void }) {
  const label = currentPath === "/console" || currentPath === "/" ? "Drift Feed" : currentPath.startsWith("/events/") ? "Risk Detail" : currentPath === "/audit" ? "Audit Log" : "Settings";
  return <header className="topbar">
    <button className="topbar-menu" onClick={onMobileMenu} aria-label="Open navigation"><Menu size={18} /></button>
    <div className="breadcrumbs"><span>platform-prod</span><ChevronRight size={14} /><strong>{label}</strong></div>
    <div className="topbar-actions"><span className="environment-chip"><span className="environment-dot" /> AP-SOUTH-1</span><span className="mode-chip"><GitBranch size={13} /> REPLAY_MODE</span><button className="icon-button" title="Help"><CircleHelp size={17} /></button><div className="topbar-avatar">AK</div></div>
  </header>;
}

function Shell({ children, state, currentPath }: { children: ReactNode; state: AppState; currentPath: string }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  return <div className={cn("app-shell unified-console", mobileOpen && "mobile-nav-open")}>
    <Sidebar currentPath={currentPath} failureMode={state.failureMode} collapsed={sidebarCollapsed} onToggleCollapse={() => setSidebarCollapsed((value) => !value)} onToggleMenu={() => setMobileOpen((value) => !value)} />
    <div className="app-main"><Topbar currentPath={currentPath} onMobileMenu={() => setMobileOpen(true)} /><main className="content-area">{children}</main></div>
    {mobileOpen && <button className="mobile-overlay" onClick={() => setMobileOpen(false)} aria-label="Close navigation" />}
  </div>;
}

// -----------------------------------------------------------------------------
// Pages
// -----------------------------------------------------------------------------

function SummaryStrip({ events, audits }: { events: DriftEvent[]; audits: AuditLog[] }) {
  const counts = events.reduce((acc, event) => { acc[event.risk_level] += 1; return acc; }, { block: 0, review: 0, approve: 0 } as Record<RiskLevel, number>);
  return <div className="summary-strip">
    <div className="summary-intro"><div className="summary-icon"><Activity size={17} /></div><div><div className="summary-label">SIGNAL OVERVIEW</div><div className="summary-value">{events.length} drift signals <span>·</span> {audits.length} decisions logged</div></div></div>
    <div className="summary-stat summary-stat-block"><span className="summary-stat-value">{counts.block}</span><span className="summary-stat-label"><XCircle size={13} /> block</span></div>
    <div className="summary-stat summary-stat-review"><span className="summary-stat-value">{counts.review}</span><span className="summary-stat-label"><AlertTriangle size={13} /> review</span></div>
    <div className="summary-stat summary-stat-approve"><span className="summary-stat-value">{counts.approve}</span><span className="summary-stat-label"><CheckCircle2 size={13} /> approve</span></div>
    <div className="summary-sync"><span className="live-dot" /> last scan <strong>2m ago</strong></div>
  </div>;
}

function FilterSelect({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) {
  return <label className="filter-select"><span>{label}</span><select value={value} onChange={(event) => onChange(event.target.value)}>{options.map((option) => <option key={option} value={option}>{option}</option>)}</select><ChevronRight size={14} className="select-chevron" /></label>;
}

function SignalActivityChart() {
  const [series, setSeries] = useState(seedSignalSeries);
  useEffect(() => {
    const timer = window.setInterval(() => {
      setSeries((current) => {
        const last = current[current.length - 1];
        const nextTime = new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
        return [...current.slice(1), {
          time: nextTime,
          block: Math.max(1, Math.min(12, last.block + Math.round(Math.random() * 4 - 2))),
          review: Math.max(2, Math.min(16, last.review + Math.round(Math.random() * 4 - 2))),
          approve: Math.max(5, Math.min(20, last.approve + Math.round(Math.random() * 4 - 2))),
        }];
      });
    }, 4200);
    return () => window.clearInterval(timer);
  }, []);
  return <section className="signal-chart-card">
    <div className="signal-chart-header"><div><div className="section-kicker"><Activity size={14} /> SIGNAL ACTIVITY / LIVE</div><h2>Drift volume by risk bucket</h2></div><div className="chart-legend"><span><i className="legend-dot legend-block" /> block</span><span><i className="legend-dot legend-review" /> review</span><span><i className="legend-dot legend-approve" /> approve</span></div></div>
    <div className="chart-viewport"><ResponsiveContainer width="100%" height="100%"><AreaChart data={series} margin={{ top: 8, right: 10, left: -22, bottom: 0 }}><defs><linearGradient id="blockFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#ef6a63" stopOpacity={0.34} /><stop offset="100%" stopColor="#ef6a63" stopOpacity={0} /></linearGradient><linearGradient id="reviewFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#eab763" stopOpacity={0.28} /><stop offset="100%" stopColor="#eab763" stopOpacity={0} /></linearGradient><linearGradient id="approveFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#57d9a3" stopOpacity={0.25} /><stop offset="100%" stopColor="#57d9a3" stopOpacity={0} /></linearGradient></defs><CartesianGrid vertical={false} stroke="rgba(163,183,201,.1)" /><XAxis dataKey="time" tick={{ fill: "#6f808b", fontSize: 9 }} tickLine={false} axisLine={false} /><YAxis tick={{ fill: "#6f808b", fontSize: 9 }} tickLine={false} axisLine={false} width={32} /><Tooltip contentStyle={{ background: "#14202a", border: "1px solid rgba(163,183,201,.2)", borderRadius: 8, color: "#f2f5f7", fontSize: 11 }} labelStyle={{ color: "#91a2ad" }} /><Area type="monotone" dataKey="approve" stroke="#57d9a3" fill="url(#approveFill)" strokeWidth={2} animationDuration={550} /><Area type="monotone" dataKey="review" stroke="#eab763" fill="url(#reviewFill)" strokeWidth={2} animationDuration={550} /><Area type="monotone" dataKey="block" stroke="#ef6a63" fill="url(#blockFill)" strokeWidth={2} animationDuration={550} /></AreaChart></ResponsiveContainer></div>
    <div className="chart-footnote"><span><span className="live-dot" /> auto-refreshing every 4s</span><span>Source: replay fixture · 24h rolling view</span></div>
  </section>;
}

function FeedPage({ state }: { state: AppState }) {
  const [riskFilter, setRiskFilter] = useState("All risk levels");
  const [serviceFilter, setServiceFilter] = useState("All services");
  const [sort, setSort] = useState("Newest first");
  const filtered = useMemo(() => state.events.filter((event) => (riskFilter === "All risk levels" || event.risk_level === riskFilter.toLowerCase()) && (serviceFilter === "All services" || event.service === serviceFilter)).sort((a, b) => sort === "Highest risk first" ? ({ block: 0, review: 1, approve: 2 }[a.risk_level] - { block: 0, review: 1, approve: 2 }[b.risk_level]) : new Date(b.created_at).getTime() - new Date(a.created_at).getTime()), [state.events, riskFilter, serviceFilter, sort]);
  return <>
    {state.failureMode && <InlineFailureBanner />}
    <PageTitle eyebrow="DRIFT SIGNALS / LAST 7 DAYS" title="Drift Feed" description="Review configuration changes before they become deployment decisions.">
      <div className="page-title-actions"><button className="button button-secondary"><RefreshCw size={15} /> Refresh scan</button><span className="sync-note"><span className="live-dot" /> synced 2m ago</span></div>
    </PageTitle>
    <SummaryStrip events={state.events} audits={state.audits} />
    <SignalActivityChart />
    <div className="filter-row">
      <div className="filter-group"><Filter size={15} className="filter-leading" /><span className="filter-label">FILTER BY</span><FilterSelect label="Risk" value={riskFilter} options={["All risk levels", "Block", "Review", "Approve"]} onChange={setRiskFilter} /><FilterSelect label="Service" value={serviceFilter} options={["All services", "S3", "IAM", "EC2", "RDS"]} onChange={setServiceFilter} /></div>
      <div className="filter-group filter-group-right"><span className="filter-label">SORT</span><FilterSelect label="Sort" value={sort} options={["Newest first", "Highest risk first"]} onChange={setSort} /></div>
    </div>
    {filtered.length === 0 ? <div className="empty-state"><div className="empty-icon"><Search size={22} /></div><h3>No events match this filter</h3><p>Try widening the risk or service filter to see more signals.</p><button className="button button-secondary" onClick={() => { setRiskFilter("All risk levels"); setServiceFilter("All services"); }}>Clear filters</button></div> : <div className="event-table-card">
      <div className="table-header"><span>RESOURCE / SIGNAL</span><span>RISK ASSESSMENT</span><span>EVIDENCE SOURCE</span><span>UPDATED</span><span></span></div>
      {filtered.map((event, index) => <EventRow key={event.id} event={event} audit={state.audits.find((audit) => audit.drift_event_id === event.id)} delay={index * 45} />)}
    </div>}
    <div className="feed-footer"><span>Showing {filtered.length} of {state.events.length} detected signals</span><span className="footer-source"><Database size={13} /> Source: replay fixture <Info size={13} /></span></div>
  </>;
}

function EventRow({ event, audit, delay }: { event: DriftEvent; audit?: AuditLog; delay: number }) {
  return <Link href={`/events/${event.id}`} className="event-row" style={{ animationDelay: `${delay}ms` }}>
    <div className="event-resource"><RiskIcon risk={event.risk_level} /><div><div className="resource-name">{event.resource}</div><div className="resource-summary">{event.summary}</div></div></div>
    <div><StatusBadge risk={event.risk_level} /><div className="risk-caption">{riskMeta[event.risk_level].eyebrow}</div></div>
    <div className="source-cell"><span className="source-icon"><GitBranch size={13} /></span><div><span>{event.evidence_source === "aws_config" ? "AWS Config" : "Replay fixture"}</span><small>{event.evidence.length} evidence points</small></div></div>
    <div className="updated-cell"><Clock3 size={14} />{formatRelative(event.created_at)}</div>
    <div className="row-trailing">{audit ? <span className="decided-chip"><Check size={12} /> decided</span> : <span className="row-arrow"><ArrowUpRight size={16} /></span>}<ChevronRight size={16} className="row-chevron" /></div>
  </Link>;
}

function RiskDetailPage({ state, eventId, setDecision, setOutcome }: { state: AppState; eventId: string; setDecision: (id: string, decision: Decision) => void; setOutcome: (id: string, outcome: Outcome) => void }) {
  const event = state.events.find((item) => item.id === eventId);
  const [, setLocation] = useLocation();
  if (!event) return <NotFoundPage />;
  const pattern = state.patterns.find((item) => item.id === event.pattern_id)!;
  const audit = state.audits.find((item) => item.drift_event_id === event.id);
  const matches = state.matches.filter((match) => match.drift_event_id === event.id);
  const recommendedDecision: Decision = event.risk_level === "block" ? "block" : event.risk_level === "review" ? "approve_with_conditions" : "approve";
  return <>
    {state.failureMode && <InlineFailureBanner />}
    <button className="back-link" onClick={() => setLocation("/console")}><ArrowLeft size={15} /> Back to drift feed</button>
    <div className="detail-title-row"><div><div className="eyebrow-row"><span className="live-dot" />RISK DETAIL / {event.service}</div><h1>{event.resource}</h1><p className="detail-subtitle">{event.summary}</p></div><div className="detail-title-meta"><span className="event-id">{event.id}</span><span className="source-chip"><GitBranch size={13} /> {event.evidence_source === "aws_config" ? "AWS Config" : "Replay fixture"}</span></div></div>
    <section className="decision-panel panel-glow">
      <div className="decision-panel-header"><div><div className="panel-kicker"><Sparkles size={14} /> EXPLAINABLE DECISION</div><h2>Deployment risk assessment</h2></div><StatusBadge risk={event.risk_level} /></div>
      <div className="risk-statement"><div className="risk-statement-badge"><span>RISK</span><strong>{riskMeta[event.risk_level].eyebrow}</strong></div><div><div className="statement-title">{event.resource} policy diverged from last-applied IaC state</div><div className="statement-note">Correlation of configuration drift, CloudTrail history, and outcome memory.</div></div></div>
      <div className="decision-grid"><div className="evidence-column"><div className="subheading"><ShieldCheck size={15} /> EVIDENCE SNAPSHOT <span>{event.evidence.length} points</span></div><ul className="evidence-list">{event.evidence.map((item) => <li key={item}><span className="evidence-bullet" /><code>{item}</code></li>)}</ul></div><div className="recommendation-card"><div className="subheading"><ArrowUpRight size={15} /> RECOMMENDATION</div><p>{event.recommendation}</p><div className="recommendation-source"><LockKeyhole size={13} /> deterministic risk engine</div></div></div>
      <div className="decision-action"><div><div className="subheading"><CircleDot size={15} /> DEPLOYMENT DECISION</div><p>Record what should happen next. This action is captured in the audit trail.</p></div><div className="decision-buttons"><DecisionButton label="Approve deployment" icon={CheckCircle2} decision="approve" active={audit?.decision === "approve" || (!audit && recommendedDecision === "approve")} onClick={() => setDecision(event.id, "approve")} /><DecisionButton label="Approve with conditions" icon={AlertTriangle} decision="approve_with_conditions" active={audit?.decision === "approve_with_conditions" || (!audit && recommendedDecision === "approve_with_conditions")} onClick={() => setDecision(event.id, "approve_with_conditions")} /><DecisionButton label="Block deployment" icon={Ban} decision="block" active={audit?.decision === "block" || (!audit && recommendedDecision === "block")} onClick={() => setDecision(event.id, "block")} /></div></div>
    </section>
    <div className="detail-grid">
      <section className="panel historical-panel"><SectionHeading kicker="FEATURE 02 / OUTCOME MEMORY" title="Historical matches" action={<span className="panel-count">{matches.length} match{matches.length === 1 ? "" : "es"}</span>} />{matches.length === 0 ? <div className="panel-empty"><History size={22} /><strong>No similar past drift found yet</strong><p>This pattern will build up as more events are recorded.</p></div> : <div className="match-list">{matches.map((match) => <MatchCard key={match.id} match={match} />)}</div>}<div className="memory-footnote"><Sparkles size={13} /> Matching uses structured evidence, not free-text similarity alone.</div></section>
      <section className="panel trust-panel"><SectionHeading kicker="PATTERN TRUST / CLAMPED 0–100" title="Trust score" action={<span className="trend-chip"><ArrowUpRight size={13} /> live</span>} /><div className="trust-main"><div className="gauge" style={{ "--score": `${pattern.trust_score}%` } as React.CSSProperties}><div className="gauge-inner"><span>{pattern.trust_score}</span><small>/100</small></div></div><div className="trust-copy"><div className="pattern-key">{pattern.pattern_key}</div><p>{pattern.description}</p><div className="trust-updated"><Clock3 size={12} /> updated {formatRelative(pattern.updated_at)}</div></div></div><div className="trust-divider" /><div className="outcome-question"><div><div className="subheading"><History size={15} /> WHAT ACTUALLY HAPPENED?</div><p>Confirm the outcome to teach Driftline how much to trust this pattern.</p></div><div className="outcome-buttons"><button className="outcome-button outcome-button-fine" onClick={() => setOutcome(event.id, "fine")}><CheckCircle2 size={15} /> Mark outcome: Fine</button><button className="outcome-button outcome-button-incident" onClick={() => setOutcome(event.id, "caused_incident")}><AlertTriangle size={15} /> Caused a problem</button></div></div></section>
    </div>
    {event.iam_flag && <section className="panel iam-panel"><div className="iam-header"><div className="iam-icon"><LockKeyhole size={18} /></div><div><div className="section-kicker">FEATURE 04 / STRETCH SIGNAL</div><h2>IAM over-permission detected</h2></div><span className="iam-flag"><AlertTriangle size={13} /> scope expanded</span></div><div className="iam-grid"><div><span className="field-label">NEW SCOPE</span><code>{event.iam_flag.new_scope}</code></div><div><span className="field-label">HISTORICAL SCOPE</span><code>{event.iam_flag.historical_scope}</code></div><div><span className="field-label">FLAGGED PERMISSIONS</span><div className="permission-list">{event.iam_flag.flagged_permissions.map((permission) => <span key={permission}>{permission}</span>)}</div></div></div></section>}
    {audit && <div className="decision-record"><CheckCircle2 size={15} /> Decision recorded as <strong>{decisionLabel[audit.decision]}</strong> · {formatRelative(audit.timestamp)} <Link href="/audit">View audit log <ArrowUpRight size={13} /></Link></div>}
  </>;
}

function DecisionButton({ label, icon: Icon, decision, active, onClick }: { label: string; icon: typeof CheckCircle2; decision: Decision; active: boolean; onClick: () => void }) {
  return <button className={cn("decision-button", `decision-${decision}`, active && "decision-active")} onClick={onClick}><Icon size={16} /><span>{label}</span>{active && <span className="recommended-pill">recommended</span>}</button>;
}

function MatchCard({ match }: { match: HistoricalMatch }) {
  return <div className={cn("match-card", match.outcome === "caused_incident" && "match-card-incident")}><div className="match-card-top"><div className="match-icon"><History size={15} /></div><div className="match-copy"><div className="match-summary">{match.matched_event_summary}</div><div className="match-date"><CalendarDays size={12} /> {formatDate(match.matched_date)}</div></div><OutcomeBadge outcome={match.outcome} /></div><div className="similarity-row"><span>SIMILARITY</span><div className="similarity-track"><span style={{ width: `${match.similarity * 100}%` }} /></div><strong>{Math.round(match.similarity * 100)}%</strong></div></div>;
}

function AuditPage({ state }: { state: AppState }) {
  const [outcomeFilter, setOutcomeFilter] = useState("All outcomes");
  const [expanded, setExpanded] = useState<string | null>(null);
  const rows = state.audits.filter((audit) => outcomeFilter === "All outcomes" || outcomeMeta[audit.outcome].label === outcomeFilter);
  const getEvent = (id: string) => state.events.find((event) => event.id === id)!;
  const downloadCsv = () => {
    const header = "timestamp,resource,service,decision,outcome";
    const csv = [header, ...rows.map((audit) => { const event = getEvent(audit.drift_event_id); return [audit.timestamp, event.resource, event.service, audit.decision, audit.outcome].map((value) => `"${String(value).replaceAll('"', '""')}"`).join(","); })].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob); const anchor = document.createElement("a"); anchor.href = url; anchor.download = "driftline-audit-log.csv"; anchor.click(); URL.revokeObjectURL(url);
    toast.success("Audit CSV downloaded", { description: `${rows.length} evidence records exported.` });
  };
  return <>
    {state.failureMode && <InlineFailureBanner />}
    <PageTitle eyebrow="COMPLIANCE / EVIDENCE TRAIL" title="Audit Log" description="Every decision is paired with the evidence snapshot that informed it."><button className="button button-primary" onClick={downloadCsv}><Download size={15} /> Download CSV</button></PageTitle>
    <div className="audit-summary-row"><div className="audit-summary-card"><div className="audit-card-icon audit-card-icon-blue"><FileText size={17} /></div><div><span>DECISIONS LOGGED</span><strong>{state.audits.length}</strong></div></div><div className="audit-summary-card"><div className="audit-card-icon audit-card-icon-green"><CheckCircle2 size={17} /></div><div><span>OUTCOMES CONFIRMED</span><strong>{state.audits.filter((audit) => !["pending", "unknown"].includes(audit.outcome)).length}</strong></div></div><div className="audit-summary-card"><div className="audit-card-icon audit-card-icon-amber"><ShieldAlert size={17} /></div><div><span>EVIDENCE SOURCE</span><strong>Replay fixture</strong></div></div><div className="audit-summary-note"><Info size={15} /><span>Evidence is captured at decision time and remains exportable for review.</span></div></div>
    <div className="audit-toolbar"><div className="audit-toolbar-left"><Search size={15} /><span>Filter records</span><FilterSelect label="Outcome" value={outcomeFilter} options={["All outcomes", "Fine", "Caused incident", "Pending", "Unknown", "False positive"]} onChange={setOutcomeFilter} /></div><button className="button button-secondary button-small"><SlidersHorizontal size={14} /> Columns</button></div>
    <div className="audit-table-card"><div className="audit-table-head"><span>TIMESTAMP</span><span>RESOURCE</span><span>DECISION</span><span>OUTCOME</span><span>EVIDENCE</span></div>{rows.length === 0 ? <div className="empty-state compact-empty"><div className="empty-icon"><FileClock size={21} /></div><h3>No decisions recorded yet.</h3><p>Decision evidence will appear here once an engineer records an action.</p></div> : rows.map((audit) => { const event = getEvent(audit.drift_event_id); const isExpanded = expanded === audit.id; return <div key={audit.id} className={cn("audit-record", isExpanded && "audit-record-expanded")}><div className="audit-record-main"><div className="audit-time"><span>{formatDate(audit.timestamp)}</span><small>{new Date(audit.timestamp).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}</small></div><div className="audit-resource"><span>{event.resource}</span><small>{event.service} · {event.id}</small></div><div><span className={cn("decision-badge", `decision-badge-${audit.decision}`)}>{decisionLabel[audit.decision]}</span></div><div><OutcomeBadge outcome={audit.outcome} /></div><button className="evidence-view-button" onClick={() => setExpanded(isExpanded ? null : audit.id)}><Eye size={14} /> {isExpanded ? "Hide" : "View"}<ChevronRight size={14} className={cn(isExpanded && "rotate-90")} /></button></div>{isExpanded && <div className="evidence-json"><div className="json-header"><span><LockKeyhole size={12} /> evidence_snapshot</span><span>captured {formatRelative(audit.timestamp)}</span></div><pre>{audit.evidence_snapshot}</pre></div>}</div>; })}</div>
    <div className="feed-footer"><span>Showing {rows.length} of {state.audits.length} records</span><span className="footer-source"><FileClock size={13} /> Retention: session memory</span></div>
  </>;
}

function Reveal({ children, className = "", id }: { children: ReactNode; className?: string; id?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    const observer = new IntersectionObserver(([entry]) => { if (entry.isIntersecting) { setVisible(true); observer.disconnect(); } }, { threshold: 0.14 });
    observer.observe(node);
    return () => observer.disconnect();
  }, []);
  return <div ref={ref} id={id} className={cn("scroll-reveal", visible && "scroll-reveal-visible", className)}>{children}</div>;
}

function LandingPage() {
  const floatingCards = [
    { className: "landing-card-state", label: "EXPECTED STATE", title: "S3 bucket policy", meta: "guardrail / aligned", icon: ShieldCheck, tone: "mint" },
    { className: "landing-card-actor", label: "ACTOR CONFIDENCE", title: "Approved CI/CD", meta: "aws configuration drift", icon: CheckCircle2, tone: "blue" },
    { className: "landing-card-decision", label: "DECISION", title: "Review required", meta: "P1 · evidence ceiling", icon: AlertTriangle, tone: "red" },
    { className: "landing-card-window", label: "CHANGE WINDOW", title: "02:00 UTC", meta: "protected window", icon: Clock3, tone: "green" },
    { className: "landing-card-signal", label: "DRIFT SIGNAL", title: "IAM role policy", meta: "principal broadened", icon: LockKeyhole, tone: "amber" },
    { className: "landing-card-match", label: "HISTORICAL MATCH", title: "3 similar outcomes", meta: "2 approved · 1 review", icon: History, tone: "gold" },
    { className: "landing-card-remediation", label: "REMEDIATION", title: "Human approval", meta: "pushback ready", icon: ArrowUpRight, tone: "teal" },
    { className: "landing-card-audit", label: "AUDIT TRAIL", title: "Evidence attached", meta: "exportable snapshot", icon: FileText, tone: "purple" },
  ];
  const processFrames = [
    { sources: 4, latency: "02.4s", evidence: 4, confidence: 92, decision: "review" },
    { sources: 5, latency: "01.8s", evidence: 6, confidence: 96, decision: "approve" },
    { sources: 3, latency: "03.1s", evidence: 3, confidence: 84, decision: "condition" },
  ];
  const [processFrame, setProcessFrame] = useState(0);
  useEffect(() => {
    const timer = window.setInterval(() => setProcessFrame((current) => (current + 1) % processFrames.length), 3600);
    return () => window.clearInterval(timer);
  }, [processFrames.length]);
  const live = processFrames[processFrame];
  return <div className="landing-page">
    <header className="landing-header"><Link href="/" className="landing-brand"><span className="landing-brand-orbit" /><span>Driftline</span></Link><nav><a href="#why-driftline">Why Driftline</a><a href="#how-it-works">How it works</a><Link href="/console">Console</Link></nav><div className="landing-header-actions"><Link href="/signin" className="landing-signin">Sign in</Link><Link href="/console" className="landing-open-console">Open console <ArrowUpRight size={15} /></Link></div></header>
    <main className="landing-hero" id="landing-top">
      <div className="landing-orbit landing-orbit-outer" /><div className="landing-orbit landing-orbit-inner" />
      <div className="landing-card-orbit">{floatingCards.map((card) => { const Icon = card.icon; return <div key={card.label} className={cn("landing-card", card.className, `landing-card-${card.tone}`)}><div className="landing-card-label">{card.label}<span><Icon size={13} /></span></div><strong>{card.title}</strong><small>{card.meta}</small></div>; })}</div>
      <div className="landing-kicker"><span className="landing-kicker-dot" /> AWS CONFIGURATION DRIFT GOVERNANCE</div>
      <h1>Infrastructure<br />changes.<br /><em>Clearly</em><br /><em>accounted</em><br /><em>for.</em></h1>
      <p className="landing-deck">Driftline connects what changed with who changed it, why it matters, and what your team should do next.</p>
      <div className="landing-hero-actions"><Link href="/console" className="landing-primary-cta">Open the console <ArrowUpRight size={17} /></Link><a href="#how-it-works" className="landing-secondary-cta">Explore capabilities <ArrowUpRight size={15} /></a></div>
    </main>
    <Reveal className="landing-editorial-section landing-why" id="why-driftline"><div className="landing-editorial-index">01 / WHY DRIFTLINE</div><div className="landing-editorial-copy"><h2>Context is the<br /><em>control plane.</em></h2><p>Most drift tools stop at “something changed.” Driftline connects the resource, actor, intent, evidence, and historical outcome so the next action is clear before the next deploy.</p><Link href="/console" className="landing-text-link">Explore the live signal feed <ArrowUpRight size={15} /></Link></div><div className="landing-proof-grid"><div><strong>01</strong><span>what changed</span></div><div><strong>02</strong><span>who changed it</span></div><div><strong>03</strong><span>why it matters</span></div><div><strong>04</strong><span>what to do next</span></div></div></Reveal>
    <Reveal className="landing-editorial-section landing-how" id="how-it-works"><div className="landing-editorial-index">02 / HOW IT WORKS</div><div className="landing-editorial-copy"><h2>From drift signal<br />to <em>accountable action.</em></h2><p>Signals move through a calm, deterministic sequence: correlate the change, score the risk, recommend the response, then remember the outcome.</p></div><div className="landing-process"><div className="landing-process-step"><span>01</span><div className="landing-process-content"><div className="process-diagram process-diagram-correlate diagram-interactive" tabIndex={0} role="img" aria-label={`Correlate diagram: ${live.sources} sources connected in ${live.latency}`}><span className="diagram-live-tag"><span className="diagram-live-dot" /> LIVE · {live.sources} SOURCES</span><span className="process-node process-node-a"><Activity size={13} /></span><span className="process-node process-node-b"><CloudCog size={13} /></span><span className="process-node process-node-c"><GitBranch size={13} /></span><i className="process-signal-line" /><span className="diagram-detail">{live.sources} sources correlated <b>{live.latency}</b></span></div><strong>Correlate</strong><p>Join AWS Config, CloudTrail, IaC, and deployment context.</p></div></div><div className="landing-process-line" /><div className="landing-process-step"><span>02</span><div className="landing-process-content"><div className="process-diagram process-diagram-explain diagram-interactive" tabIndex={0} role="img" aria-label={`Explain diagram: ${live.evidence} evidence points attached`}><span className="diagram-live-tag"><span className="diagram-live-dot" /> {live.evidence} EVIDENCE POINTS</span><span className="evidence-sheet evidence-sheet-back" /><span className="evidence-sheet evidence-sheet-mid" /><span className="evidence-sheet evidence-sheet-front"><CheckCircle2 size={14} /></span><span className="evidence-spark evidence-spark-one" /><span className="evidence-spark evidence-spark-two" /><span className="diagram-detail">Evidence attached <b>{live.confidence}% confidence</b></span></div><strong>Explain</strong><p>Show the evidence and the historical matches behind the score.</p></div></div><div className="landing-process-line" /><div className="landing-process-step"><span>03</span><div className="landing-process-content"><div className="process-diagram process-diagram-decide diagram-interactive" tabIndex={0} role="img" aria-label={`Decide diagram: recommended outcome ${live.decision}`}><span className="diagram-live-tag"><span className="diagram-live-dot" /> RECOMMEND · {live.decision.toUpperCase()}</span><span className="decision-root"><GitBranch size={14} /></span><span className="decision-branch decision-branch-a"><Check size={12} /></span><span className="decision-branch decision-branch-b"><AlertTriangle size={12} /></span><span className="decision-branch decision-branch-c"><Ban size={12} /></span><i className="decision-line decision-line-a" /><i className="decision-line decision-line-b" /><i className="decision-line decision-line-c" /><span className="diagram-detail">Next action <b>record decision</b></span></div><strong>Decide</strong><p>Approve, condition, or block with an exportable audit trail.</p></div></div></div><Link href="/console" className="landing-primary-cta landing-process-cta">Open the console <ArrowUpRight size={17} /></Link></Reveal>
    <Reveal className="landing-capabilities" id="capabilities"><div><span>03 / OPERATING MODEL</span><h2>One memory layer<br />for every change.</h2></div><p>Every decision becomes part of a growing operational memory, making the next risk faster to understand and easier to act on.</p><Link href="/audit" className="landing-text-link">View the evidence trail <ArrowUpRight size={15} /></Link></Reveal>
  </div>;
}

function SettingsPage({ state, setState }: { state: AppState; setState: (updater: (current: AppState) => AppState) => void }) {
  return <>
    <PageTitle eyebrow="CONTROL PLANE / LOCAL CONFIG" title="Settings" description="Tune the replay experience without changing the evidence model." />
    <div className="settings-layout"><div className="settings-main"><section className="panel settings-panel"><SectionHeading kicker="DEMO CONTROLS" title="Failure handling" action={<span className={cn("setting-status", state.failureMode ? "setting-status-on" : "setting-status-off")}>{state.failureMode ? "enabled" : "disabled"}</span>} /><div className="setting-row"><div className="setting-row-icon"><RefreshCw size={17} /></div><div className="setting-row-copy"><strong>Simulate data source failure</strong><p>Simulates the mock data source failing to load. Drift Feed, Risk Detail, and Audit Log keep rendering the last-known state with a calm inline banner.</p><span className="setting-note"><Info size={12} /> This is a demo control, not a real AWS outage toggle.</span></div><button className={cn("toggle", state.failureMode && "toggle-on")} onClick={() => setState((current) => ({ ...current, failureMode: !current.failureMode }))} role="switch" aria-checked={state.failureMode}><span /></button></div></section><section className="panel settings-panel settings-muted"><SectionHeading kicker="EVIDENCE CONFIGURATION" title="Replay source" /><div className="settings-grid"><div><span>DRIFT SIGNAL</span><strong><CloudCog size={15} /> AWS Config-shaped fixture</strong></div><div><span>HISTORY</span><strong><History size={15} /> CloudTrail-shaped fixture</strong></div><div><span>REASONING</span><strong><Sparkles size={15} /> Deterministic fallback</strong></div><div><span>REGION</span><strong><Server size={15} /> ap-south-1</strong></div></div></section></div><aside className="settings-side"><div className="settings-side-illustration"><div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="orbit-core"><GitBranch size={25} /></div></div><div className="section-kicker">SYSTEM BEHAVIOR</div><h3>Graceful by default</h3><p>When an upstream signal is unavailable, Driftline falls back to the last loaded state instead of hiding evidence or showing a blank screen.</p><div className="settings-check"><CheckCircle2 size={14} /> data failure and app crash remain distinct</div><div className="settings-check"><CheckCircle2 size={14} /> evidence source is always visible</div><div className="settings-check"><CheckCircle2 size={14} /> no persistence outside this session</div></aside></div>
  </>;
}

function NotFoundPage() {
  return <div className="not-found"><div className="not-found-icon"><CircleHelp size={24} /></div><div className="eyebrow-row">404 / SIGNAL NOT FOUND</div><h1>Event not found</h1><p>This resource may have been archived or the link is invalid.</p><Link className="button button-secondary" href="/"><ArrowLeft size={15} /> Return to drift feed</Link></div>;
}

function GenericErrorFallback() {
  return <div className="crash-screen"><div className="crash-icon"><AlertTriangle size={25} /></div><div className="eyebrow-row">APPLICATION ERROR</div><h1>Something went wrong</h1><p>The application hit an unexpected error. Refresh the page to try again.</p><button className="button button-primary" onClick={() => window.location.reload()}><RefreshCw size={15} /> Refresh application</button></div>;
}

function SignInPage({ onSignedIn }: { onSignedIn: () => void }) {
  const [, setLocation] = useLocation();
  const [email, setEmail] = useState("operator@driftline.dev");
  const [password, setPassword] = useState("driftline-demo");
  const nextPath = new URLSearchParams(window.location.search).get("next") || "/console";
  const submit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!email || !password) return;
    window.sessionStorage.setItem("driftline-signed-in", "true");
    onSignedIn();
    setLocation(nextPath);
  };
  return <div className="auth-page"><header className="auth-header"><Link href="/" className="landing-brand"><span className="landing-brand-orbit" /><span>Driftline</span></Link><span className="auth-header-note">DECISION INTELLIGENCE</span></header><main className="auth-main"><div className="auth-visual"><div className="auth-orbit auth-orbit-one" /><div className="auth-orbit auth-orbit-two" /><div className="auth-visual-core"><GitBranch size={28} /></div><span className="auth-float auth-float-one"><Activity size={15} /> signal feed</span><span className="auth-float auth-float-two"><ShieldCheck size={15} /> evidence ready</span><span className="auth-float auth-float-three"><CheckCircle2 size={15} /> accountable</span></div><section className="auth-card"><div className="landing-kicker"><span className="landing-kicker-dot" /> SECURE OPERATIONS ACCESS</div><h1>Welcome back.</h1><p>Sign in to open your Driftline decision intelligence console.</p><form onSubmit={submit}><label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" required /></label><label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required /></label><button className="landing-primary-cta auth-submit" type="submit">Continue to console <ArrowUpRight size={16} /></button></form><div className="auth-demo-note"><LockKeyhole size={13} /><span>Demo access is prefilled. No external account is required.</span></div><Link href="/" className="auth-back"><ArrowLeft size={14} /> Back to Driftline home</Link></section></main></div>;
}

function Router({ state, setState, setDecision, setOutcome }: { state: AppState; setState: (updater: (current: AppState) => AppState) => void; setDecision: (id: string, decision: Decision) => void; setOutcome: (id: string, outcome: Outcome) => void }) {
  const [location] = useLocation();
  if (location === "/console") return <FeedPage state={state} />;
  if (location === "/audit") return <AuditPage state={state} />;
  if (location === "/settings") return <SettingsPage state={state} setState={setState} />;
  if (location.startsWith("/events/")) return <RiskDetailPage state={state} eventId={location.split("/")[2] ?? ""} setDecision={setDecision} setOutcome={setOutcome} />;
  return <NotFoundPage />;
}

function App() {
  const { state, setState, setDecision, setOutcome } = useDriftlineState();
  const [location] = useLocation();
  const [signedIn, setSignedIn] = useState(() => window.sessionStorage.getItem("driftline-signed-in") === "true");
  const needsAuth = location !== "/" && location !== "/signin";
  const content = location === "/" ? <LandingPage /> : location === "/signin" || (!signedIn && needsAuth) ? <SignInPage onSignedIn={() => setSignedIn(true)} /> : <Shell state={state} currentPath={location}><Router state={state} setState={setState} setDecision={setDecision} setOutcome={setOutcome} /></Shell>;
  return <ErrorBoundary>{content}<Toaster theme="dark" position="bottom-right" toastOptions={{ className: "drift-toast" }} /></ErrorBoundary>;
}

export default App;
