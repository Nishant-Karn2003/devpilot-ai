import { useEffect, useState } from 'react';
import Editor from '@monaco-editor/react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Activity, AlertTriangle, ArrowUpRight, Check, ChevronDown, Code2, FileCode2, GitPullRequest, History, LayoutDashboard, LockKeyhole, LogOut, Package, Plus, Search, Settings2, ShieldCheck, Sparkles, X } from 'lucide-react';
import { Link, NavLink, Route, Routes, useNavigate, useParams } from 'react-router-dom';
import { api, authenticate, getToken, saveToken } from './api';
import type { Analysis, Finding, PatchSuggestion, Severity } from './types';

const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const prettyDate = (value: string) => new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });

function App() {
  const queryClient = useQueryClient();
  const [signedIn, setSignedIn] = useState(Boolean(getToken()));
  useEffect(() => {
    const handleUnauthorized = () => {
      queryClient.clear();
      setSignedIn(false);
    };
    window.addEventListener('devpilot:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('devpilot:unauthorized', handleUnauthorized);
  }, [queryClient]);
  return signedIn
    ? <Workspace onLogout={() => { saveToken(null); queryClient.clear(); setSignedIn(false); }} />
    : <AuthScreen onSignedIn={() => { queryClient.clear(); setSignedIn(true); }} />;
}

function AuthScreen({ onSignedIn }: { onSignedIn: () => void }) {
  const [registering, setRegistering] = useState(false);
  const [error, setError] = useState('');
  const mutation = useMutation({
    mutationFn: (data: { email: string; password: string }) => authenticate(registering ? 'register' : 'login', data),
    onSuccess: onSignedIn,
    onError: (failure: Error) => setError(failure.message),
  });
  return <main className="auth-shell">
    <section className="auth-card">
      <div className="brand brand-large"><span className="brand-mark"><Sparkles size={19} /></span><span>DevPilot <b>AI</b></span></div>
      <p className="eyebrow">ENGINEERING INTELLIGENCE</p><h1>{registering ? 'Create your workspace' : 'Welcome back'}</h1>
      <p className="muted">Review code quality with transparent, evidence-based analysis.</p>
      <form onSubmit={event => { event.preventDefault(); const form = new FormData(event.currentTarget); mutation.mutate({ email: String(form.get('email')), password: String(form.get('password')) }); }}>
        <label>Email address<input required type="email" name="email" autoComplete="email" placeholder="you@company.com" /></label>
        <label>Password<input required minLength={12} type="password" name="password" autoComplete={registering ? 'new-password' : 'current-password'} placeholder="At least 12 characters" /></label>
        {error && <p className="error-banner" role="alert">{error}</p>}
        <button className="button primary full" disabled={mutation.isPending}>{mutation.isPending ? 'Connecting…' : registering ? 'Create account' : 'Sign in'}<ArrowUpRight size={16} /></button>
      </form>
      <p className="auth-switch">{registering ? 'Already have an account?' : 'New to DevPilot?'} <button onClick={() => { setError(''); setRegistering(!registering); }}>{registering ? 'Sign in' : 'Create account'}</button></p>
      <div className="auth-foot"><LockKeyhole size={14} /> Passwords are hashed; reports are private to your account.</div>
    </section>
  </main>;
}

function Workspace({ onLogout }: { onLogout: () => void }) {
  const overview = useQuery({ queryKey: ['overview'], queryFn: api.overview });
  const analyses = useQuery({ queryKey: ['analyses'], queryFn: api.analyses });
  const health = useQuery({ queryKey: ['health'], queryFn: api.health });
  const links = [
    { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
    { to: '/analyze', label: 'Code analysis', icon: Code2 },
    { to: '/diff', label: 'Diff review', icon: GitPullRequest },
    { to: '/dependencies', label: 'Dependencies', icon: Package },
    { to: '/history', label: 'Analysis history', icon: History },
    { to: '/settings', label: 'Settings', icon: Settings2 },
  ];
  return <div className="app-shell">
    <aside className="sidebar">
      <Link to="/" className="brand"><span className="brand-mark"><Sparkles size={17} /></span><span>DevPilot <b>AI</b></span></Link>
      <div className="workspace-select"><span className="workspace-icon">D</span><span><b>Personal workspace</b><small>Local account</small></span><ChevronDown size={15} /></div>
      <p className="nav-label">WORKSPACE</p>
      <nav>{links.map(({ to, label, icon: Icon, end }) => <NavLink key={to} to={to} end={end} className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}><Icon size={17} />{label}</NavLink>)}</nav>
      <div className="sidebar-bottom">
        <div className="system-state"><span className={`pulse ${health.data ? 'ok' : ''}`} /><span>{health.isLoading ? 'Connecting to API' : health.isError ? 'API unavailable' : 'Analysis services online'}</span><span className="state-dot" /></div>
        <button className="nav-item logout" onClick={onLogout}><LogOut size={17} />Sign out</button>
        <div className="profile"><span className="avatar">DP</span><div><b>Developer</b><small>Personal account</small></div><button aria-label="Sign out" onClick={onLogout}><LogOut size={15} /></button></div>
      </div>
    </aside>
    <main className="main-area">
      <header className="topbar"><div className="breadcrumb">Workspace <span>/</span> <b><Routes><Route path="/analyze" element="Code analysis" /><Route path="/diff" element="Diff review" /><Route path="/dependencies" element="Dependencies" /><Route path="/history" element="Analysis history" /><Route path="/settings" element="Settings" /><Route path="/report/:id" element="Review report" /><Route path="*" element="Overview" /></Routes></b></div><div className="top-actions"><span className="api-status"><span className={`pulse ${health.data ? 'ok' : ''}`} />{health.isError ? 'API offline' : 'API connected'}</span><span className="avatar small">DP</span></div></header>
      <Routes>
        <Route path="/" element={<OverviewPage data={overview.data} loading={overview.isLoading} error={overview.error} />} />
        <Route path="/analyze" element={<AnalyzePage />} />
        <Route path="/diff" element={<DiffPage />} />
        <Route path="/dependencies" element={<DependenciesPage />} />
        <Route path="/history" element={<HistoryPage data={analyses.data} loading={analyses.isLoading} error={analyses.error} />} />
        <Route path="/report/:id" element={<ReportPage />} />
        <Route path="/settings" element={<SettingsPage llmConfigured={health.data?.llm_configured} error={health.isError} />} />
        <Route path="*" element={<OverviewPage data={overview.data} loading={overview.isLoading} error={overview.error} />} />
      </Routes>
    </main>
  </div>;
}

function PageHeader({ kicker, title, description, action }: { kicker: string; title: string; description: string; action?: React.ReactNode }) {
  return <div className="page-header"><div><p className="eyebrow">{kicker}</p><h1>{title}</h1><p className="muted">{description}</p></div>{action}</div>;
}

function OverviewPage({ data, loading, error }: { data?: Awaited<ReturnType<typeof api.overview>>; loading: boolean; error: Error | null }) {
  const distribution = severityOrder.map(severity => ({ name: severity, value: data?.severity_distribution[severity] ?? 0 })).filter(item => item.value > 0);
  const colors: Record<string, string> = { critical: '#fb7185', high: '#fb923c', medium: '#fbbf24', low: '#60a5fa', info: '#a78bfa' };
  return <section className="page">
    <PageHeader kicker="YOUR ENGINEERING PULSE" title="Overview" description="A live snapshot of your analyzed source and review activity." action={<Link className="button primary" to="/analyze"><Plus size={17} />New analysis</Link>} />
    {error && <ErrorNotice message={error.message} />}
    {loading ? <Loading /> : data && <><div className="metrics-grid">
      <Metric icon={<FileCode2 />} label="Analyses run" value={data.analysis_count} detail="All time · your account" />
      <Metric icon={<AlertTriangle />} label="Findings detected" value={Object.values(data.severity_distribution).reduce((a, b) => a + b, 0)} detail="Across completed reports" />
      <Metric icon={<ShieldCheck />} label="Critical findings" value={data.severity_distribution.critical ?? 0} detail="Secret-pattern matches included" />
      <Metric icon={<Activity />} label="Analysis mode" value="Deterministic" detail="AI review is optional" />
    </div>
    <div className="overview-grid">
      <section className="panel chart-panel"><div className="panel-heading"><div><h2>Finding severity</h2><p>Current snapshot from persisted reports</p></div><span className="chart-legend"><i />Findings</span></div>
        {distribution.length ? <div className="chart-wrap"><div className="donut" style={{ background: `conic-gradient(${distribution.map((item, index) => `${colors[item.name]} ${distribution.slice(0, index).reduce((s, x) => s + x.value, 0) / distribution.reduce((s, x) => s + x.value, 0) * 100}% ${distribution.slice(0, index + 1).reduce((s, x) => s + x.value, 0) / distribution.reduce((s, x) => s + x.value, 0) * 100}%`).join(', ')})` }}><div><b>{distribution.reduce((s, x) => s + x.value, 0)}</b><small>findings</small></div></div><div className="legend-list">{severityOrder.map(key => <div key={key}><span><i style={{ background: colors[key] }} />{key}</span><b>{data.severity_distribution[key] ?? 0}</b></div>)}</div></div> : <EmptyState icon={<Activity />} title="No findings yet" description="Run an analysis to see your severity snapshot." action={<Link to="/analyze" className="text-link">Analyze code <ArrowUpRight size={14} /></Link>} />}
      </section>
      <section className="panel activity-panel"><div className="panel-heading"><div><h2>Recent activity</h2><p>Your latest persisted analyses</p></div><Link className="text-link" to="/history">View history <ArrowUpRight size={14} /></Link></div>
        {data.recent_analyses.length ? <div className="activity-list">{data.recent_analyses.map(item => <Link to={`/report/${item.id}`} key={item.id} className="activity-row"><span className="file-icon"><Code2 size={16} /></span><span className="activity-info"><b>{item.source_name}</b><small>{item.language} · {prettyDate(item.created_at)}</small></span><span className={`status-badge ${item.status}`}>{item.status}</span><span className="finding-count">{item.findings} findings</span><ArrowUpRight size={15} /></Link>)}</div> : <EmptyState icon={<History />} title="Nothing reviewed yet" description="Your completed analysis reports will appear here." action={<Link to="/analyze" className="text-link">Start an analysis <ArrowUpRight size={14} /></Link>} />}
      </section>
    </div><div className="notice-line"><ShieldCheck size={15} />{data.snapshot_note} A clean result does not prove code is defect-free.</div></>}
  </section>;
}

function Metric({ icon, label, value, detail }: { icon: React.ReactNode; label: string; value: React.ReactNode; detail: string }) {
  return <div className="metric-card"><div className="metric-top"><span>{label}</span><i>{icon}</i></div><strong>{value}</strong><small>{detail}</small></div>;
}

function AnalyzePage() {
  const [language, setLanguage] = useState('python');
  const [gateThreshold, setGateThreshold] = useState('high');
  const [filename, setFilename] = useState('main.py');
  const [code, setCode] = useState('import os\n\n\ndef load_config(path):\n    try:\n        with open(path) as file:\n            return file.read()\n    except:\n        return None\n');
  const [error, setError] = useState('');
  const client = useQueryClient();
  const navigate = useNavigate();
  const mutation = useMutation({
    mutationFn: api.submit,
    onSuccess: result => { client.invalidateQueries({ queryKey: ['analyses'] }); client.invalidateQueries({ queryKey: ['overview'] }); navigate(`/report/${result.id}`); },
    onError: (failure: Error) => setError(failure.message),
  });
  return <section className="page"><PageHeader kicker="STATIC ANALYSIS" title="Analyze source" description="Submit source text for syntax checks, AST analysis, and redacted secret-pattern scanning." />
    {error && <ErrorNotice message={error} />}
    <div className="editor-panel panel"><div className="editor-toolbar"><div className="editor-file"><span className="file-icon"><Code2 size={15} /></span><input aria-label="File name" value={filename} onChange={e => setFilename(e.target.value)} /><span className="editor-dot" /></div><div className="editor-options"><label>Language<select value={language} onChange={e => { setLanguage(e.target.value); setFilename(e.target.value === 'python' ? 'main.py' : e.target.value === 'typescript' ? 'main.ts' : 'main.js'); }}><option value="python">Python</option><option value="javascript">JavaScript</option><option value="typescript">TypeScript</option></select></label><label>Gate threshold<select aria-label="Gate threshold" value={gateThreshold} onChange={event => setGateThreshold(event.target.value)}><option value="critical">Critical+</option><option value="high">High+</option><option value="medium">Medium+</option><option value="low">Low+</option></select></label><span className="editor-limit">{new TextEncoder().encode(code).length.toLocaleString()} / 100,000 bytes</span></div></div>
      <Editor height="390px" language={language} theme="vs-dark" value={code} onChange={value => setCode(value ?? '')} options={{ minimap: { enabled: false }, fontSize: 13, padding: { top: 18 }, scrollBeyondLastLine: false, automaticLayout: true, tabSize: 4, wordWrap: 'on' }} />
      <div className="editor-footer"><span><span className="pulse ok" />Ready · source is not executed</span><button className="button primary" disabled={mutation.isPending || !code.trim()} onClick={() => { setError(''); mutation.mutate({ code, language, file_name: filename || 'pasted-source', fail_on_severity: gateThreshold }); }}><Sparkles size={16} />{mutation.isPending ? 'Submitting…' : 'Run analysis'}<ArrowUpRight size={15} /></button></div>
    </div>
    <div className="info-cards"><InfoCard icon={<Code2 />} title="Deterministic by default" text="Python AST rules detect syntax errors, unused imports, and bare exception handlers. JS/TS uses ESLint when installed, otherwise a bounded delimiter fallback." /><InfoCard icon={<LockKeyhole />} title="No code execution" text="Submitted source is parsed as text only. Analysis does not run submitted code or access local repositories." /><InfoCard icon={<ShieldCheck />} title="Redacted secrets" text="Recognized secret patterns are reported with matched values redacted in evidence." /></div>
  </section>;
}

function DiffPage() {
  const [diff, setDiff] = useState('diff --git a/example.py b/example.py\nindex 2ab7c..9dcfe 100644\n--- a/example.py\n+++ b/example.py\n@@ -1,0 +1,3 @@\n+import os\n+\n+def read_config(path):\n+    try:\n+        return open(path).read()\n+    except:\n+        return None\n');
  const [gateThreshold, setGateThreshold] = useState('high');
  const [error, setError] = useState('');
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const mutation = useMutation({ mutationFn: (source: string) => api.diff(source, gateThreshold), onSuccess: result => { queryClient.invalidateQueries({ queryKey: ['analyses'] }); queryClient.invalidateQueries({ queryKey: ['overview'] }); navigate(`/report/${result.id}`); }, onError: (failure: Error) => setError(failure.message) });
  return <section className="page"><PageHeader kicker="CHANGE REVIEW" title="Review a diff" description="Upload unified Git diff text. Only added lines are sent through source analysis; no GitHub credentials are required." />
    {error && <ErrorNotice message={error} />}
    <div className="panel diff-panel"><div className="panel-heading"><div><h2>Unified diff</h2><p>Paste a supported .py, .js, or .ts diff (up to 100 KB).</p></div><span className="outline-tag"><GitPullRequest size={14} />Manual diff</span></div><textarea className="diff-editor" aria-label="Unified diff" spellCheck={false} value={diff} onChange={event => setDiff(event.target.value)} /><div className="editor-footer"><div className="editor-options"><span><span className="pulse ok" />No external repository will be modified</span><label>Gate threshold<select aria-label="Gate threshold" value={gateThreshold} onChange={event => setGateThreshold(event.target.value)}><option value="critical">Critical+</option><option value="high">High+</option><option value="medium">Medium+</option><option value="low">Low+</option></select></label></div><button className="button primary" disabled={mutation.isPending || !diff.trim()} onClick={() => { setError(''); mutation.mutate(diff); }}><GitPullRequest size={16} />{mutation.isPending ? 'Submitting…' : 'Analyze changes'}<ArrowUpRight size={15} /></button></div></div>
    <div className="notice-box"><AlertTriangle size={17} /><span><b>Review scope limitation</b> Diff reports analyze added lines as a source fragment; deletion context, exact original line mapping, baseline comparison, and pull-request publishing are not currently implemented.</span></div>
  </section>;
}

function DependenciesPage() {
  const [ecosystem, setEcosystem] = useState<'python' | 'npm'>('python');
  const [manifest, setManifest] = useState('');
  const [lockfile, setLockfile] = useState('');
  const [scanId, setScanId] = useState('');
  const [error, setError] = useState('');
  const client = useQueryClient();
  const history = useQuery({ queryKey: ['dependency-scans'], queryFn: api.dependencyScans });
  const scan = useQuery({
    queryKey: ['dependency-scan', scanId],
    queryFn: () => api.dependencyScan(scanId),
    enabled: Boolean(scanId),
    refetchInterval: query => ['queued', 'running'].includes(query.state.data?.status ?? '') ? 1000 : false,
  });
  const mutation = useMutation({
    mutationFn: api.scanDependencies,
    onSuccess: result => {
      setScanId(result.id);
      setError('');
      client.invalidateQueries({ queryKey: ['dependency-scans'] });
    },
    onError: (failure: Error) => setError(failure.message),
  });
  const report = scan.data;
  return <section className="page"><PageHeader kicker="DEPENDENCY INTELLIGENCE" title="Dependencies" description="Inventory Python and npm packages, then query the real OSV vulnerability database for exact resolved versions." />
    {error && <ErrorNotice message={error} />}
    {scan.error && <ErrorNotice message={scan.error.message} />}
    {scan.isLoading && scanId && <Loading />}
    <div className="panel dependency-form"><div className="panel-heading"><div><h2>Scan dependency manifests</h2><p>Analysis does not install packages or execute manifest contents.</p></div><span className="outline-tag"><ShieldCheck size={14} />OSV database</span></div>
      <div className="dependency-fields"><label>Ecosystem<select value={ecosystem} onChange={event => { setEcosystem(event.target.value as 'python' | 'npm'); setManifest(''); setLockfile(''); }}><option value="python">Python · requirements.txt</option><option value="npm">npm · package.json</option></select></label><label>Manifest<textarea aria-label="Dependency manifest" spellCheck={false} placeholder={ecosystem === 'python' ? 'requests>=2.0\\nfastapi==0.115.0' : '{\\n  "dependencies": {\\n    "example": "^1.0.0"\\n  }\\n}'} value={manifest} onChange={event => setManifest(event.target.value)} /></label><label>Lockfile <span className="optional">(optional, recommended for resolved versions)</span><textarea aria-label="Dependency lockfile" spellCheck={false} placeholder={ecosystem === 'python' ? 'Pinned requirements, one package per line' : 'package-lock.json (lockfile v2 or v3)'} value={lockfile} onChange={event => setLockfile(event.target.value)} /></label></div>
      <div className="editor-footer"><span><LockKeyhole size={14} />Only package names and exact versions are sent to OSV; manifest URLs are ignored.</span><button className="button primary" disabled={mutation.isPending || !manifest.trim()} onClick={() => { setError(''); setScanId(''); mutation.mutate({ ecosystem, manifest, lockfile }); }}><ShieldCheck size={15} />{mutation.isPending ? 'Submitting…' : 'Inventory & scan'}</button></div>
    </div>
    {report && <section className="panel dependency-report"><div className="panel-heading"><div><h2>Scan report <span className={`status-badge ${report.status}`}>{report.status}</span></h2><p>{report.ecosystem} · {prettyDate(report.created_at)}</p></div><span className="count-pill">{report.inventory.length} packages</span></div>
      {report.status === 'running' || report.status === 'queued' ? <div className="loading-state"><span className="spinner" />Querying OSV for exact locked versions…</div> : report.status === 'failed' ? <ErrorNotice message={report.error_message ?? 'Vulnerability lookup failed.'} /> : <>
        {report.warnings.map((warning, index) => (
          <div className="notice-line" key={`${warning}-${index}`}>
            <AlertTriangle size={14} />
            {warning}
          </div>
        ))}
        <div className="dependency-summary"><Metric icon={<Package />} label="Inventory" value={report.inventory.length} detail="Declared and resolved packages" /><Metric icon={<ShieldCheck />} label="OSV advisories" value={report.vulnerabilities.length} detail="Records returned for locked versions" /><Metric icon={<LockKeyhole />} label="Unresolved versions" value={report.inventory.filter(item => !item.resolved_version).length} detail="Not queried by OSV" /></div>
        {report.vulnerabilities.length > 0 && <div className="vulnerability-list">{report.vulnerabilities.map(vulnerability => <article className="vulnerability-card" key={`${vulnerability.package_name}-${vulnerability.resolved_version}-${vulnerability.id}`}><div className="finding-title"><span className={`severity-tag ${vulnerability.severity}`}>{vulnerability.severity}</span><b>{vulnerability.id}</b><code>{vulnerability.package_name}@{vulnerability.resolved_version}</code></div><p>{vulnerability.summary}</p>{vulnerability.aliases.length > 0 && <small>Aliases: {vulnerability.aliases.join(', ')}</small>}{vulnerability.references.map(reference => <a className="text-link" href={reference} target="_blank" rel="noreferrer" key={reference}>Advisory reference <ArrowUpRight size={13} /></a>)}</article>)}</div>}
        <div className="table-scroll"><table><thead><tr><th>Package</th><th>Relationship</th><th>Declared</th><th>Resolved</th><th>OSV status</th></tr></thead><tbody>{report.inventory.map((item, index) => { const hasAlert = report.vulnerabilities.some(alert => alert.package_name === item.name && alert.resolved_version === item.resolved_version); return <tr key={`${item.name}-${item.resolved_version}-${index}`}><td>{item.name}</td><td>{item.direct ? 'Direct' : 'Transitive'}</td><td>{item.declared_spec || '—'}</td><td>{item.resolved_version ?? 'Unresolved'}</td><td>{item.resolved_version ? hasAlert ? 'Advisory returned' : 'No advisory returned' : 'Not scanned'}</td></tr>; })}</tbody></table></div>
      </>}
    </section>}
    <section className="panel dependency-history"><div className="panel-heading"><div><h2>Recent scans</h2><p>Persisted dependency intelligence for your account</p></div></div>{history.isLoading ? <Loading /> : history.error ? <ErrorNotice message={history.error.message} /> : history.data?.length ? <div className="activity-list">{history.data.map(item => <button className={`activity-row dependency-history-row${item.id === scanId ? ' selected' : ''}`} key={item.id} onClick={() => { setScanId(item.id); setError(''); }}><span className="file-icon"><Package size={15} /></span><span className="activity-info"><b>{item.ecosystem} dependency scan</b><small>{prettyDate(item.created_at)} · {item.inventory.length} packages</small></span><span className={`status-badge ${item.status}`}>{item.status}</span><span className="finding-count">{item.vulnerabilities.length} advisories</span></button>)}</div> : <EmptyState icon={<Package />} title="No dependency scans yet" description="Submit a manifest to see its package inventory and OSV results." />}
    </section>
    <div className="notice-box"><AlertTriangle size={17} /><span><b>Data-source and coverage limits</b> Exact resolved versions are queried against OSV over HTTPS. The service must be reachable; no local cache or offline CVE feed is included. Missing lockfiles leave ranges unresolved, and “no advisory returned” is not proof that a package is vulnerability-free.</span></div>
  </section>;
}

function HistoryPage({ data, loading, error }: { data?: Analysis[]; loading: boolean; error: Error | null }) {
  const [filter, setFilter] = useState('');
  const rows = data?.filter(row => `${row.source_name} ${row.language} ${row.status}`.toLowerCase().includes(filter.toLowerCase())) ?? [];
  return <section className="page"><PageHeader kicker="YOUR REPORT ARCHIVE" title="Analysis history" description="Review the reports and findings saved to your account." />
    <div className="panel history-panel"><div className="history-tools"><div className="search-field"><Search size={16} /><input aria-label="Filter analyses" placeholder="Filter by file, language, status…" value={filter} onChange={event => setFilter(event.target.value)} /></div><span>{data?.length ?? 0} reports</span></div>
      {error ? <ErrorNotice message={error.message} /> : loading ? <Loading /> : rows.length ? <div className="table-scroll"><table><thead><tr><th>Source</th><th>Language</th><th>Status</th><th>Findings</th><th>Created</th><th /></tr></thead><tbody>{rows.map(row => <tr key={row.id}><td><Link to={`/report/${row.id}`} className="source-link"><span className="file-icon"><Code2 size={15} /></span>{row.source_name}</Link></td><td><span className="language-tag">{row.language}</span></td><td><span className={`status-badge ${row.status}`}>{row.status}</span></td><td>{row.findings.length}</td><td className="muted">{prettyDate(row.created_at)}</td><td><Link to={`/report/${row.id}`} className="icon-button" aria-label={`Open ${row.source_name}`}><ArrowUpRight size={16} /></Link></td></tr>)}</tbody></table></div> : <EmptyState icon={<History />} title={filter ? 'No matching analyses' : 'No analysis reports'} description={filter ? 'Try a different search phrase.' : 'Your reports will show up here once you run an analysis.'} action={<Link to="/analyze" className="text-link">Analyze source <ArrowUpRight size={14} /></Link>} />}
    </div>
  </section>;
}

function ReportPage() {
  const { id = '' } = useParams();
  const query = useQuery({ queryKey: ['analysis', id], queryFn: () => api.analysis(id), refetchInterval: query => ['queued', 'running'].includes(query.state.data?.status ?? '') ? 1000 : false });
  const health = useQuery({ queryKey: ['health'], queryFn: api.health });
  const queryClient = useQueryClient();
  const [aiError, setAiError] = useState('');
  const [aiMessage, setAiMessage] = useState('');
  const aiMutation = useMutation({
    mutationFn: () => api.aiReview(id),
    onSuccess: result => {
      setAiError('');
      setAiMessage(`${result.added_findings} evidence-checked suggestion${result.added_findings === 1 ? '' : 's'} added.`);
      queryClient.invalidateQueries({ queryKey: ['analysis', id] });
    },
    onError: (failure: Error) => setAiError(failure.message),
  });
  const [severity, setSeverity] = useState('all');
  if (query.isLoading) return <section className="page"><Loading /></section>;
  if (query.error) return <section className="page"><ErrorNotice message={query.error.message} /></section>;
  const report = query.data!;
  const findings = report.findings.filter(item => severity === 'all' || item.severity === severity);
  return <section className="page"><PageHeader kicker={report.mode === 'diff' ? 'DIFF REVIEW REPORT' : 'ANALYSIS REPORT'} title={report.source_name} description={`${report.language} · submitted ${prettyDate(report.created_at)}`} action={<div className="action-group"><button className="button secondary" title={health.data?.llm_configured ? 'Source will be sent to the configured provider after secret-pattern redaction.' : 'Configure an OpenAI-compatible provider in the backend.'} disabled={!health.data?.llm_configured || aiMutation.isPending || report.status !== 'completed'} onClick={() => { setAiError(''); setAiMessage(''); aiMutation.mutate(); }}><Sparkles size={15} />{aiMutation.isPending ? 'Reviewing…' : 'Send source to AI review'}</button><Link className="button secondary" to="/history"><History size={16} />All reports</Link></div>} />
    {(report.status === 'queued' || report.status === 'running') && <div className="working-banner"><span className="spinner" />Analysis {report.status}… this report will refresh automatically.</div>}
    {report.status === 'failed' && <ErrorNotice message={report.error_message ?? 'Analysis failed.'} />}
    {report.status === 'completed' && <>
      {aiError && <ErrorNotice message={aiError} />}
      {aiMessage && <div className="notice-line"><Sparkles size={15} />{aiMessage} AI suggestions are advisory, not verified fixes.</div>}
      <div className="report-summary"><div className="summary-card"><span className={`gate-icon ${report.quality_gate.passed ? 'passed' : 'failed'}`}>{report.quality_gate.passed ? <Check size={19} /> : <X size={19} />}</span><div><small>QUALITY GATE · {report.quality_gate.threshold ?? 'high'}+ threshold</small><b>{report.quality_gate.passed ? 'Checks passed' : 'Action required'}</b><p>{report.quality_gate.reasons?.length ? report.quality_gate.reasons.join(' · ') : 'No configured blocking findings detected.'}</p></div></div>
        <div className="summary-stats"><Metric icon={<AlertTriangle />} label="Total findings" value={report.findings.length} detail="Deduplicated by rule and location" /><Metric icon={<ShieldCheck />} label="Syntax check" value={report.summary.syntax_valid === true ? 'Valid' : 'Invalid'} detail="Heuristic / parser validation" /></div></div>
      <div className="notice-line"><ShieldCheck size={15} />{report.quality_gate.note ?? 'Static analysis does not establish that code is defect-free.'} Analyzers: {String((report.summary.analyzers as string[] | undefined)?.join(', ') ?? 'Not reported')}.</div>
      <div className="panel findings-panel"><div className="panel-heading"><div><h2>Findings <span className="count-pill">{report.findings.length}</span></h2><p>Evidence and source coordinates from deterministic analysis</p></div><label className="filter-select">Severity<select value={severity} onChange={event => setSeverity(event.target.value)}><option value="all">All severities</option>{severityOrder.map(item => <option key={item}>{item}</option>)}</select></label></div>
        {findings.length ? <div className="findings-list">{findings.map(item => <FindingCard key={item.id} analysisId={report.id} finding={item} existingSuggestion={report.patch_suggestions.find(patch => patch.finding_id === item.id) ?? null} />)}</div> : <EmptyState icon={<ShieldCheck />} title="No findings in this filter" description="No report findings matched this severity." />}
      </div>
    </>}
  </section>;
}

function FindingCard({ analysisId, finding, existingSuggestion }: { analysisId: string; finding: Finding; existingSuggestion: PatchSuggestion | null }) {
  const [suggestion, setSuggestion] = useState<PatchSuggestion | null>(existingSuggestion);
  const [error, setError] = useState('');
  const create = useMutation({ mutationFn: () => api.suggestPatch(analysisId, finding.id), onSuccess: setSuggestion, onError: failure => setError(failure.message) });
  const decide = useMutation({
    mutationFn: (decision: 'accepted' | 'rejected') => api.decidePatch(suggestion!.id, decision),
    onSuccess: setSuggestion,
    onError: failure => setError(failure.message),
  });
  return <article className="finding-row"><div className={`severity-marker ${finding.severity}`} /><div className="finding-body"><div className="finding-title"><span className={`severity-tag ${finding.severity}`}>{finding.severity}</span><b>{finding.title}</b><code>{finding.rule_id}</code></div><p>{finding.description}</p>{finding.evidence && <pre className="evidence">{finding.evidence}</pre>}{finding.remediation && <div className="remediation"><Sparkles size={14} /><span><b>Suggested remediation</b> {finding.remediation}</span></div>}<div className="finding-meta"><span><FileCode2 size={13} />{finding.file_path ?? 'source'}</span>{finding.line && <span>Line {finding.line}{finding.column ? `:${finding.column}` : ''}</span>}<span>{finding.analyzer} · {finding.origin}</span></div>
    {finding.rule_id === 'python.unused-import' && <div className="patch-tools">{!suggestion && <button className="text-link" disabled={create.isPending} onClick={() => { setError(''); create.mutate(); }}><Code2 size={13} />{create.isPending ? 'Preparing safe preview…' : 'Preview safe patch'}</button>}
      {error && <p className="patch-error" role="alert">{error}</p>}
      {suggestion && <div className="patch-preview"><div className="patch-heading"><b>Proposed change · source not modified</b><span className={`status-badge ${suggestion.status}`}>{suggestion.status}</span></div><p>{suggestion.explanation}</p><pre className="patch-diff">{suggestion.patch}</pre>{suggestion.status === 'pending' && <div className="patch-decisions"><button className="button secondary" disabled={decide.isPending} onClick={() => decide.mutate('rejected')}><X size={14} />Reject</button><button className="button primary" disabled={decide.isPending} onClick={() => decide.mutate('accepted')}><Check size={14} />Mark accepted</button></div>}{suggestion.status !== 'pending' && <small>Decision recorded. The patch was not applied to a repository.</small>}</div>}</div>}
  </div></article>;
}

function SettingsPage({ llmConfigured, error }: { llmConfigured?: boolean; error: boolean }) {
  return <section className="page"><PageHeader kicker="WORKSPACE PREFERENCES" title="Settings" description="Review active analysis and integration configuration." />
    <div className="settings-grid"><section className="panel settings-panel"><div className="setting-icon"><Sparkles size={18} /></div><div className="setting-content"><h2>AI review provider</h2><p>AI review is optional. Deterministic analysis runs without an external provider.</p><div className="setting-status">{error ? <><span className="state-dot danger" />API status unavailable</> : llmConfigured === undefined ? 'Checking provider configuration…' : llmConfigured ? <><span className="state-dot good" />Provider credentials configured</> : <><span className="state-dot" />Not configured · deterministic mode</>}</div><p className="setting-hint">Configure <code>DEVPILOT_LLM_BASE_URL</code>, <code>DEVPILOT_LLM_API_KEY</code>, and <code>DEVPILOT_LLM_MODEL</code> on the backend. Secrets are not sent to the browser.</p></div></section>
      <section className="panel settings-panel"><div className="setting-icon"><ShieldCheck size={18} /></div><div className="setting-content"><h2>Analysis controls</h2><p>Static source analysis is bounded, does not run submitted code, and has no local repository filesystem integration.</p><div className="setting-status"><span className="state-dot good" />Maximum source size: 100 KB by default</div><p className="setting-hint">Python AST checks and redacted secret pattern matching are active. JavaScript/TypeScript uses ESLint when the frontend dependencies are installed; otherwise it falls back to delimiter checking. Neither path performs TypeScript type-checking.</p></div></section>
      <section className="panel settings-panel"><div className="setting-icon"><LockKeyhole size={18} /></div><div className="setting-content"><h2>Security & privacy</h2><p>Account-owned reports are access-controlled. Passwords are hashed and access tokens are short-lived.</p><div className="setting-status"><span className="state-dot good" />No source execution or automatic patch application</div><p className="setting-hint">Tokens are held in browser localStorage. Use a trusted device and sign out when finished. See the security model in project documentation.</p></div></section></div>
  </section>;
}

function InfoCard({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) {
  return <div className="info-card"><span>{icon}</span><div><b>{title}</b><p>{text}</p></div></div>;
}

function EmptyState({ icon, title, description, action }: { icon: React.ReactNode; title: string; description: string; action?: React.ReactNode }) {
  return <div className="empty-state"><span>{icon}</span><b>{title}</b><p>{description}</p>{action}</div>;
}

function Loading() { return <div className="loading-state"><span className="spinner" />Loading your workspace…</div>; }
function ErrorNotice({ message }: { message: string }) { return <div className="error-banner" role="alert"><AlertTriangle size={16} />{message}</div>; }

export default App;
