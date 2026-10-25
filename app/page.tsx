const cases = [
  { id: "CASE-0001", subject: "maya.chen@example.com", status: "INCOMPLETE", finding: "Backup restore risk", system: "backup_service", evidence: "EV-0042", tone: "danger" },
  { id: "CASE-0002", subject: "jordan.wells@example.com", status: "COMPLETE", finding: "Verified absent", system: "account_service", evidence: "EV-0018", tone: "success" },
  { id: "CASE-0003", subject: "samir.patel@example.com", status: "INCOMPLETE", finding: "Active data flow", system: "integration_service", evidence: "EV-0071", tone: "warning" },
  { id: "CASE-0004", subject: "ana.rodriguez@example.com", status: "NOT_APPLICABLE", finding: "No deletion request", system: "—", evidence: "—", tone: "muted" },
  { id: "CASE-0005", subject: "liam.okafor@example.com", status: "INCOMPLETE", finding: "Exposed PII", system: "analytics_platform", evidence: "EV-0096", tone: "danger" },
];

const navItems = ["Overview", "Deletion cases", "Evidence explorer", "Run history"];

export default function Page() {
  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">G</span><span>Ghost Data</span></div>
        <div className="workspace"><span className="workspace-dot" />Production audit <span className="chevron">⌄</span></div>
        <nav aria-label="Primary navigation">
          {navItems.map((item, index) => <a className={index === 0 ? "nav-item active" : "nav-item"} href="#" key={item}><span className="nav-icon">{["◫", "⌁", "◌", "↗"][index]}</span>{item}{index === 1 && <span className="nav-count">518</span>}</a>)}
        </nav>
        <div className="sidebar-bottom"><div className="agent-card"><div className="pulse" /><div><strong>Audit agent online</strong><span>Last run 2m ago</span></div></div><a className="nav-item" href="#"><span className="nav-icon">?</span>Documentation</a><div className="profile"><span className="avatar">AK</span><div><strong>Alex Kim</strong><span>Security operations</span></div><span className="more">•••</span></div></div>
      </aside>
      <section className="content">
        <header className="topbar"><div className="breadcrumbs"><span>Workspace</span><b>/</b><strong>Overview</strong></div><div className="top-actions"><span className="last-run">Last run <strong>Oct 25, 2026 at 10:42 AM</strong></span><button className="icon-button" aria-label="Notifications">♧</button><button className="run-button">Run audit <span>↗</span></button></div></header>
        <div className="page-body">
          <div className="intro"><div><p className="eyebrow">DELETION AUDIT / PRODUCTION</p><h1>Ghost Data Still Exists</h1><p className="subhead">Your deletion workflow says complete. The evidence says otherwise.</p></div><button className="export-button">Export report <span>↓</span></button></div>
          <div className="stat-grid"><Stat label="Requests audited" value="518" detail="All requests processed" accent="navy"/><Stat label="Incomplete deletions" value="184" detail="35.5% of requests" accent="red"/><Stat label="Complete" value="291" detail="56.2% of requests" accent="teal"/><Stat label="Not applicable" value="43" detail="8.3% of requests" accent="gray"/></div>
          <div className="section-heading"><div><h2>Audit health</h2><p>Current run across all evidence sources</p></div><span className="run-id">RUN-2026-10-25-1042</span></div>
          <div className="health-grid"><div className="health-card"><div className="health-ring"><strong>64<span>%</span></strong><small>healthy</small></div><div className="health-copy"><h3>Deletion integrity</h3><p>291 of 475 applicable requests have no remaining data or recreation risk.</p><div className="progress"><span style={{width:"64%"}} /></div><div className="legend"><span><i className="dot teal" />Complete <b>291</b></span><span><i className="dot red" />Needs action <b>184</b></span></div></div></div><div className="risk-card"><div className="card-label">TOP RISK CATEGORIES <span>ⓘ</span></div><Risk label="Remaining records" value="91" percent="49%" color="red"/><Risk label="Active data flows" value="47" percent="26%" color="amber"/><Risk label="Restore risk" value="31" percent="17%" color="purple"/><Risk label="Exposed PII" value="15" percent="8%" color="blue"/></div></div>
          <div className="section-heading cases-heading"><div><h2>Recent deletion cases</h2><p>Latest findings requiring your attention</p></div><a href="#" className="view-all">View all cases <span>→</span></a></div>
          <div className="table-wrap"><table><thead><tr><th>CASE</th><th>REQUESTER</th><th>STATUS</th><th>PRIMARY FINDING</th><th>SYSTEM</th><th>EVIDENCE</th><th /></tr></thead><tbody>{cases.map(c => <tr key={c.id}><td><strong className="case-id">{c.id}</strong></td><td>{c.subject}</td><td><span className={`status ${c.tone}`}><i />{c.status}</span></td><td>{c.finding}</td><td><code>{c.system}</code></td><td><span className="evidence">{c.evidence}</span></td><td><button className="row-more">•••</button></td></tr>)}</tbody></table></div>
        </div>
      </section>
    </main>
  );
}
function Stat({label,value,detail,accent}:{label:string,value:string,detail:string,accent:string}) { return <div className={`stat-card ${accent}`}><p>{label}</p><strong>{value}</strong><span>{detail}</span></div> }
function Risk({label,value,percent,color}:{label:string,value:string,percent:string,color:string}) { return <div className="risk-row"><div className="risk-title"><span><i className={`dot ${color}`} />{label}</span><b>{value}</b></div><div className="risk-track"><span className={color} style={{width:percent}} /></div></div> }
