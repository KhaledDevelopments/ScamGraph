export default function EvidencePanel({ node }) {
  const { type, label, report, isAssessed } = node.data;

  if (type === 'message') {
    return <div className="border border-border rounded-xl bg-surface p-6"><p className="text-muted text-sm">Original submitted content — indicators extracted from it are shown as connected nodes.</p></div>;
  }

  if (type === 'url') {
    return (
      <div className="border border-border rounded-xl bg-surface p-6">
        <p className="font-mono text-sm break-all mb-2">{label}</p>
        {isAssessed
          ? <p className="text-sm text-accent">This is the URL that was checked against threat intelligence.</p>
          : <p className="text-sm text-muted">Skipped — only the first extracted URL is assessed in this version.</p>}
      </div>
    );
  }

  if (type === 'virustotal') {
    if (!report) return <div className="border border-border rounded-xl bg-surface p-6"><p className="text-muted text-sm">No VirusTotal data.</p></div>;
    return (
      <div className="border border-border rounded-xl bg-surface p-6">
        <p className="font-mono text-sm mb-2">VirusTotal — {report.indicator}</p>
        <p className="text-sm text-muted mb-3">Status: <span className="text-white">{report.status}</span></p>
        {report.status === 'ok' && report.stats && (
          <ul className="text-sm space-y-1">
            <li>Malicious: <span className="text-risk-high">{report.stats.malicious}</span></li>
            <li>Suspicious: <span className="text-risk-medium">{report.stats.suspicious}</span></li>
            <li>Harmless: <span className="text-risk-low">{report.stats.harmless}</span></li>
          </ul>
        )}
        {report.status !== 'ok' && (
          <p className="text-sm text-muted italic">A non-"ok" status means no usable report was retrieved — it does not mean the URL is safe.</p>
        )}
        {report.last_analysis_date && <p className="text-xs text-muted mt-3">Last analyzed: {report.last_analysis_date}</p>}
      </div>
    );
  }

  return <div className="border border-border rounded-xl bg-surface p-6"><p className="font-mono text-sm">{label}</p><p className="text-muted text-sm mt-2">Extracted indicator — no provider data checked yet.</p></div>;
}