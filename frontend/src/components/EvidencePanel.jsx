export default function EvidencePanel({ node }) {
  const { type, label, report, isAssessed } = node.data;

  if (type === 'ipinfo') {
    return (
      <div className="border border-border rounded-xl bg-surface p-6 space-y-2 text-sm">
        <p className="font-mono break-all">IPinfo — {report?.hostname || report?.indicator}</p>
        <p className="text-muted">Status: {report?.status}</p>
        {report?.ip && <p>IP address: {report.ip}</p>}
        {report?.status === 'ok' ? (
          <>
            <p>Country: {report.country} ({report.country_code})</p>
            <p>Network: {report.asn} — {report.as_name}</p>
            <p className="break-all">Network domain: {report.as_domain}</p>
          </>
        ) : <p className="text-muted">IP context was not retrieved for this URL.</p>}
        <p className="text-muted italic">One public IP for the first URL. It may belong to a CDN or shared host. Country and network ownership do not establish risk and add no points.</p>
      </div>
    );
  }

  if (type === 'message') {
    return (
      <div className="border border-border rounded-xl bg-surface p-6">
        <p className="text-muted text-sm">Original submitted content — indicators extracted from it are shown as connected nodes.</p>
      </div>
    );
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

  if (type === 'urlhaus') {
    if (!report) return <div className="border border-border rounded-xl bg-surface p-6"><p className="text-muted text-sm">No URLhaus data.</p></div>;
    return (
      <div className="border border-border rounded-xl bg-surface p-6">
        <p className="font-mono text-sm mb-2">URLhaus — {report.indicator}</p>
        <p className="text-sm text-muted mb-3">Status: <span className="text-white">{report.status}</span></p>
        {report.status === 'ok' && (
          <ul className="text-sm space-y-1">
            <li>Listed as malicious: <span className="text-risk-high">Yes</span></li>
            {report.threat && <li>Threat type: <span className="text-white">{report.threat}</span></li>}
            {report.url_status && <li>URL status: <span className="text-white">{report.url_status}</span></li>}
            {report.tags?.length > 0 && <li>Tags: <span className="text-white">{report.tags.join(', ')}</span></li>}
          </ul>
        )}
        {report.status === 'not_found' && (
          <p className="text-sm text-muted italic">Not found in URLhaus's database — this does not mean the URL is safe, only that URLhaus has no record of it.</p>
        )}
        {report.status !== 'ok' && report.status !== 'not_found' && (
          <p className="text-sm text-muted italic">A non-"ok" status means no usable report was retrieved — it does not mean the URL is safe.</p>
        )}
        {report.date_added && <p className="text-xs text-muted mt-3">Date added: {report.date_added}</p>}
      </div>
    );
  }

  if (type === 'google_safe_browsing') {
    if (!report) return <div className="border border-border rounded-xl bg-surface p-6"><p className="text-muted text-sm">No Google Safe Browsing data.</p></div>;
    return (
      <div className="border border-border rounded-xl bg-surface p-6">
        <p className="font-mono text-sm mb-2">Google Safe Browsing — {report.indicator}</p>
        <p className="text-sm text-muted mb-3">Status: <span className="text-white">{report.status}</span></p>
        {report.status === 'ok' && (
          <ul className="text-sm space-y-1">
            <li>Flagged: <span className="text-risk-high">Yes</span></li>
            {report.threat_types?.length > 0 && <li>Threat types: <span className="text-white">{report.threat_types.join(', ')}</span></li>}
          </ul>
        )}
        {report.status === 'not_found' && (
          <p className="text-sm text-risk-low">Checked — no known threats found on Google's current threat lists.</p>
        )}
        {report.status !== 'ok' && report.status !== 'not_found' && (
          <p className="text-sm text-muted italic">A non-"ok" status means no usable check was completed — it does not mean the URL is safe.</p>
        )}
      </div>
    );
  }

  return (
    <div className="border border-border rounded-xl bg-surface p-6">
      <p className="font-mono text-sm">{label}</p>
      <p className="text-muted text-sm mt-2">Extracted indicator — no provider data checked yet.</p>
    </div>
  );
}
