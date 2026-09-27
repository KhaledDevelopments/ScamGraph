import { formatStatus } from '../utils/statusLabels';

export default function EvidencePanel({ node, onClose }) {
  const { type, label, report, isAssessed } = node.data;

  const renderHeader = (title) => (
    <div className="flex items-center justify-between pb-3 mb-3 border-b border-border/60">
      <span className="text-xs font-mono uppercase tracking-wider text-muted flex items-center gap-1.5">
        <span>🔍 Node Evidence:</span>
        <span className="text-white font-medium">{title}</span>
      </span>
      {onClose && (
        <button
          type="button"
          onClick={onClose}
          className="text-xs text-muted hover:text-white hover:bg-slate-800 px-2 py-0.5 rounded transition-colors"
          title="Clear node selection"
        >
          ✕ Close
        </button>
      )}
    </div>
  );

  if (type === 'ipinfo') {
    return (
      <div className="border border-border rounded-xl bg-surface p-6 space-y-2 text-sm">
        {renderHeader('IPinfo Context')}
        <p className="font-mono break-all text-white/90">IPinfo — {report?.hostname || report?.indicator}</p>
        <p className="text-muted">Status: {report?.status}</p>
        {report?.ip && <p>IP address: <span className="font-mono text-white/90">{report.ip}</span></p>}
        {report?.status === 'ok' ? (
          <>
            <p>Country: {report.country} ({report.country_code})</p>
            <p>Network: {report.asn} — {report.as_name}</p>
            <p className="break-all">Network domain: {report.as_domain}</p>
          </>
        ) : <p className="text-muted">IP context was not retrieved for this URL.</p>}
        <p className="text-muted italic text-xs pt-1">One public IP for the first URL. It may belong to a CDN or shared host. Country and network ownership do not establish risk and add no points.</p>
      </div>
    );
  }

  if (type === 'message') {
    return (
      <div className="border border-border rounded-xl bg-surface p-6">
        {renderHeader('Original Input')}
        <p className="text-muted text-sm">Original submitted content — indicators extracted from it are shown as connected nodes.</p>
      </div>
    );
  }

  if (type === 'url') {
    return (
      <div className="border border-border rounded-xl bg-surface p-6">
        {renderHeader('URL Indicator')}
        <p className="font-mono text-sm break-all mb-2 text-white/90">{label}</p>
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
        {renderHeader('VirusTotal Provider')}
        <p className="font-mono text-sm mb-2 break-all text-white/90">VirusTotal — {report.indicator}</p>
        <p className="text-sm text-muted mb-3">Status: <span className="text-white">{formatStatus(report.status)}</span></p>
        {report.status === 'ok' && report.stats && (
          <ul className="text-sm space-y-1">
            <li>Malicious: <span className="text-risk-high font-medium">{report.stats.malicious}</span></li>
            <li>Suspicious: <span className="text-risk-medium font-medium">{report.stats.suspicious}</span></li>
            <li>Harmless: <span className="text-risk-low font-medium">{report.stats.harmless}</span></li>
          </ul>
        )}
        {report.status !== 'ok' && (
          <p className="text-sm text-muted italic">A non-&quot;ok&quot; status means no usable report was retrieved — it does not mean the URL is safe.</p>
        )}
        {report.last_analysis_date && <p className="text-xs text-muted mt-3">Last analyzed: {report.last_analysis_date}</p>}
      </div>
    );
  }

  if (type === 'urlhaus') {
    if (!report) return <div className="border border-border rounded-xl bg-surface p-6"><p className="text-muted text-sm">No URLhaus data.</p></div>;
    return (
      <div className="border border-border rounded-xl bg-surface p-6">
        {renderHeader('URLhaus Provider')}
        <p className="font-mono text-sm mb-2 break-all text-white/90">URLhaus — {report.indicator}</p>
        <p className="text-sm text-muted mb-3">Status: <span className="text-white">{formatStatus(report.status)}</span></p>
        {report.status === 'ok' && (
          <ul className="text-sm space-y-1">
            <li>Listed as malicious: <span className="text-risk-high font-medium">Yes</span></li>
            {report.threat && <li>Threat type: <span className="text-white">{report.threat}</span></li>}
            {report.url_status && <li>URL status: <span className="text-white">{report.url_status}</span></li>}
            {report.tags?.length > 0 && <li>Tags: <span className="text-white">{report.tags.join(', ')}</span></li>}
          </ul>
        )}
        {report.status === 'not_found' && (
          <p className="text-sm text-muted italic">Not found in URLhaus&apos;s database — this does not mean the URL is safe, only that URLhaus has no record of it.</p>
        )}
        {report.status !== 'ok' && report.status !== 'not_found' && (
          <p className="text-sm text-muted italic">A non-&quot;ok&quot; status means no usable report was retrieved — it does not mean the URL is safe.</p>
        )}
        {report.date_added && <p className="text-xs text-muted mt-3">Date added: {report.date_added}</p>}
      </div>
    );
  }

  if (type === 'google_safe_browsing') {
    if (!report) return <div className="border border-border rounded-xl bg-surface p-6"><p className="text-muted text-sm">No Google Safe Browsing data.</p></div>;
    return (
      <div className="border border-border rounded-xl bg-surface p-6">
        {renderHeader('Safe Browsing Provider')}
        <p className="font-mono text-sm mb-2 break-all text-white/90">Google Safe Browsing — {report.indicator}</p>
        <p className="text-sm text-muted mb-3">Status: <span className="text-white">{formatStatus(report.status)}</span></p>
        {report.status === 'ok' && (
          <ul className="text-sm space-y-1">
            <li>Flagged: <span className="text-risk-high font-medium">Yes</span></li>
            {report.threat_types?.length > 0 && <li>Threat types: <span className="text-white">{report.threat_types.join(', ')}</span></li>}
          </ul>
        )}
        {report.status === 'not_found' && (
          <p className="text-sm text-risk-low">Checked — no known threats found on Google&apos;s current threat lists.</p>
        )}
        {report.status !== 'ok' && report.status !== 'not_found' && (
          <p className="text-sm text-muted italic">A non-&quot;ok&quot; status means no usable check was completed — it does not mean the URL is safe.</p>
        )}
      </div>
    );
  }

  if (type === 'rdap') {
    if (!report) return <div className="border border-border rounded-xl bg-surface p-6"><p className="text-muted text-sm">No RDAP data.</p></div>;
    return (
      <div className="border border-border rounded-xl bg-surface p-6 space-y-2 text-sm">
        {renderHeader('RDAP Registration')}
        <p className="font-mono text-sm mb-2 break-all text-white/90">RDAP — {report.domain || report.indicator}</p>
        <p className="text-sm text-muted mb-2">Status: <span className="text-white">{formatStatus(report.status)}</span></p>
        {report.status === 'ok' && (
          <div className="space-y-1 text-sm">
            {report.registration_date && (
              <p>Registration Date: <span className="font-mono text-white/90">{report.registration_date}</span></p>
            )}
            {report.domain_age_days !== null && (
              <p>
                Domain Age: <span className="font-mono font-bold text-white/90">{report.domain_age_days} days</span>
                {report.recent_domain && (
                  <span className="ml-2 text-xs text-risk-high bg-risk-high/15 border border-risk-high/30 px-2 py-0.5 rounded-full font-sans font-medium">
                    ⚠️ Young domain (&lt; 30 days old)
                  </span>
                )}
              </p>
            )}
            {report.registrar && (
              <p className="text-muted">Registrar: <span className="text-white/80">{report.registrar}</span></p>
            )}
          </div>
        )}
        {report.status === 'not_found' && (
          <p className="text-sm text-muted italic">Domain registration record was not found in ICANN authoritative RDAP registries.</p>
        )}
        {report.status !== 'ok' && report.status !== 'not_found' && (
          <p className="text-sm text-muted italic">RDAP registration record could not be retrieved — this does not mean the URL is safe.</p>
        )}
        <p className="text-muted italic text-xs pt-1">RDAP provides authoritative registry creation dates via ICANN bootstrap. Domains registered less than 30 days ago add +10 risk points.</p>
      </div>
    );
  }

  return (
    <div className="border border-border rounded-xl bg-surface p-6">
      {renderHeader(type || 'Indicator')}
      <p className="font-mono text-sm break-all text-white/90">{label}</p>
      <p className="text-muted text-sm mt-2">Extracted indicator — no provider data checked yet.</p>
    </div>
  );
}
