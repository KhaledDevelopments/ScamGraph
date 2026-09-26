const evidenceData = {
  domain: {
    title: 'unb-secure-login.xyz',
    source: 'VirusTotal',
    findings: [
      'Domain differs from UNB\'s official domain (unb.ca)',
      'Registered 4 days ago',
      'Flagged by 12 of 90 security vendors',
    ],
    contribution: 45,
  },
  vt: {
    title: 'VirusTotal Detection',
    source: 'VirusTotal API',
    findings: [
      'Listed in active phishing campaign database',
      'Associated with known credential-harvesting infrastructure',
    ],
    contribution: 30,
  },
};

export default function EvidencePanel({ node }) {
  const evidence = evidenceData[node.id];

  if (!evidence) {
    return (
      <div className="border border-border rounded-xl bg-surface p-6">
        <p className="text-muted">No additional evidence for this node yet.</p>
      </div>
    );
  }

  return (
    <div className="border border-border rounded-xl bg-surface p-6">
      <div className="flex items-center justify-between mb-4">
        <p className="font-mono text-lg">{evidence.title}</p>
        <span className="text-risk-high font-mono text-sm">+{evidence.contribution}</span>
      </div>
      <p className="text-muted text-sm mb-3">Source: {evidence.source}</p>
      <ul className="space-y-2">
        {evidence.findings.map((f, i) => (
          <li key={i} className="text-sm text-white/90 flex gap-2">
            <span className="text-accent">›</span>{f}
          </li>
        ))}
      </ul>
    </div>
  );
}