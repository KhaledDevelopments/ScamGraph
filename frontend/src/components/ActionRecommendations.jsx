export default function ActionRecommendations({ assessment }) {
  if (!assessment || assessment.assessment_status === 'unavailable') {
    return (
      <div className="border border-border rounded-xl bg-surface p-6">
        <h3 className="text-xs font-mono font-medium text-muted uppercase tracking-wider mb-3">Recommended Actions</h3>
        <ul className="space-y-2 text-sm text-white/90">
          <li className="flex items-start gap-2">
            <span className="text-risk-medium">⚠️</span>
            <span><strong>Verify out-of-band:</strong> Contact the sender using a phone number or official website you independently know and trust.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-muted">ℹ️</span>
            <span><strong>Unchecked risk:</strong> No threat intelligence could be verified for this content. Treat unexpected links with caution.</span>
          </li>
        </ul>
      </div>
    );
  }

  const { risk_level } = assessment;
  const isHighRisk = risk_level === 'CRITICAL' || risk_level === 'HIGH';
  const isMediumRisk = risk_level === 'SUSPICIOUS';

  return (
    <div className={`border rounded-xl bg-surface p-6 ${isHighRisk ? 'border-risk-high/40' : 'border-border'}`}>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-mono font-medium uppercase tracking-wider text-muted">
          Recommended Safety Actions
        </h3>
        <span className={`text-[11px] px-2.5 py-0.5 rounded-full font-mono font-medium ${
          isHighRisk ? 'bg-risk-high/20 text-risk-high' : isMediumRisk ? 'bg-risk-medium/20 text-risk-medium' : 'bg-risk-low/20 text-risk-low'
        }`}>
          {isHighRisk ? 'Action Required' : isMediumRisk ? 'Caution Advised' : 'Stay Alert'}
        </span>
      </div>

      <ul className="space-y-2.5 text-sm">
        {isHighRisk ? (
          <>
            <li className="flex items-start gap-2.5 text-white/90">
              <span className="text-risk-high font-bold leading-none mt-0.5">🛑</span>
              <span><strong>Do not click any links or download attachments:</strong> Threat providers or heuristic analysis detected malicious activity.</span>
            </li>
            <li className="flex items-start gap-2.5 text-white/90">
              <span className="text-risk-high font-bold leading-none mt-0.5">🔒</span>
              <span><strong>Never provide passwords or credentials:</strong> Legitimate institutions do not demand login credentials through unverified urgent messages.</span>
            </li>
            <li className="flex items-start gap-2.5 text-white/90">
              <span className="text-accent font-bold leading-none mt-0.5">📢</span>
              <span><strong>Report to IT or Security:</strong> Forward this message to your organization&apos;s security helpdesk or mark it as phishing.</span>
            </li>
          </>
        ) : isMediumRisk ? (
          <>
            <li className="flex items-start gap-2.5 text-white/90">
              <span className="text-risk-medium font-bold leading-none mt-0.5">⚠️</span>
              <span><strong>Scrutinize sender and links:</strong> Suspicious language patterns or domain mismatches were detected. Inspect the target domain carefully.</span>
            </li>
            <li className="flex items-start gap-2.5 text-white/90">
              <span className="text-risk-medium font-bold leading-none mt-0.5">🔍</span>
              <span><strong>Confirm through an official channel:</strong> Navigate directly to the organization&apos;s official website rather than using provided links.</span>
            </li>
            <li className="flex items-start gap-2.5 text-white/90">
              <span className="text-muted font-bold leading-none mt-0.5">ℹ️</span>
              <span><strong>Never enter multi-factor authentication (MFA) codes</strong> on pages opened from unprompted messages.</span>
            </li>
          </>
        ) : (
          <>
            <li className="flex items-start gap-2.5 text-white/90">
              <span className="text-risk-low font-bold leading-none mt-0.5">✓</span>
              <span><strong>No active threat signatures found:</strong> Completed provider lookups reported no known malicious records on file.</span>
            </li>
            <li className="flex items-start gap-2.5 text-white/90">
              <span className="text-risk-medium font-bold leading-none mt-0.5">⚠️</span>
              <span><strong>Absence of records is not proof of safety:</strong> Newly created phishing sites or targeted attacks may not yet appear on public threat feeds.</span>
            </li>
            <li className="flex items-start gap-2.5 text-white/90">
              <span className="text-muted font-bold leading-none mt-0.5">ℹ️</span>
              <span>Always verify unexpected financial or login requests through an independent, trusted channel before proceeding.</span>
            </li>
          </>
        )}
      </ul>
    </div>
  );
}
