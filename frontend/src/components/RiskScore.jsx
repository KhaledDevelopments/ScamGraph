const levelColor = {
  CRITICAL: 'text-risk-high',
  HIGH: 'text-risk-high',
  SUSPICIOUS: 'text-risk-medium',
  LOW: 'text-risk-low',
};

export default function RiskScore({ assessment }) {
  const { risk_score, risk_level, assessment_status, missing_evidence, assessment_note } = assessment;

  if (assessment_status === 'unavailable') {
    return (
      <div className="border border-border rounded-xl bg-surface p-6">
        <p className="text-muted text-sm mb-1">Risk assessment</p>
        <p className="text-lg font-medium text-muted">Risk unknown</p>
        <p className="text-sm text-muted mt-2">No threat intelligence could be retrieved for this content.</p>
      </div>
    );
  }

  const colorClass = levelColor[risk_level] || 'text-muted';

  return (
    <div className="border border-border rounded-xl bg-surface p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-muted text-sm mb-1">Risk assessment</p>
          <p className={`text-lg font-medium ${colorClass}`}>{risk_level}</p>
          {assessment_status === 'partial' && (
            <p className="text-xs text-risk-medium mt-1">Partial data — some checks unavailable</p>
          )}
        </div>
        <p className={`font-mono text-5xl font-bold ${colorClass}`}>
          {risk_score}<span className="text-xl text-muted">/100</span>
        </p>
      </div>
      {missing_evidence?.length > 0 && (
        <p className="text-xs text-muted mt-3">Not checked: {missing_evidence.join(', ')}</p>
      )}
      <p className="text-xs text-muted mt-3 italic">{assessment_note}</p>
    </div>
  );
}