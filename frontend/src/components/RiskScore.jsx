const riskColor = (risk) => {
  if (risk === 'HIGH RISK') return 'text-risk-high';
  if (risk === 'MEDIUM RISK') return 'text-risk-medium';
  return 'text-risk-low';
};

export default function RiskScore({ data }) {
  return (
    <div className="border border-border rounded-xl bg-surface p-6 flex items-center justify-between">
      <div>
        <p className="text-muted text-sm mb-1">Risk assessment</p>
        <p className={`text-lg font-medium ${riskColor(data.risk)}`}>{data.risk}</p>
      </div>
      <p className={`font-mono text-5xl font-bold ${riskColor(data.risk)}`}>
        {data.score}<span className="text-xl text-muted">/100</span>
      </p>
    </div>
  );
}