export default function RiskScore({ data }) {
  return (
    <div className="mt-4 bg-gray-800 p-4 rounded-lg">
      <p className="text-2xl font-bold">{data.score}/100</p>
      <p className="text-red-400">{data.risk}</p>
    </div>
  );
}
