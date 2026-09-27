import { useMemo } from 'react';
import ReactFlow, { Background, Controls, useNodesState, useEdgesState } from 'reactflow';
import 'reactflow/dist/style.css';
import { formatStatus } from '../utils/statusLabels';

const NODE_WIDTH = 190;

const COLUMN_WIDTH = 230;

const baseStyle = {
  background: '#141B2D', color: '#fff', border: '1px solid #253147',
  fontFamily: 'monospace', fontSize: '12px', width: NODE_WIDTH, height: 64,
  padding: '20px 12px', whiteSpace: 'nowrap', wordBreak: 'break-word', textAlign: 'center', lineHeight: '1.4',
};

const flaggedStyle = { 
  ...baseStyle,
  background: '#3B1418', 
  color: '#fff', 
  border: '1px solid #E5484D', 
  fontFamily: 'monospace', 
  fontSize: '12px' 
};

function buildGraph(data) {
  const nodes = [];
  const edges = [];
  const { urls = [], emails = [], domains = [] } = data.indicators || {};
  const reports = data.threat_intelligence?.virustotal || [];
  const urlhausReports = data.threat_intelligence?.urlhaus || [];
  const gsbReports = data.threat_intelligence?.google_safe_browsing || [];
  const ipReports = data.threat_intelligence?.ipinfo || [];
  const assessedUrl = data.assessment?.assessed_url;

  const urlColumnCounts = urls.map((url) => {
    const hasVt = reports.some((r) => r.indicator === url);
    const hasUh = urlhausReports.some((r) => r.indicator === url);
    const hasGsb = gsbReports.some((r) => r.indicator === url);
    const hasIp = ipReports.some((r) => r.indicator === url);
    return Math.max(1, (hasVt ? 1 : 0) + (hasUh ? 1 : 0) + (hasGsb ? 1 : 0) + (hasIp ? 1 : 0));
  });
  const totalUrlColumns = urlColumnCounts.reduce((sum, c) => sum + c, 0);
  const columnCount = Math.max(1, totalUrlColumns + emails.length + domains.length);
  const centerX = (columnCount - 1) * COLUMN_WIDTH / 2;
  nodes.push({ id: 'message', position: { x: centerX, y: 0 }, data: { type: 'message', label: 'MESSAGE' }, style: baseStyle });

  let urlBranchStart = 0;
  urls.forEach((url, i) => {
    const id = `url-${i}`;
    const report = reports.find((r) => r.indicator === url);
    const urlhausReport = urlhausReports.find((r) => r.indicator === url);
    const gsbReport = gsbReports.find((r) => r.indicator === url);
    const ipReport = ipReports.find((r) => r.indicator === url);
    const isAssessed = url === assessedUrl;

    const vtMalicious = report?.status === 'ok' && report.stats?.malicious > 0;
    const uhMalicious = urlhausReport?.malicious === true;
    const gsbMalicious = gsbReport?.flagged === true;
    const malicious = vtMalicious || uhMalicious || gsbMalicious;

    const branchColumns = urlColumnCounts[i];
    const branchX = urlBranchStart * COLUMN_WIDTH;
    const branchCenterX = branchX + (branchColumns - 1) * COLUMN_WIDTH / 2;

    nodes.push({ id, position: { x: branchCenterX, y: 160 }, data: { type: 'url', label: url, url, report, isAssessed }, style: malicious ? flaggedStyle : baseStyle });
    edges.push({ id: `e-msg-${id}`, source: 'message', target: id });

    const providerNodes = [];
    if (report) providerNodes.push({ id: `vt-${i}`, label: `VirusTotal: ${formatStatus(report.status)}`, type: 'virustotal', report, malicious: vtMalicious });
    if (urlhausReport) providerNodes.push({ id: `urlhaus-${i}`, label: `URLhaus: ${formatStatus(urlhausReport.status)}`, type: 'urlhaus', report: urlhausReport, malicious: uhMalicious });
    if (gsbReport) providerNodes.push({ id: `gsb-${i}`, label: `Safe Browsing: ${formatStatus(gsbReport.status)}`, type: 'google_safe_browsing', report: gsbReport, malicious: gsbMalicious });
    if (ipReport) providerNodes.push({ id: `ipinfo-${i}`, label: `IPinfo: ${ipReport.ip || STATUS_LABELS[ipReport.status] || ipReport.status}`, type: 'ipinfo', report: ipReport, malicious: false });

    providerNodes.forEach((p, j) => {
      nodes.push({ id: p.id, position: { x: branchX + j * COLUMN_WIDTH, y: 320 }, data: { type: p.type, label: p.label, report: p.report }, style: p.malicious ? flaggedStyle : baseStyle });
      edges.push({ id: `e-${id}-${p.id}`, source: id, target: p.id });
    });

    urlBranchStart += branchColumns;
  });

  emails.forEach((email, i) => {
    const id = `email-${i}`;
    nodes.push({ id, position: { x: (urlBranchStart + i) * COLUMN_WIDTH, y: 160 }, data: { type: 'email', label: email }, style: baseStyle });
    edges.push({ id: `e-msg-${id}`, source: 'message', target: id });
  });

  domains.forEach((domain, i) => {
    const id = `domain-${i}`;
    nodes.push({ id, position: { x: (urlBranchStart + emails.length + i) * COLUMN_WIDTH, y: 160 }, data: { type: 'domain', label: domain }, style: baseStyle });
    edges.push({ id: `e-msg-${id}`, source: 'message', target: id });
  });

  return {
    nodes: nodes.map((node) => ({
      ...node,
      style: { ...baseStyle, ...node.style },
      data: {
        ...node.data,
        label: <span title={node.data.label} style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis' }}>{node.data.label}</span>,
        fullLabel: node.data.label,
      },
    })),
    edges: edges.map((edge) => ({ ...edge, type: 'smoothstep' })),
  };
}

export default function ScamGraph({ data, onNodeClick }) {
  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => buildGraph(data), [data]);
  return <GraphCanvas key={JSON.stringify(data)} initialNodes={initialNodes} initialEdges={initialEdges} onNodeClick={onNodeClick} />;
}

function GraphCanvas({ initialNodes, initialEdges, onNodeClick }) {
  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  return (
    <div style={{ height: '460px', width: '100%' }} className="border border-border rounded-xl overflow-hidden">
      <ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
        onNodeClick={(e, node) => onNodeClick({ ...node, data: { ...node.data, label: node.data.fullLabel } })}
        nodesConnectable={false} minZoom={0.05} fitView fitViewOptions={{ padding: 0.2, maxZoom: 1 }}>
        <Background color="#253147" />
        <Controls />
      </ReactFlow>
    </div>
  );
}
