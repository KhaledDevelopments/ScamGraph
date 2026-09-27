import { useMemo } from 'react';
import ReactFlow, { Background, Controls, useNodesState, useEdgesState } from 'reactflow';
import 'reactflow/dist/style.css';

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
  const assessedUrl = data.assessment?.assessed_url;
  // Reserve two columns per URL for its sibling provider nodes. Other
  // indicators stay on the same level as URLs, outside those branches.
  const columnCount = Math.max(1, urls.length * 2 + emails.length + domains.length);
  const centerX = (columnCount * COLUMN_WIDTH - NODE_WIDTH) / 2;
  nodes.push({ id: 'message', position: { x: centerX, y: 0 }, data: { type: 'message', label: 'MESSAGE' }, style: baseStyle });

  urls.forEach((url, i) => {
    const id = `url-${i}`;
    const report = reports.find((r) => r.indicator === url);
    const urlhausReport = urlhausReports.find((r) => r.indicator === url);
    const isAssessed = url === assessedUrl;
    const vtMalicious = report?.status === 'ok' && report.stats?.malicious > 0;
    const uhMalicious = urlhausReport?.malicious === true;
    const malicious = vtMalicious || uhMalicious;
    const branchX = i * COLUMN_WIDTH * 2;
    nodes.push({ id, position: { x: branchX + COLUMN_WIDTH / 2, y: 160 }, data: { type: 'url', label: url, url, report, isAssessed }, style: malicious ? flaggedStyle : baseStyle });
    edges.push({ id: `e-msg-${id}`, source: 'message', target: id });

    if (report) {
      const vtId = `vt-${i}`;
      nodes.push({ id: vtId, position: { x: urlhausReport ? branchX : branchX + COLUMN_WIDTH / 2, y: 320 }, data: { type: 'virustotal', label: `VirusTotal: ${report.status}`, report }, style: vtMalicious ? flaggedStyle : baseStyle });
      edges.push({ id: `e-${id}-${vtId}`, source: id, target: vtId });
    }
    if (urlhausReport) {
      const uhId = `urlhaus-${i}`;
      nodes.push({ id: uhId, position: { x: report ? branchX + COLUMN_WIDTH : branchX + COLUMN_WIDTH / 2, y: 320 }, data: { type: 'urlhaus', label: `URLhaus: ${urlhausReport.status}`, report: urlhausReport }, style: uhMalicious ? flaggedStyle : baseStyle });
      edges.push({ id: `e-${id}-${uhId}`, source: id, target: uhId });
    }
  });

  emails.forEach((email, i) => {
    const id = `email-${i}`;
    nodes.push({ id, position: { x: (urls.length * 2 + i) * COLUMN_WIDTH, y: 160 }, data: { type: 'email', label: email }, style: baseStyle });
    edges.push({ id: `e-msg-${id}`, source: 'message', target: id });
  });

  domains.forEach((domain, i) => {
    const id = `domain-${i}`;
    nodes.push({ id, position: { x: (urls.length * 2 + emails.length + i) * COLUMN_WIDTH, y: 160 }, data: { type: 'domain', label: domain }, style: baseStyle });
    edges.push({ id: `e-msg-${id}`, source: 'message', target: id });
  });

  return {
    nodes: nodes.map((node) => ({
      ...node,
      style: { ...baseStyle, ...node.style },
      data: {
        ...node.data,
        // Truncate the visual label only; the evidence panel keeps the full value.
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
