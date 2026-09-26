import { useMemo } from 'react';
import ReactFlow, { Background, Controls, useNodesState, useEdgesState } from 'reactflow';
import 'reactflow/dist/style.css';

const baseStyle = { background: '#141B2D', color: '#fff', border: '1px solid #253147', fontFamily: 'monospace', fontSize: '12px' };
const flaggedStyle = { background: '#3B1418', color: '#fff', border: '1px solid #E5484D', fontFamily: 'monospace', fontSize: '12px' };

function buildGraph(data) {
  const nodes = [{ id: 'message', position: { x: 300, y: 0 }, data: { type: 'message', label: 'MESSAGE' }, style: baseStyle }];
  const edges = [];
  const { urls = [], emails = [], domains = [] } = data.indicators || {};
  const reports = data.threat_intelligence?.virustotal || [];
  const assessedUrl = data.assessment?.assessed_url;

  urls.forEach((url, i) => {
    const id = `url-${i}`;
    const report = reports.find((r) => r.indicator === url);
    const isAssessed = url === assessedUrl;
    const malicious = report?.status === 'ok' && report.stats?.malicious > 0;
    nodes.push({ id, position: { x: 50 + i * 220, y: 120 }, data: { type: 'url', label: url, url, report, isAssessed }, style: malicious ? flaggedStyle : baseStyle });
    edges.push({ id: `e-msg-${id}`, source: 'message', target: id });

    if (report) {
      const vtId = `vt-${i}`;
      nodes.push({ id: vtId, position: { x: 50 + i * 220, y: 240 }, data: { type: 'virustotal', label: `VirusTotal: ${report.status}`, report }, style: malicious ? flaggedStyle : baseStyle });
      edges.push({ id: `e-${id}-${vtId}`, source: id, target: vtId });
    }
  });

  emails.forEach((email, i) => {
    const id = `email-${i}`;
    nodes.push({ id, position: { x: 50 + i * 220, y: 360 }, data: { type: 'email', label: email }, style: baseStyle });
    edges.push({ id: `e-msg-${id}`, source: 'message', target: id });
  });

  domains.forEach((domain, i) => {
    const id = `domain-${i}`;
    nodes.push({ id, position: { x: 50 + i * 220, y: 480 }, data: { type: 'domain', label: domain }, style: baseStyle });
    edges.push({ id: `e-msg-${id}`, source: 'message', target: id });
  });

  return { nodes, edges };
}

export default function ScamGraph({ data, onNodeClick }) {
  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => buildGraph(data), [data]);
  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  return (
    <div style={{ height: '420px', width: '100%' }} className="border border-border rounded-xl overflow-hidden">
      <ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
        onNodeClick={(e, node) => onNodeClick(node)} nodesConnectable={false} fitView>
        <Background color="#253147" />
        <Controls />
      </ReactFlow>
    </div>
  );
}