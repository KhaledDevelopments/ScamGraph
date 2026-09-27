import { useCallback, useMemo } from 'react';
import ReactFlow, { Background, Controls, useNodesState, useEdgesState } from 'reactflow';
import 'reactflow/dist/style.css';
import { formatStatus } from '../utils/statusLabels';

const NODE_WIDTH = 220;

const COLUMN_WIDTH = 250;

const TYPE_BADGES = {
  message: { label: 'INPUT', color: '#38BDF8' },
  url: { label: 'URL', color: '#38BDF8' },
  email: { label: 'EMAIL', color: '#A78BFA' },
  domain: { label: 'DOMAIN', color: '#6EE7B7' },
  virustotal: { label: 'VIRUSTOTAL', color: '#94A3B8' },
  urlhaus: { label: 'URLHAUS', color: '#94A3B8' },
  google_safe_browsing: { label: 'SAFE BROWSING', color: '#94A3B8' },
  ipinfo: { label: 'IPINFO', color: '#94A3B8' },
  rdap: { label: 'RDAP', color: '#94A3B8' },
};

const baseStyle = {
  background: '#141B2D',
  color: '#fff',
  border: '1px solid #253147',
  borderRadius: '8px',
  fontFamily: 'monospace',
  fontSize: '11px',
  width: NODE_WIDTH,
  minHeight: 68,
  height: 'auto',
  padding: '10px 12px',
  textAlign: 'center',
  display: 'flex',
  flexDirection: 'column',
  justifyContent: 'center',
  alignItems: 'center',
  boxShadow: '0 4px 12px rgba(0, 0, 0, 0.25)',
  cursor: 'pointer',
};

const flaggedStyle = { 
  ...baseStyle,
  background: '#3B1418', 
  color: '#fff', 
  border: '1px solid #E5484D', 
  boxShadow: '0 4px 14px rgba(229, 72, 77, 0.35)',
};

function buildGraph(data) {
  const nodes = [];
  const edges = [];
  const { urls = [], emails = [], domains = [] } = data.indicators || {};
  const reports = data.threat_intelligence?.virustotal || [];
  const urlhausReports = data.threat_intelligence?.urlhaus || [];
  const gsbReports = data.threat_intelligence?.google_safe_browsing || [];
  const ipReports = data.threat_intelligence?.ipinfo || [];
  const rdapReports = data.threat_intelligence?.rdap || [];
  const assessedUrl = data.assessment?.assessed_url;

  const urlColumnCounts = urls.map((url) => {
    const hasVt = reports.some((r) => r.indicator === url);
    const hasUh = urlhausReports.some((r) => r.indicator === url);
    const hasGsb = gsbReports.some((r) => r.indicator === url);
    const hasIp = ipReports.some((r) => r.indicator === url);
    const hasRdap = rdapReports.some((r) => r.indicator === url);
    return Math.max(1, (hasVt ? 1 : 0) + (hasUh ? 1 : 0) + (hasGsb ? 1 : 0) + (hasIp ? 1 : 0) + (hasRdap ? 1 : 0));
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
    const rdapReport = rdapReports.find((r) => r.indicator === url);
    const isAssessed = url === assessedUrl;

    const vtMalicious = report?.status === 'ok' && report.stats?.malicious > 0;
    const uhMalicious = urlhausReport?.malicious === true;
    const gsbMalicious = gsbReport?.flagged === true;
    const rdapRecent = rdapReport?.recent_domain === true;
    const malicious = vtMalicious || uhMalicious || gsbMalicious || rdapRecent;

    const branchColumns = urlColumnCounts[i];
    const branchX = urlBranchStart * COLUMN_WIDTH;
    const branchCenterX = branchX + (branchColumns - 1) * COLUMN_WIDTH / 2;

    nodes.push({ id, position: { x: branchCenterX, y: 160 }, data: { type: 'url', label: url, url, report, isAssessed }, style: malicious ? flaggedStyle : baseStyle });
    edges.push({ id: `e-msg-${id}`, source: 'message', target: id });

    const providerNodes = [];
    if (report) providerNodes.push({ id: `vt-${i}`, label: `VirusTotal: ${formatStatus(report.status)}`, type: 'virustotal', report, malicious: vtMalicious });
    if (urlhausReport) providerNodes.push({ id: `urlhaus-${i}`, label: `URLhaus: ${formatStatus(urlhausReport.status)}`, type: 'urlhaus', report: urlhausReport, malicious: uhMalicious });
    if (gsbReport) providerNodes.push({ id: `gsb-${i}`, label: `Safe Browsing: ${formatStatus(gsbReport.status)}`, type: 'google_safe_browsing', report: gsbReport, malicious: gsbMalicious });
    if (ipReport) providerNodes.push({ id: `ipinfo-${i}`, label: `IPinfo: ${ipReport.ip || formatStatus(ipReport.status)}`, type: 'ipinfo', report: ipReport, malicious: false });
    if (rdapReport) {
      const ageLabel = rdapReport.domain_age_days !== null ? `${rdapReport.domain_age_days}d age` : formatStatus(rdapReport.status);
      providerNodes.push({ id: `rdap-${i}`, label: `RDAP: ${ageLabel}`, type: 'rdap', report: rdapReport, malicious: rdapRecent });
    }

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
    nodes: nodes.map((node) => {
      const badge = TYPE_BADGES[node.data.type] || {
        label: (node.data.type || '').toUpperCase(),
        color: '#94A3B8',
      };
      const isFlagged = node.style === flaggedStyle || node.data.malicious;
      const badgeColor = isFlagged ? '#F87171' : badge.color;

      let displayValue = node.data.label;
      if (node.data.type === 'message') {
        displayValue = 'Message';
      } else if (node.data.type === 'virustotal' && displayValue.startsWith('VirusTotal: ')) {
        displayValue = displayValue.replace('VirusTotal: ', '');
      } else if (node.data.type === 'urlhaus' && displayValue.startsWith('URLhaus: ')) {
        displayValue = displayValue.replace('URLhaus: ', '');
      } else if (node.data.type === 'google_safe_browsing' && displayValue.startsWith('Safe Browsing: ')) {
        displayValue = displayValue.replace('Safe Browsing: ', '');
      } else if (node.data.type === 'ipinfo' && displayValue.startsWith('IPinfo: ')) {
        displayValue = displayValue.replace('IPinfo: ', '');
      }

      return {
        ...node,
        style: { ...baseStyle, ...node.style },
        data: {
          ...node.data,
          label: (
            <div style={{ width: '100%', pointerEvents: 'none' }}>
              <div
                style={{
                  fontSize: '9px',
                  fontWeight: 700,
                  letterSpacing: '0.06em',
                  color: badgeColor,
                  marginBottom: '3px',
                  textTransform: 'uppercase',
                }}
              >
                {isFlagged ? `⚠️ ${badge.label}` : badge.label}
              </div>
              <div
                title={node.data.label}
                style={{
                  display: 'block',
                  width: '100%',
                  fontSize: '11px',
                  lineHeight: '1.3',
                  wordBreak: 'break-all',
                  whiteSpace: 'normal',
                  color: '#F8FAFC',
                }}
              >
                {displayValue}
              </div>
            </div>
          ),
          fullLabel: node.data.label,
        },
      };
    }),
    edges: edges.map((edge) => ({
      ...edge,
      type: 'smoothstep',
      style: { stroke: '#334155', strokeWidth: 1.5 },
    })),
  };
}

export default function ScamGraph({ data, onNodeClick }) {
  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => buildGraph(data), [data]);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 px-1 text-xs text-muted">
        <span className="font-mono uppercase tracking-wider text-white/90 font-medium">
          Evidence & Correlation Graph
        </span>
        <div className="flex flex-wrap items-center gap-3 font-mono text-[11px]">
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#38BDF8]"></span> URL/Input</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#A78BFA]"></span> Email</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#6EE7B7]"></span> Domain</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#94A3B8]"></span> Provider</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#E5484D]"></span> Threat</span>
        </div>
      </div>
      <GraphCanvas key={JSON.stringify(data)} initialNodes={initialNodes} initialEdges={initialEdges} onNodeClick={onNodeClick} />
    </div>
  );
}

function GraphCanvas({ initialNodes, initialEdges, onNodeClick }) {
  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);
  const handleSelectionChange = useCallback(({ nodes: selectedNodes }) => {
    const node = selectedNodes[0];
    onNodeClick(node ? { ...node, data: { ...node.data, label: node.data.fullLabel } } : null);
  }, [onNodeClick]);

  return (
    <div style={{ height: '460px', width: '100%' }} className="border border-border rounded-xl overflow-hidden">
      <ReactFlow 
        nodes={nodes} 
        edges={edges} 
        onNodesChange={onNodesChange} 
        onEdgesChange={onEdgesChange}
        onSelectionChange={handleSelectionChange}
        nodesConnectable={false} 
        nodesDraggable={false}
        minZoom={0.05} 
        fitView 
        fitViewOptions={{ padding: 0.2, maxZoom: 1 }}>
        <Background color="#253147" />
        <Controls />
      </ReactFlow>
    </div>
  );
}
