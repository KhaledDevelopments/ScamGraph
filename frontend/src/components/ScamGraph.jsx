import { useNodesState, useEdgesState, default as ReactFlow, Background, Controls } from 'reactflow';
import 'reactflow/dist/style.css';

const initialNodes = [
  { id: 'email', position: { x: 250, y: 0 }, data: { label: 'EMAIL' }, style: { background: '#141B2D', color: '#fff', border: '1px solid #253147', fontFamily: 'monospace' } },
  { id: 'url', position: { x: 100, y: 100 }, data: { label: 'URL' }, style: { background: '#141B2D', color: '#fff', border: '1px solid #253147', fontFamily: 'monospace' } },
  { id: 'sender', position: { x: 400, y: 100 }, data: { label: 'SENDER' }, style: { background: '#141B2D', color: '#fff', border: '1px solid #253147', fontFamily: 'monospace' } },
  { id: 'domain', position: { x: 100, y: 200 }, data: { label: 'unb-secure-login.xyz' }, style: { background: '#3B1418', color: '#fff', border: '1px solid #E5484D', fontFamily: 'monospace' } },
  { id: 'vt', position: { x: 100, y: 300 }, data: { label: 'VirusTotal: FLAGGED' }, style: { background: '#3B1418', color: '#fff', border: '1px solid #E5484D', fontFamily: 'monospace' } },
];

const initialEdges = [
  { id: 'e1', source: 'email', target: 'url' },
  { id: 'e2', source: 'email', target: 'sender' },
  { id: 'e3', source: 'url', target: 'domain' },
  { id: 'e4', source: 'domain', target: 'vt' },
];

export default function ScamGraph({ onNodeClick }) {
  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  return (
    <div style={{ height: '400px', width: '100%' }} className="border border-border rounded-xl overflow-hidden">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={(event, node) => onNodeClick(node)}
        nodesConnectable={false}
        fitView
      >
        <Background color="#253147" />
        <Controls />
      </ReactFlow>
    </div>
  );
}