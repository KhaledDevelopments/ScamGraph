import { useState } from 'react';
import ReactFlow, { Background, Controls, useNodesState, useEdgesState } from 'reactflow';
import 'reactflow/dist/style.css';

const initialNodes = [
  { id: 'email', position: { x: 250, y: 0 }, data: { label: 'EMAIL' }, style: { background: '#374151', color: 'white' } },
  { id: 'url', position: { x: 100, y: 100 }, data: { label: 'URL' }, style: { background: '#374151', color: 'white' } },
  { id: 'sender', position: { x: 400, y: 100 }, data: { label: 'SENDER' }, style: { background: '#374151', color: 'white' } },
  { id: 'domain', position: { x: 100, y: 200 }, data: { label: 'unb-secure-login.xyz' }, style: { background: '#7f1d1d', color: 'white' } },
  { id: 'vt', position: { x: 100, y: 300 }, data: { label: 'VirusTotal: FLAGGED' }, style: { background: '#991b1b', color: 'white' } },
];

const initialEdges = [
  { id: 'e1', source: 'email', target: 'url' },
  { id: 'e2', source: 'email', target: 'sender' },
  { id: 'e3', source: 'url', target: 'domain' },
  { id: 'e4', source: 'domain', target: 'vt' },
];

export default function ScamGraph() {
  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  return (
    <div style={{ height: '400px', width: '100%' }} className="bg-gray-800 rounded-lg mt-4">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodesConnectable={false}
        fitView
      >
        <Background color="#444" />
        <Controls />
      </ReactFlow>
    </div>
  );
}