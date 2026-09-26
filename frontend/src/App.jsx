import { useState } from 'react';
import axios from 'axios';
import InputPanel from './components/InputPanel';
import RiskScore from './components/RiskScore';
import ScamGraph from './components/ScamGraph';
import EvidencePanel from './components/EvidencePanel';

function App() {
  const [result, setResult] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);

  const handleAnalyze = async (content) => {
    const res = await axios.post('http://localhost:8000/analyze', { content });
    setResult(res.data);
    setSelectedNode(null);
  };

  return (
    <div className="min-h-screen bg-base text-white font-sans">
      <div className="max-w-3xl mx-auto px-6 py-16">
        <div className="mb-10">
          <p className="text-accent font-mono text-sm mb-2">threat analysis console</p>
          <h1 className="text-4xl font-bold tracking-tight">ScamGraph</h1>
          <p className="text-muted mt-2">Paste a suspicious message or link. We'll show you exactly why it's dangerous.</p>
        </div>

        <InputPanel onAnalyze={handleAnalyze} />

        {result && (
          <div className="mt-8 space-y-6">
            <RiskScore data={result} />
            <ScamGraph onNodeClick={setSelectedNode} />
            {selectedNode && <EvidencePanel node={selectedNode} />}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;