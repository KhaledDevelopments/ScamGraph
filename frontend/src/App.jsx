import { useState } from 'react';
import axios from 'axios';
import InputPanel from './components/InputPanel';
import RiskScore from './components/RiskScore';
import ScamGraph from './components/ScamGraph';
import EvidencePanel from './components/EvidencePanel';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

function App() {
  const [result, setResult] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleAnalyze = async (content) => {
    if (!content.trim()) return;
    setLoading(true);
    setError(null);
    setSelectedNode(null);
    try {
      const res = await axios.post(`${API_BASE_URL}/analyze`, { content });
      setResult(res.data);
    } catch (err) {
      setError('Could not reach the analysis server. Is the backend running?');
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-base text-white font-sans">
      <div className="max-w-3xl mx-auto px-6 py-16">
        <div className="mb-10">
          <p className="text-accent font-mono text-sm mb-2">threat analysis console</p>
          <h1 className="text-4xl font-bold tracking-tight">ScamGraph</h1>
          <p className="text-muted mt-2">Paste a suspicious message or link. We'll show you exactly why it's dangerous.</p>
        </div>

        <InputPanel onAnalyze={handleAnalyze} loading={loading} />

        {loading && <p className="text-muted mt-6">Analyzing...</p>}
        {error && <p className="text-risk-high mt-6">{error}</p>}

        {result && !loading && (
          <div className="mt-8 space-y-6">
            <RiskScore assessment={result.assessment} />
            <ScamGraph data={result} onNodeClick={setSelectedNode} />
            {selectedNode && <EvidencePanel node={selectedNode} />}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;