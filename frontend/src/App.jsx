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
  const [explanation, setExplanation] = useState(null);
  const [explaining, setExplaining] = useState(false);

  const handleAnalyze = async (content) => {
    if (loading || !content.trim()) return;
    setLoading(true);
    setError(null);
    setSelectedNode(null);
    setExplanation(null);
    try {
      const res = await axios.post(`${API_BASE_URL}/analyze`, { content });
      if (!res.data?.assessment) {
        setError('The backend returned an outdated response. Restart the backend and try again.');
        setResult(null);
        return;
      }
      setResult(res.data);
    } catch {
      setError('Could not reach the analysis server. Is the backend running?');
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const handleExplain = async () => {
    if (!result) return;
    setExplaining(true);
    try {
      const res = await axios.post(`${API_BASE_URL}/explain`, {
        content: result.content,
        assessment: result.assessment,
        indicators: result.indicators,
      });
      setExplanation(res.data);
    } catch (err) {
      setExplanation({ status: 'unavailable', explanation: null });
    } finally {
      setExplaining(false);
    }
  };

  const handleReset = () => {
    setResult(null);
    setSelectedNode(null);
    setError(null);
    setExplanation(null);
  };

  return (
    <div
      className="bg-base text-white font-sans"
      style={{ width: '420px', minHeight: '500px', maxHeight: '600px', overflowY: 'auto' }}
    >
      <div className="max-w-3xl mx-auto px-6 py-16">
        <div className="mb-10">
          <p className="text-accent font-mono text-sm mb-2">threat analysis console</p>
          <h1 className="text-4xl font-bold tracking-tight">ScamGraph</h1>
          <p className="text-muted mt-2">Paste a suspicious message or link. We'll show you exactly why it's dangerous.</p>
        </div>

        <InputPanel
          onAnalyze={handleAnalyze}
          onReset={handleReset}
          loading={loading}
          hasResult={Boolean(result)}
        />

        {loading && <p className="text-muted mt-6">Analyzing...</p>}
        {error && <p className="text-risk-high mt-6">{error}</p>}

        {result && !loading && (
          <div className="mt-8 space-y-6">
            <RiskScore assessment={result.assessment} />
            <ScamGraph data={result} onNodeClick={setSelectedNode} />
            {selectedNode && <EvidencePanel node={selectedNode} />}

            <div className="border border-border rounded-xl bg-surface p-6">
              {!explanation && (
                <button
                  onClick={handleExplain}
                  disabled={explaining}
                  className="text-accent hover:text-sky-400 text-sm font-medium disabled:opacity-40"
                >
                  {explaining ? 'Generating explanation...' : '✦ Explain this in plain English'}
                </button>
              )}
              {explanation?.status === 'ok' && (
                <p className="text-sm text-white/90 leading-relaxed">{explanation.explanation}</p>
              )}
              {explanation && explanation.status !== 'ok' && (
                <p className="text-sm text-muted italic">Plain-English explanation unavailable right now.</p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;