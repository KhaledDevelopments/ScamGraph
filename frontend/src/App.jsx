import { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import InputPanel from './components/InputPanel';
import RiskScore from './components/RiskScore';
import ScamGraph from './components/ScamGraph';
import EvidencePanel from './components/EvidencePanel';
import { createAnalysisSession, INITIAL_ANALYSIS_STATE } from './utils/analysisSession';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

function App() {
  const [state, setState] = useState(INITIAL_ANALYSIS_STATE);
  const [selectedNode, setSelectedNode] = useState(null);
  const { result, loading, error, explanation, explaining } = state;
  const session = useMemo(() => createAnalysisSession({
    request: async (path, body, signal) => {
      const response = await axios.post(`${API_BASE_URL}${path}`, body, { signal });
      return response.data;
    },
    onChange: setState,
  }), []);

  useEffect(() => () => session.dispose(), [session]);

  const handleAnalyze = (content) => {
    setSelectedNode(null);
    return session.analyze(content);
  };

  const handleReset = () => {
    session.reset();
    setSelectedNode(null);
  };

  return (
    <div className="min-h-screen bg-base text-white font-sans">
      <div className="max-w-3xl mx-auto px-6 py-16">
        <div className="mb-10">
          <p className="text-accent font-mono text-sm mb-2">threat analysis console</p>
          <h1 className="text-4xl font-bold tracking-tight">ScamGraph</h1>
          <p className="text-muted mt-2">Paste a suspicious message or link to inspect warning signs and available threat intelligence.</p>
        </div>

        <InputPanel
          onAnalyze={handleAnalyze}
          onReset={handleReset}
          loading={loading}
          hasResult={Boolean(result)}
        />

        {loading && <p role="status" className="text-muted mt-6">Analyzing...</p>}
        {error && <p role="alert" className="text-risk-high mt-6">{error}</p>}

        {result && !loading && (
          <div className="mt-8 space-y-6">
            <RiskScore assessment={result.assessment} />
            <ScamGraph data={result} onNodeClick={setSelectedNode} />
            {selectedNode && <EvidencePanel node={selectedNode} />}

            <div className="border border-border rounded-xl bg-surface p-6">
              {!explanation && (
                <button
                  onClick={session.explain}
                  disabled={explaining}
                  className="text-accent hover:text-sky-400 text-sm font-medium disabled:opacity-40"
                >
                  {explaining ? 'Generating explanation...' : '✦ Explain this in plain English'}
                </button>
              )}
              {explanation?.status === 'ok' && (
                <div>
                  {explanation.source === 'fallback' && (
                    <p className="text-xs text-muted mb-2">Evidence summary · AI explanation unavailable</p>
                  )}
                  <p className="text-sm text-white/90 leading-relaxed">{explanation.explanation}</p>
                </div>
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
