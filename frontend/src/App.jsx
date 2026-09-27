import { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import InputPanel from './components/InputPanel';
import RiskScore from './components/RiskScore';
import ActionRecommendations from './components/ActionRecommendations';
import ScamGraph from './components/ScamGraph';
import EvidencePanel from './components/EvidencePanel';
import { createAnalysisSession, INITIAL_ANALYSIS_STATE } from './utils/analysisSession';
import { generateThreatReport } from './utils/reportGenerator';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

function FormattedExplanation({ text }) {
  if (!text) return null;
  const parts = text.split(/(\*\*.*?\*\*|`.*?`)/g);

  return (
    <p className="text-sm text-white/90 leading-relaxed">
      {parts.map((part, index) => {
        if (part.startsWith('**') && part.endsWith('**')) {
          return (
            <strong key={index} className="font-semibold text-white">
              {part.slice(2, -2)}
            </strong>
          );
        }
        if (part.startsWith('`') && part.endsWith('`')) {
          return (
            <code
              key={index}
              className="bg-slate-800/90 border border-slate-700/80 text-sky-300 font-mono text-xs px-1.5 py-0.5 rounded mx-0.5"
            >
              {part.slice(1, -1)}
            </code>
          );
        }
        return part;
      })}
    </p>
  );
}

function App() {
  const [state, setState] = useState(INITIAL_ANALYSIS_STATE);
  const [selectedNode, setSelectedNode] = useState(null);
  const [copied, setCopied] = useState(false);
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
    setCopied(false);
    return session.analyze(content);
  };

  const handleReset = () => {
    session.reset();
    setSelectedNode(null);
    setCopied(false);
  };

  const handleCopyReport = async () => {
    if (!result) return;
    const reportText = generateThreatReport(result, explanation);
    try {
      await navigator.clipboard.writeText(reportText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      // Ignore clipboard permission errors
    }
  };

  return (
    <div className="min-h-screen bg-base text-white font-sans">
      <div className="max-w-3xl mx-auto px-6 py-16">
        <div className="mb-10">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <p className="text-accent font-mono text-sm">threat analysis console</p>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-emerald-950/70 text-emerald-400 border border-emerald-800/50">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                Engine Online
              </span>
              <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-mono bg-surface text-muted border border-border">
                Hack Atlantic 2026
              </span>
            </div>
          </div>
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
            <div className="flex items-center justify-between pt-2">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                <span className="text-xs font-mono uppercase tracking-wider text-muted font-medium">Threat Assessment Result</span>
              </div>
              <button
                type="button"
                onClick={handleCopyReport}
                className="inline-flex items-center gap-1.5 text-xs text-muted hover:text-white bg-surface hover:bg-slate-800 border border-border px-3 py-1.5 rounded-lg transition-colors font-mono"
              >
                {copied ? '✓ Report Copied!' : '📋 Copy Threat Report'}
              </button>
            </div>

            <RiskScore assessment={result.assessment} />
            <ActionRecommendations assessment={result.assessment} />
            <ScamGraph data={result} onNodeClick={setSelectedNode} />

            {selectedNode ? (
              <EvidencePanel node={selectedNode} onClose={() => setSelectedNode(null)} />
            ) : (
              <div className="border border-dashed border-border/70 rounded-xl bg-surface/40 p-4 text-center text-xs text-muted font-mono">
                👆 Click any node in the graph above to view its provider intelligence & evidence
              </div>
            )}

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
                  <FormattedExplanation text={explanation.explanation} />
                </div>
              )}
              {explanation && explanation.status !== 'ok' && (
                <p className="text-sm text-muted italic">Plain-English explanation unavailable right now.</p>
              )}
            </div>
          </div>
        )}

        <footer className="mt-20 pt-8 border-t border-border/60 text-center text-xs text-muted space-y-2">
          <p>
            <strong>ScamGraph</strong> · Built for <strong>Hack Atlantic 2026</strong>
          </p>
          <p className="text-[11px] text-muted/80">
            Correlating Local Warnings, VirusTotal, URLhaus, Google Safe Browsing, IPinfo, RDAP & Gemini
          </p>
          <p className="text-[11px] font-mono">
            <a
              href="https://github.com/KhaledDevelopments/ScamGraph"
              target="_blank"
              rel="noopener noreferrer"
              className="text-accent hover:underline"
            >
              github.com/KhaledDevelopments/ScamGraph
            </a>
          </p>
        </footer>
      </div>
    </div>
  );
}

export default App;
