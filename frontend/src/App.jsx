import { useState } from 'react';
import axios from 'axios';
import InputPanel from './components/InputPanel';
import RiskScore from './components/RiskScore';
import ScamGraph from './components/ScamGraph';

function App() {
  const [result, setResult] = useState(null);

  const handleAnalyze = async (content) => {
    const res = await axios.post('http://localhost:8000/analyze', { content });
    setResult(res.data);
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <h1 className="text-3xl font-bold mb-6">ScamGraph</h1>
      <InputPanel onAnalyze={handleAnalyze} />
      {result && <RiskScore data={result} />}
      {result && <ScamGraph />}
    </div>
  );
}

export default App;