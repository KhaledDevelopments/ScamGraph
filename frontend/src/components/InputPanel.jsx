import { useState } from 'react';

export default function InputPanel({ onAnalyze }) {
  const [text, setText] = useState('');

  return (
    <div className="bg-gray-800 p-4 rounded-lg">
      <textarea
        className="w-full h-32 bg-gray-700 p-2 rounded text-white"
        placeholder="Paste suspicious content..."
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <button
        className="mt-2 bg-red-600 hover:bg-red-700 px-4 py-2 rounded"
        onClick={() => onAnalyze(text)}
      >
        Analyze
      </button>
    </div>
  );
}