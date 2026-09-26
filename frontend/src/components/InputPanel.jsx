import { useState } from 'react';

export default function InputPanel({ onAnalyze }) {
  const [text, setText] = useState('');

  return (
    <div className="border border-border rounded-xl bg-surface p-1 focus-within:border-accent transition-colors">
      <textarea
        className="w-full h-36 bg-transparent p-4 text-white placeholder-muted resize-none focus:outline-none"
        placeholder="Paste an email, text message, or link..."
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <div className="flex justify-end p-2">
        <button
          className="bg-accent hover:bg-sky-400 text-base font-medium px-6 py-2.5 rounded-lg transition-colors disabled:opacity-40"
          onClick={() => onAnalyze(text)}
          disabled={!text.trim()}
        >
          Analyze
        </button>
      </div>
    </div>
  );
}