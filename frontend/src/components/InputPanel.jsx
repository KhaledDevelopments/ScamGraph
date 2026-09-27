import { useState } from 'react';
import { MAX_CONTENT_LENGTH } from '../utils/analysisSession';

const PRESETS = [
  {
    id: 'unb-phish',
    label: '🚨 UNB Phish (Live DNS & IPinfo)',
    text: `FINAL NOTICE: Your UNB student account has been suspended due to suspicious activity. You must act immediately to confirm your credentials and restore access: https://unb.netlify.app/login\n\nIf you need assistance, contact admin-support@unb-notice.com right away.`,
  },
  {
    id: 'google-safe-browsing',
    label: '⚠️ Google Safe Browsing & VT Hit',
    text: `URGENT SECURITY ALERT: Unauthorized sign-in detected on your account. Confirm your credentials immediately to prevent permanent account suspension: http://testsafebrowsing.appspot.com/s/phishing.html`,
  },
  {
    id: 'urlhaus-malware',
    label: '☣️ URLhaus Malware Listing',
    text: `Critical security update: Download and apply the system patch immediately from the distribution host: http://123.11.10.172:55820/bin.sh`,
  },
  {
    id: 'legitimate',
    label: '🟢 Official UNB (Clean Baseline)',
    text: `Welcome to the semester at UNB! For orientation information, academic dates, and course schedules, visit the official student portal at https://unb.ca/students or email questions@unb.ca.`,
  },
];

export default function InputPanel({ onAnalyze, onReset, loading, hasResult }) {
  const [text, setText] = useState('');
  const characterCount = Array.from(text).length;
  const tooLong = characterCount > MAX_CONTENT_LENGTH;

  const handlePreset = (presetText) => {
    setText(presetText);
    if (onReset) onReset();
  };

  const handleClear = () => {
    setText('');
    if (onReset) onReset();
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (text.trim() && !loading && !tooLong) {
        onAnalyze(text);
      }
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-muted font-medium">Sample scenarios:</span>
        {PRESETS.map((preset) => (
          <button
            key={preset.id}
            type="button"
            onClick={() => handlePreset(preset.text)}
            className="text-xs bg-surface border border-border hover:border-accent text-slate-300 hover:text-white px-2.5 py-1 rounded-md transition-colors"
          >
            {preset.label}
          </button>
        ))}
      </div>

      <label htmlFor="message-content" className="block text-sm font-medium">Message or link to analyze</label>
      <div className="border border-border rounded-xl bg-surface p-1 focus-within:border-accent transition-colors">
        <textarea
          id="message-content"
          className="w-full h-36 bg-transparent p-4 text-white placeholder-muted resize-none focus:outline-none"
          placeholder="Paste an email, text message, or link..."
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            onReset?.();
          }}
          onKeyDown={handleKeyDown}
          aria-describedby="message-length"
          aria-invalid={tooLong}
        />
        <p id="message-length" className={`px-4 text-xs ${tooLong ? 'text-risk-high' : 'text-muted'}`}>
          {characterCount.toLocaleString('en-US')} / {MAX_CONTENT_LENGTH.toLocaleString('en-US')} characters
          {tooLong && ' — shorten the message before analyzing.'}
        </p>
        <div className="flex items-center justify-between p-2">
          {(text || hasResult) ? (
            <button
              type="button"
              onClick={handleClear}
              className="text-xs text-muted hover:text-white px-3 py-1.5 rounded-md hover:bg-slate-800 transition-colors"
            >
              ✕ Clear / Reset
            </button>
          ) : (
            <div />
          )}
          <button
            className="bg-accent hover:bg-sky-400 text-base font-medium px-6 py-2.5 rounded-lg transition-colors disabled:opacity-40"
            onClick={() => onAnalyze(text)}
            disabled={!text.trim() || loading || tooLong}
          >
            {loading ? 'Analyzing...' : 'Analyze'}
          </button>
        </div>
      </div>
    </div>
  );
}
