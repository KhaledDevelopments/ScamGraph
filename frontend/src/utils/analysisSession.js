export const MAX_CONTENT_LENGTH = 20_000;

export const INITIAL_ANALYSIS_STATE = {
  result: null,
  loading: false,
  error: null,
  explanation: null,
  explaining: false,
};

function analysisError(error) {
  const status = error.response?.status;
  if (status === 422 || status === 413) {
    return `Enter a message or link with at most ${MAX_CONTENT_LENGTH.toLocaleString('en-US')} characters.`;
  }
  if (status === 429) return 'Too many requests. Wait a moment and try again.';
  if (status) return 'The analysis server could not complete this request. Please try again.';
  return 'Could not reach the analysis server. Check your connection and that the backend is running.';
}

// Request identity also guards transports that finish after cancellation.
export function createAnalysisSession({ request, onChange }) {
  let state = INITIAL_ANALYSIS_STATE;
  let version = 0;
  let analysisRequest = null;
  let explanationRequest = null;

  const publish = (patch) => {
    state = { ...state, ...patch };
    onChange(state);
  };

  const cancel = () => {
    version += 1;
    analysisRequest?.abort();
    explanationRequest?.abort();
    analysisRequest = null;
    explanationRequest = null;
  };

  return {
    async analyze(content) {
      cancel();
      if (!content.trim() || Array.from(content).length > MAX_CONTENT_LENGTH) {
        publish({ ...INITIAL_ANALYSIS_STATE, error: analysisError({ response: { status: 422 } }) });
        return;
      }

      const currentVersion = version;
      analysisRequest = new AbortController();
      publish({ ...INITIAL_ANALYSIS_STATE, loading: true });
      try {
        const data = await request('/analyze', { content }, analysisRequest.signal);
        if (currentVersion !== version) return;
        if (!data?.assessment) {
          publish({ error: 'The backend returned an outdated response. Restart the backend and try again.' });
          return;
        }
        publish({ result: data });
      } catch (error) {
        if (currentVersion === version) publish({ error: analysisError(error), result: null });
      } finally {
        if (currentVersion === version) {
          analysisRequest = null;
          publish({ loading: false });
        }
      }
    },

    async explain() {
      if (!state.result || state.loading || state.explaining || state.explanation) return;
      const currentVersion = version;
      const { content, assessment, indicators } = state.result;
      explanationRequest = new AbortController();
      publish({ explaining: true });
      try {
        const data = await request('/explain', { content, assessment, indicators }, explanationRequest.signal);
        if (currentVersion === version) {
          publish({ explanation: data || { status: 'unavailable', explanation: null } });
        }
      } catch {
        if (currentVersion === version) publish({ explanation: { status: 'unavailable', explanation: null } });
      } finally {
        if (currentVersion === version) {
          explanationRequest = null;
          publish({ explaining: false });
        }
      }
    },

    reset() {
      cancel();
      publish(INITIAL_ANALYSIS_STATE);
    },

    dispose: cancel,
  };
}
