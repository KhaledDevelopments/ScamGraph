import assert from 'node:assert/strict';
import test from 'node:test';
import { createAnalysisSession, INITIAL_ANALYSIS_STATE, MAX_CONTENT_LENGTH } from '../src/utils/analysisSession.js';

function createHarness() {
  let state = INITIAL_ANALYSIS_STATE;
  const updates = [];
  const requests = [];
  const session = createAnalysisSession({
    request: (path, body, signal) => new Promise((resolve, reject) => {
      // Deliberately ignore abort: even a late transport response must be safe.
      requests.push({ path, body, signal, resolve, reject });
    }),
    onChange: (next) => {
      state = next;
      updates.push(next);
    },
  });
  return { session, requests, updates, get state() { return state; } };
}

const resultFor = (content) => ({
  content,
  assessment: { risk_score: 20, risk_level: 'LOW', assessment_status: 'partial' },
  indicators: { urls: [] },
});

async function finishAnalysis(harness, content) {
  const pending = harness.session.analyze(content);
  harness.requests.at(-1).resolve(resultFor(content));
  await pending;
}

test('resetting for a new preset aborts analysis and ignores its late response', async () => {
  const h = createHarness();
  const pending = h.session.analyze('Message A');
  assert.equal(h.state.loading, true);
  h.session.reset();
  assert.equal(h.requests[0].signal.aborted, true);
  h.requests[0].resolve(resultFor('Message A'));
  await pending;
  assert.deepEqual(h.state, INITIAL_ANALYSIS_STATE);
});

test('an older analysis cannot overwrite the result of a newer analysis', async () => {
  const h = createHarness();
  const old = h.session.analyze('Message A');
  await finishAnalysis(h, 'Message B');
  assert.equal(h.requests[0].signal.aborted, true);
  h.requests[0].resolve(resultFor('Message A'));
  await old;
  assert.equal(h.state.result.content, 'Message B');
  assert.equal(h.state.loading, false);
});

test('a stale analysis failure cannot clear the current loading state or show an error', async () => {
  const h = createHarness();
  const old = h.session.analyze('Message A');
  const current = h.session.analyze('Message B');
  h.requests[0].reject(new Error('Connection failed'));
  await old;
  assert.equal(h.state.loading, true);
  assert.equal(h.state.error, null);
  h.requests[1].resolve(resultFor('Message B'));
  await current;
  assert.equal(h.state.result.content, 'Message B');
});

test('an explanation for message A cannot appear under message B or stop its spinner', async () => {
  const h = createHarness();
  await finishAnalysis(h, 'Message A');
  const old = h.session.explain();
  const oldRequest = h.requests.at(-1);
  assert.deepEqual(oldRequest.body, resultFor('Message A'));
  await finishAnalysis(h, 'Message B');
  assert.equal(oldRequest.signal.aborted, true);
  assert.equal(h.state.explaining, false);
  const current = h.session.explain();
  const currentRequest = h.requests.at(-1);
  oldRequest.resolve({ status: 'ok', explanation: 'Explanation of A' });
  await old;
  assert.equal(h.state.explanation, null);
  assert.equal(h.state.explaining, true);
  currentRequest.resolve({ status: 'ok', source: 'fallback', explanation: 'Explanation of B' });
  await current;
  assert.equal(h.state.explanation.explanation, 'Explanation of B');
  assert.equal(h.state.explanation.source, 'fallback');
  assert.equal(h.state.explaining, false);
});

test('a stale explanation failure cannot replace a new explanation', async () => {
  const h = createHarness();
  await finishAnalysis(h, 'Message A');
  const old = h.session.explain();
  const oldRequest = h.requests.at(-1);
  await finishAnalysis(h, 'Message B');
  const current = h.session.explain();
  h.requests.at(-1).resolve({ status: 'ok', explanation: 'Explanation of B' });
  await current;
  oldRequest.reject(new Error('Connection failed'));
  await old;
  assert.equal(h.state.explanation.explanation, 'Explanation of B');
});

test('reset aborts a pending explanation and clears all result and busy state', async () => {
  const h = createHarness();
  await finishAnalysis(h, 'Message A');
  const pending = h.session.explain();
  const request = h.requests.at(-1);
  h.session.reset();
  assert.equal(request.signal.aborted, true);
  assert.deepEqual(h.state, INITIAL_ANALYSIS_STATE);
  request.resolve({ status: 'ok', explanation: 'Stale explanation' });
  await pending;
  assert.deepEqual(h.state, INITIAL_ANALYSIS_STATE);
});

test('component cleanup aborts pending analysis without publishing after unmount', async () => {
  const h = createHarness();
  const pending = h.session.analyze('Message A');
  const updateCount = h.updates.length;
  h.session.dispose();
  assert.equal(h.requests[0].signal.aborted, true);
  h.requests[0].resolve(resultFor('Message A'));
  await pending;
  assert.equal(h.updates.length, updateCount);
});

test('component cleanup aborts pending explanation without publishing after unmount', async () => {
  const h = createHarness();
  await finishAnalysis(h, 'Message A');
  const pending = h.session.explain();
  const request = h.requests.at(-1);
  const updateCount = h.updates.length;
  h.session.dispose();
  assert.equal(request.signal.aborted, true);
  request.reject(new Error('Aborted'));
  await pending;
  assert.equal(h.updates.length, updateCount);
});

test('invalid input is rejected before making a request', async () => {
  const h = createHarness();
  for (const content of ['', '  \n ', 'x'.repeat(MAX_CONTENT_LENGTH + 1)]) {
    await h.session.analyze(content);
    assert.equal(h.requests.length, 0);
    assert.match(h.state.error, /20,000 characters/);
    assert.equal(h.state.loading, false);
  }
});

test('the input limit counts Unicode code points consistently with the backend', async () => {
  const h = createHarness();
  const content = '😀'.repeat(MAX_CONTENT_LENGTH);
  await finishAnalysis(h, content);
  assert.equal(h.requests[0].body.content, content);
  assert.equal(h.state.error, null);
});

test('validation, rate-limit, server, and connection failures have useful errors', async () => {
  for (const [status, expected] of [[422, /20,000/], [413, /20,000/], [429, /Too many requests/], [500, /could not complete/], [null, /Could not reach/]]) {
    const h = createHarness();
    const pending = h.session.analyze('Message');
    h.requests[0].reject(status ? { response: { status } } : new Error('Network error'));
    await pending;
    assert.match(h.state.error, expected);
    assert.equal(h.state.loading, false);
    assert.equal(h.state.result, null);
  }
});

test('responses without an assessment cannot become a result', async () => {
  const h = createHarness();
  const pending = h.session.analyze('Message');
  h.requests[0].resolve({ content: 'Message' });
  await pending;
  assert.equal(h.state.result, null);
  assert.match(h.state.error, /outdated response/);
});

test('duplicate explanation requests are ignored and failure ends the busy state', async () => {
  const h = createHarness();
  await finishAnalysis(h, 'Message');
  const pending = h.session.explain();
  await h.session.explain();
  assert.equal(h.requests.length, 2);
  h.requests[1].reject(new Error('Network error'));
  await pending;
  assert.equal(h.state.explanation.status, 'unavailable');
  assert.equal(h.state.explaining, false);
});
