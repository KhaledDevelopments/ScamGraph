const STATUS_LABELS = {
  ok: 'Checked',
  not_found: 'Not found in database',
  not_configured: 'Not configured',
  rate_limited: 'Rate limited — try again shortly',
  unavailable: 'Temporarily unavailable',
  skipped: 'Skipped',
};

export function formatStatus(status) {
  return STATUS_LABELS[status] || status;
}