import type { RemediationStatus, ScoreDimension } from '../api/types';

export const DIMENSION_LABELS: Record<ScoreDimension, string> = {
  groundedness: 'Groundedness',
  security_correctness: 'Security correctness',
  framework_fit: 'Framework fit',
};

export const DIMENSION_HINTS: Record<ScoreDimension, string> = {
  groundedness: 'Is the patch derived from the retrieved sources rather than invented?',
  security_correctness: 'Does it actually close the vulnerability class?',
  framework_fit: 'Does it follow the internal snippets’ conventions?',
};

export const STATUS_LABELS: Record<RemediationStatus, string> = {
  shipped: 'Patch shipped',
  rejected: 'Rejected at intent gate',
  human_review_required: 'Human review required',
};

export function formatUsd(value: number): string {
  if (value === 0) return '$0';
  if (value < 0.0001) return `$${value.toExponential(2)}`;
  if (value < 0.01) return `$${value.toFixed(5)}`;
  return `$${value.toFixed(4)}`;
}

export function formatMs(value: number): string {
  return value >= 1000 ? `${(value / 1000).toFixed(2)} s` : `${value.toFixed(value < 10 ? 1 : 0)} ms`;
}

export function formatPercent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

export function humanize(identifier: string): string {
  return identifier.replace(/_/g, ' ');
}
