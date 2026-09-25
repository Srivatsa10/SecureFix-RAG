import type { RemediationResult } from '../api/types';
import { STATUS_LABELS, formatMs, formatPercent, humanize } from '../lib/format';
import { Card } from './Card';
import { Citations } from './Citations';
import { CostPanel } from './CostPanel';
import { DecisionTrace } from './DecisionTrace';
import { DiffView } from './DiffView';
import styles from './ResultView.module.css';
import { ScoreBars } from './ScoreBars';

export function ResultView({ result }: { result: RemediationResult }) {
  const { patch, scores } = result;
  return (
    <div className={styles.stack}>
      <section className={styles[result.status]} aria-live="polite" aria-label="Outcome">
        <div className={styles.statusRow}>
          <h2 className={styles.statusTitle}>{STATUS_LABELS[result.status]}</h2>
          <span className={styles.facts}>
            {result.vuln_class ? humanize(result.vuln_class) : null}
            {result.vuln_confidence !== null ? ` (${formatPercent(result.vuln_confidence)})` : null}
            {' · '}
            {result.attempts} attempt{result.attempts === 1 ? '' : 's'} · {formatMs(result.latency_ms)}
          </span>
        </div>
        {result.rejection_reason ? <p className={styles.reason}>{result.rejection_reason}</p> : null}
        {result.handoff_reason ? <p className={styles.reason}>{result.handoff_reason}</p> : null}
      </section>

      {patch ? (
        <Card
          title={result.requires_human_review ? 'Best partial patch' : 'Patch'}
          subtitle={
            patch.conventions_applied.length
              ? `Conventions: ${patch.conventions_applied.join(', ')}`
              : undefined
          }
        >
          <DiffView diff={patch.diff} patchedCode={patch.patched_code} />
          <p className={styles.explanation}>{patch.explanation}</p>
        </Card>
      ) : null}

      {scores ? (
        <Card title="Jev evaluation" subtitle={`Every dimension must reach ${result.score_threshold.toFixed(2)} to ship.`}>
          <ScoreBars scores={scores} threshold={result.score_threshold} />
        </Card>
      ) : null}

      {patch ? (
        <Card title="Citations" subtitle="Retrieved chunks the patch is grounded in.">
          <Citations citations={result.citations} />
        </Card>
      ) : null}

      <Card title="Decision trace" subtitle={`Request ${result.request_id}`}>
        <DecisionTrace trace={result.trace} usage={result.usage} />
      </Card>

      <Card title="Cost">
        <CostPanel cost={result.cost} />
      </Card>
    </div>
  );
}
