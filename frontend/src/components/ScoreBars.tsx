import { SCORE_DIMENSIONS, type EvaluationScores } from '../api/types';
import { DIMENSION_HINTS, DIMENSION_LABELS } from '../lib/format';
import styles from './ScoreBars.module.css';

interface ScoreBarsProps {
  scores: EvaluationScores;
  threshold: number;
}

export function ScoreBars({ scores, threshold }: ScoreBarsProps) {
  return (
    <ul className={styles.list}>
      {SCORE_DIMENSIONS.map((dimension) => {
        const score = scores[dimension];
        const passed = score.value >= threshold;
        return (
          <li key={dimension} className={styles.item}>
            <div className={styles.labelRow}>
              <span className={styles.label} title={DIMENSION_HINTS[dimension]}>
                {DIMENSION_LABELS[dimension]}
              </span>
              <span className={passed ? styles.pass : styles.fail}>
                {score.value.toFixed(2)} {passed ? '✓' : '✗'}
              </span>
            </div>
            <div
              className={styles.track}
              role="meter"
              aria-label={DIMENSION_LABELS[dimension]}
              aria-valuemin={0}
              aria-valuemax={1}
              aria-valuenow={score.value}
            >
              <div
                className={passed ? styles.fillPass : styles.fillFail}
                style={{ width: `${Math.round(score.value * 100)}%` }}
              />
              <div
                className={styles.threshold}
                style={{ left: `${threshold * 100}%` }}
                title={`threshold ${threshold.toFixed(2)}`}
              />
            </div>
            <div className={styles.meta}>
              {score.level} · confidence {score.confidence.toFixed(2)}
            </div>
          </li>
        );
      })}
    </ul>
  );
}
