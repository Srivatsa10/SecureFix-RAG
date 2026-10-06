import type { CostSummary } from '../api/types';
import { formatUsd } from '../lib/format';
import styles from './CostPanel.module.css';

export function CostPanel({ cost }: { cost: CostSummary }) {
  const judgeRan = cost.decision_layer === 'llm_judge';
  const rows = [
    {
      label: 'Jev decision layer',
      tag: judgeRan ? 'estimate' : 'this run',
      decisions: cost.jev_usd,
      total: cost.total_with_jev_usd,
      actual: !judgeRan,
    },
    {
      label: 'LLM judge',
      tag: judgeRan ? 'this run' : 'estimate',
      decisions: cost.llm_judge_decision_usd,
      total: cost.total_with_llm_judge_usd,
      actual: judgeRan,
    },
  ];
  return (
    <div className={styles.panel}>
      <table className={styles.table}>
        <thead>
          <tr>
            <th scope="col" />
            <th scope="col">Generation</th>
            <th scope="col">Decisions</th>
            <th scope="col">Total</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.label} className={row.actual ? styles.actual : undefined}>
              <th scope="row">
                {row.label} <span className={styles.tag}>({row.tag})</span>
              </th>
              <td>{formatUsd(cost.generation_usd)}</td>
              <td className={row.actual ? styles.highlight : undefined}>
                {formatUsd(row.decisions)}
              </td>
              <td>{formatUsd(row.total)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className={styles.note}>
        {cost.decisions} typed decisions in {cost.decision_calls} calls
        {cost.decision_cost_ratio
          ? ` · Jev is ${String(Math.round(cost.decision_cost_ratio))}× cheaper than an LLM judge for these decisions`
          : ''}
        {cost.priced_mock_calls ? ' · includes mocked/offline calls priced at list rates' : ''}
      </p>
    </div>
  );
}
