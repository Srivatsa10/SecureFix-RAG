import type { CostSummary } from '../api/types';
import { formatUsd } from '../lib/format';
import styles from './CostPanel.module.css';

export function CostPanel({ cost }: { cost: CostSummary }) {
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
          <tr>
            <th scope="row">Jev decision layer</th>
            <td>{formatUsd(cost.generation_usd)}</td>
            <td className={styles.highlight}>{formatUsd(cost.jev_usd)}</td>
            <td>{formatUsd(cost.total_usd)}</td>
          </tr>
          <tr>
            <th scope="row">LLM judge instead</th>
            <td>{formatUsd(cost.generation_usd)}</td>
            <td>{formatUsd(cost.llm_judge_decision_usd)}</td>
            <td>{formatUsd(cost.total_with_llm_judge_usd)}</td>
          </tr>
        </tbody>
      </table>
      <p className={styles.note}>
        {cost.jev_decisions} typed decisions in {cost.jev_calls} Jev calls
        {cost.decision_cost_ratio ? ` · decision layer ${Math.round(cost.decision_cost_ratio)}× cheaper` : ''}
        {cost.priced_mock_calls ? ' · includes mocked/offline calls priced at list rates' : ''}
      </p>
    </div>
  );
}
