import type { TraceEvent, UsageRecord } from '../api/types';
import { formatMs } from '../lib/format';
import styles from './DecisionTrace.module.css';

type Actor = 'jev' | 'bedrock' | 'control' | 'terminal';

const NODE_ACTOR: Record<string, Actor> = {
  intent_gate: 'jev',
  rerank_chunks: 'jev',
  evaluate_draft: 'jev',
  draft_patch: 'bedrock',
  retrieve_dual: 'control',
  circuit_breaker: 'control',
  retry_with_adjusted_retrieval: 'control',
  finalize: 'terminal',
  human_handoff: 'terminal',
  reject: 'terminal',
};

/** Label actors by what actually served the request, so mocks are never shown as the real thing. */
function actorLabels(usage: UsageRecord[]): Record<Actor, string> {
  const jevMocked = usage.some((u) => u.provider === 'jev' && u.mocked);
  const offlineGenerator = usage.some((u) => u.provider === 'offline');
  return {
    jev: jevMocked ? 'Jev (mock)' : 'Jev',
    bedrock: offlineGenerator ? 'Offline generator' : 'Bedrock',
    control: 'Graph',
    terminal: 'Result',
  };
}

function groupByAttempt(trace: TraceEvent[]): [number, TraceEvent[]][] {
  const groups = new Map<number, TraceEvent[]>();
  for (const event of trace) {
    const group = groups.get(event.attempt) ?? [];
    group.push(event);
    groups.set(event.attempt, group);
  }
  return [...groups.entries()];
}

interface DecisionTraceProps {
  trace: TraceEvent[];
  usage: UsageRecord[];
}

export function DecisionTrace({ trace, usage }: DecisionTraceProps) {
  const labels = actorLabels(usage);
  return (
    <div className={styles.attempts}>
      {groupByAttempt(trace).map(([attempt, events]) => (
        <section key={attempt} aria-label={`Attempt ${attempt + 1}`}>
          <h3 className={styles.attemptTitle}>
            {attempt === 0 ? 'Attempt 1' : `Retry ${attempt}`}
          </h3>
          <ol className={styles.timeline}>
            {events.map((event, index) => {
              const actor = NODE_ACTOR[event.node] ?? 'control';
              return (
                <li key={`${event.node}-${index}`} className={styles[actor]}>
                  <div className={styles.head}>
                    <code className={styles.node}>{event.node}</code>
                    <span className={styles.actor}>{labels[actor]}</span>
                    {event.duration_ms > 0 ? (
                      <span className={styles.duration}>{formatMs(event.duration_ms)}</span>
                    ) : null}
                  </div>
                  <p className={styles.summary}>{event.summary}</p>
                </li>
              );
            })}
          </ol>
        </section>
      ))}
    </div>
  );
}
