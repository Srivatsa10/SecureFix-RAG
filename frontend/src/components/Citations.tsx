import type { ResolvedCitation } from '../api/types';
import { formatPercent } from '../lib/format';
import styles from './Citations.module.css';

export function Citations({ citations }: { citations: ResolvedCitation[] }) {
  if (citations.length === 0) {
    return <p className={styles.empty}>The draft cited no sources.</p>;
  }
  return (
    <ul className={styles.list}>
      {citations.map((citation) => (
        <li key={citation.chunk_id} className={styles.item}>
          <details>
            <summary>
              <span className={citation.source === 'owasp' ? styles.owasp : styles.internal}>
                {citation.known ? (citation.source === 'owasp' ? 'OWASP' : 'Internal') : 'Unknown'}
              </span>
              <span className={styles.title}>{citation.title || citation.chunk_id}</span>
              {citation.relevance !== null ? (
                <span className={styles.relevance} title="Jev relevance (Noul)">
                  {formatPercent(citation.relevance)}
                </span>
              ) : null}
            </summary>
            <p className={styles.reason}>{citation.reason}</p>
            {citation.known ? (
              <>
                <p className={styles.path}>
                  <code>{citation.chunk_id}</code>
                  {citation.framework !== 'any' ? ` · ${citation.language}/${citation.framework}` : ''}
                </p>
                <pre className={styles.excerpt}>
                  <code>{citation.excerpt}</code>
                </pre>
              </>
            ) : (
              <p className={styles.warning}>
                This id was not among the retrieved sources - a possible hallucinated citation.
              </p>
            )}
          </details>
        </li>
      ))}
    </ul>
  );
}
