import { useMemo, useState } from 'react';

import { diffStats, parseUnifiedDiff } from '../lib/diff';
import styles from './DiffView.module.css';

interface DiffViewProps {
  diff: string;
  patchedCode: string;
}

export function DiffView({ diff, patchedCode }: DiffViewProps) {
  const lines = useMemo(() => parseUnifiedDiff(diff), [diff]);
  const { added, removed } = diffStats(lines);
  const hasDiff = added + removed > 0;
  const [view, setView] = useState<'diff' | 'full'>(hasDiff ? 'diff' : 'full');
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(patchedCode);
      setCopied(true);
      window.setTimeout(() => { setCopied(false); }, 1500);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className={styles.wrapper}>
      <div className={styles.toolbar}>
        <div className={styles.tabs} role="tablist" aria-label="Patch view">
          <button
            type="button"
            role="tab"
            aria-selected={view === 'diff'}
            disabled={!hasDiff}
            onClick={() => { setView('diff'); }}
          >
            Diff{hasDiff ? ` +${added} −${removed}` : ' (no changes)'}
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={view === 'full'}
            onClick={() => { setView('full'); }}
          >
            Patched code
          </button>
        </div>
        <button type="button" className={styles.copy} onClick={() => void copy()}>
          {copied ? 'Copied' : 'Copy patch'}
        </button>
      </div>

      {view === 'diff' && hasDiff ? (
        <pre className={styles.code} aria-label="Unified diff">
          {lines
            .filter((line) => line.kind !== 'meta')
            .map((line, index) => (
              <div key={index} className={styles[line.kind]}>
                <span className={styles.gutter} aria-hidden>
                  {line.oldNumber ?? ''}
                </span>
                <span className={styles.gutter} aria-hidden>
                  {line.newNumber ?? ''}
                </span>
                <span className={styles.sign} aria-hidden>
                  {line.kind === 'add' ? '+' : line.kind === 'remove' ? '−' : ' '}
                </span>
                <code>{line.text}</code>
              </div>
            ))}
        </pre>
      ) : (
        <pre className={styles.code} aria-label="Patched code">
          <code className={styles.plain}>{patchedCode}</code>
        </pre>
      )}
    </div>
  );
}
