import type { RuntimeInfo } from '../api/types';

import styles from './RuntimeBanner.module.css';

/** Always visible, so mocked/offline results can never be mistaken for real Bedrock/Jev output. */
export function RuntimeBanner({ runtime }: { runtime: RuntimeInfo }) {
  const degraded = runtime.warnings.length > 0;
  return (
    <div className={degraded ? styles.warn : styles.live} role="status">
      <strong>{degraded ? 'Demo mode' : 'Live mode'}</strong>
      <dl className={styles.facts}>
        <div>
          <dt>Decisions</dt>
          <dd>{runtime.jev}</dd>
        </div>
        <div>
          <dt>Generator</dt>
          <dd>{runtime.generator}</dd>
        </div>
        <div>
          <dt>Index</dt>
          <dd>{runtime.vector_store}</dd>
        </div>
      </dl>
    </div>
  );
}
