import { useCallback } from 'react';

import { ApiError, api } from './api/client';
import type { RemediationRequest } from './api/types';
import styles from './App.module.css';
import { RemediationForm } from './components/RemediationForm';
import { ResultView } from './components/ResultView';
import { RuntimeBanner } from './components/RuntimeBanner';
import { useAsyncAction, useAsyncResource } from './hooks/useAsync';

const loadBootstrap = async (signal: AbortSignal) => {
  const [health, examples] = await Promise.all([api.health(signal), api.examples(signal)]);
  return { runtime: health.runtime, examples };
};

const remediate = (signal: AbortSignal, request: RemediationRequest) =>
  api.remediate(request, signal);

function describeError(error: Error): string {
  if (error instanceof ApiError && error.requestId) {
    return `${error.message} (request ${error.requestId})`;
  }
  return error.message;
}

export default function App() {
  const bootstrap = useAsyncResource(loadBootstrap);
  const { state: remediation, run, reset } = useAsyncAction(remediate);

  const onSubmit = useCallback((request: RemediationRequest) => void run(request), [run]);

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <div>
          <h1 className={styles.title}>RemediationRAG</h1>
          <p className={styles.tagline}>
            Security patches grounded in approved code and OWASP guidance, and scored before they ship.
          </p>
        </div>
      </header>

      {bootstrap.status === 'loading' || bootstrap.status === 'idle' ? (
        <p className={styles.muted}>Connecting to the backend…</p>
      ) : null}

      {bootstrap.status === 'error' ? (
        <div className={styles.error} role="alert">
          <strong>Backend unavailable.</strong> {describeError(bootstrap.error)}
          <br />
          Start it with <code>make backend</code> and reload.
        </div>
      ) : null}

      {bootstrap.status === 'success' ? (
        <>
          <RuntimeBanner runtime={bootstrap.data.runtime} />
          <main className={styles.grid}>
            <div className={styles.inputColumn}>
              <RemediationForm
                examples={bootstrap.data.examples}
                loading={remediation.status === 'loading'}
                onSubmit={onSubmit}
                onCancel={reset}
              />
            </div>
            <div className={styles.resultColumn}>
              {remediation.status === 'idle' ? (
                <div className={styles.placeholder}>
                  Run a remediation to see the patch, Jev&apos;s scores and the graph&apos;s decision
                  trace.
                </div>
              ) : null}
              {remediation.status === 'loading' ? (
                <div className={styles.placeholder} aria-busy="true">
                  Running intent gate → retrieval → rerank → draft → evaluate…
                </div>
              ) : null}
              {remediation.status === 'error' ? (
                <div className={styles.error} role="alert">
                  <strong>Remediation failed.</strong> {describeError(remediation.error)}
                </div>
              ) : null}
              {remediation.status === 'success' ? <ResultView result={remediation.data} /> : null}
            </div>
          </main>
        </>
      ) : null}
    </div>
  );
}
