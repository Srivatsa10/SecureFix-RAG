import { useCallback, useEffect, useRef, useState } from 'react';

export type AsyncState<T> =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; data: T }
  | { status: 'error'; error: Error };

/**
 * Runs an abortable async action. Starting a new run aborts the previous one, and the
 * in-flight request is aborted on unmount, so stale responses can never overwrite state.
 */
export function useAsyncAction<A extends unknown[], T>(
  action: (signal: AbortSignal, ...args: A) => Promise<T>,
) {
  const [state, setState] = useState<AsyncState<T>>({ status: 'idle' });
  const controller = useRef<AbortController | null>(null);

  useEffect(() => () => controller.current?.abort(), []);

  const run = useCallback(
    async (...args: A) => {
      controller.current?.abort();
      const current = new AbortController();
      controller.current = current;
      setState({ status: 'loading' });
      try {
        const data = await action(current.signal, ...args);
        if (!current.signal.aborted) setState({ status: 'success', data });
      } catch (error) {
        if (current.signal.aborted) return;
        setState({
          status: 'error',
          error: error instanceof Error ? error : new Error(String(error)),
        });
      }
    },
    [action],
  );

  const reset = useCallback(() => {
    controller.current?.abort();
    setState({ status: 'idle' });
  }, []);

  return { state, run, reset };
}

/** Load data once on mount (and abort on unmount). */
export function useAsyncResource<T>(load: (signal: AbortSignal) => Promise<T>): AsyncState<T> {
  const { state, run } = useAsyncAction(load);
  useEffect(() => {
    void run();
  }, [run]);
  return state;
}
