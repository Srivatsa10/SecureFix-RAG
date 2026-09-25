import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import App from './App';
import { api } from './api/client';
import { example, runtime, shippedResult } from './test/fixtures';

vi.mock('./api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./api/client')>();
  return { ...actual, api: { health: vi.fn(), examples: vi.fn(), remediate: vi.fn() } };
});

const mocked = vi.mocked(api);

beforeEach(() => {
  mocked.health.mockResolvedValue({ status: 'ok', runtime });
  mocked.examples.mockResolvedValue([example]);
  mocked.remediate.mockResolvedValue(shippedResult);
});

afterEach(() => {
  vi.clearAllMocks();
});

describe('App', () => {
  it('shows the demo-mode banner so mocked results are never mistaken for real ones', async () => {
    render(<App />);
    expect(await screen.findByText('Demo mode')).toBeInTheDocument();
    expect(screen.getByText(runtime.jev)).toBeInTheDocument();
  });

  it('submits the selected example and renders the shipped patch, scores and trace', async () => {
    const user = userEvent.setup();
    render(<App />);

    const submit = await screen.findByRole('button', { name: 'Generate patch' });
    await user.click(submit);

    expect(mocked.remediate).toHaveBeenCalledWith(
      { code: example.code, language: 'python', framework: 'psycopg', description: 'Bandit B608' },
      expect.any(AbortSignal),
    );
    expect(await screen.findByText('Patch shipped')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Jev evaluation' })).toBeInTheDocument();
    expect(screen.getByText('intent_gate')).toBeInTheDocument();
    expect(screen.getByText(/66× cheaper/)).toBeInTheDocument();
  });

  it('shows a helpful error when the backend is down', async () => {
    mocked.health.mockRejectedValue(new Error('Could not reach the backend. Is it running?'));
    render(<App />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Backend unavailable');
  });
});

describe('DecisionTrace labels', () => {
  it('labels mocked Jev and offline generation honestly', async () => {
    const { DecisionTrace } = await import('./components/DecisionTrace');
    render(
      <DecisionTrace
        trace={[
          { node: 'intent_gate', attempt: 0, summary: 's', data: {}, duration_ms: 1 },
          { node: 'draft_patch', attempt: 0, summary: 's', data: {}, duration_ms: 1 },
        ]}
        usage={[
          { node: 'intent_gate', provider: 'jev', model: 'm', input_tokens: 1, output_tokens: 0, latency_ms: 1, decisions: 2, mocked: true },
          { node: 'draft_patch', provider: 'offline', model: 'm', input_tokens: 1, output_tokens: 1, latency_ms: 1, decisions: 0, mocked: true },
        ]}
      />,
    );
    expect(screen.getByText('Jev (mock)')).toBeInTheDocument();
    expect(screen.getByText('Offline generator')).toBeInTheDocument();
  });
});
