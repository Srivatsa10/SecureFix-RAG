import type { ExampleCase, RemediationResult, RuntimeInfo } from '../api/types';

export const runtime: RuntimeInfo = {
  app_mode: 'offline',
  jev: 'MOCK (local heuristics, not the real Jev model)',
  generator: 'OFFLINE (rule-based rewrite, no LLM)',
  vector_store: 'in-memory (offline)',
  embeddings: 'OFFLINE (hashed bag-of-words)',
  warnings: ['Jev is mocked: decision scores come from local heuristics.'],
};

export const example: ExampleCase = {
  id: 'py-psycopg-fstring',
  title: 'Python psycopg f-string lookup',
  code: 'cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n',
  language: 'python',
  framework: 'psycopg',
  description: 'Bandit B608',
  expected_status: 'shipped',
};

const score = (value: number) => ({ value, confidence: 0.8, level: 'Strong' });

export const shippedResult: RemediationResult = {
  request_id: 'req123',
  status: 'shipped',
  requires_human_review: false,
  vuln_class: 'sql_injection',
  vuln_confidence: 0.97,
  intent_probability: 0.95,
  rejection_reason: null,
  handoff_reason: null,
  patch: {
    explanation: 'Bind the value as a parameter.',
    patched_code: 'cursor.execute("SELECT * FROM users WHERE name = %s", (name,))\n',
    diff: '--- a/snippet\n+++ b/snippet\n@@ -1 +1 @@\n-cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n+cursor.execute("SELECT * FROM users WHERE name = %s", (name,))\n',
    conventions_applied: ['psycopg parameterized query'],
    citations: [{ chunk_id: 'internal:python/psycopg_repository.py#0', reason: 'placeholder style' }],
  },
  citations: [
    {
      chunk_id: 'internal:python/psycopg_repository.py#0',
      reason: 'placeholder style',
      known: true,
      title: 'psycopg parameterized repository functions',
      source: 'internal',
      source_path: 'python/psycopg_repository.py',
      language: 'python',
      framework: 'psycopg',
      relevance: 0.96,
      excerpt: 'cur.execute("SELECT ... WHERE email = %s", (email,))',
    },
  ],
  scores: { groundedness: score(0.99), security_correctness: score(0.9), framework_fit: score(0.8) },
  score_threshold: 0.85,
  attempts: 1,
  retries: 0,
  latency_ms: 12,
  trace: [
    { node: 'intent_gate', attempt: 0, summary: 'in_scope p=0.95', data: {}, duration_ms: 0.5 },
    { node: 'finalize', attempt: 0, summary: 'shipping patch', data: {}, duration_ms: 0 },
  ],
  usage: [],
  cost: {
    generation_usd: 0.02,
    jev_usd: 0.0003,
    total_usd: 0.0203,
    jev_calls: 3,
    jev_decisions: 13,
    jev_input_tokens: 7000,
    generation_input_tokens: 1300,
    generation_output_tokens: 250,
    llm_judge_decision_usd: 0.02,
    total_with_llm_judge_usd: 0.04,
    decision_cost_ratio: 66,
    priced_mock_calls: true,
  },
  runtime,
};
