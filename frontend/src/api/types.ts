// Mirrors the FastAPI response models in backend/remediation_rag/{service,domain,telemetry,costing}.py.
// Keep in sync with GET /openapi.json when the backend contract changes.

export type Language = 'python' | 'javascript' | 'typescript' | 'java';

export const LANGUAGES: readonly Language[] = ['python', 'javascript', 'typescript', 'java'];

export type RemediationStatus = 'shipped' | 'rejected' | 'human_review_required';

export type ScoreDimension = 'groundedness' | 'security_correctness' | 'framework_fit';

export const SCORE_DIMENSIONS: readonly ScoreDimension[] = [
  'groundedness',
  'security_correctness',
  'framework_fit',
];

export interface RemediationRequest {
  code: string;
  language?: Language | null;
  framework?: string | null;
  description?: string | null;
  file_path?: string | null;
}

export interface Citation {
  chunk_id: string;
  reason: string;
}

export interface PatchDraft {
  explanation: string;
  patched_code: string;
  diff: string;
  conventions_applied: string[];
  citations: Citation[];
}

export interface DimensionScore {
  value: number;
  confidence: number;
  level: string;
}

export type EvaluationScores = Record<ScoreDimension, DimensionScore>;

export interface ResolvedCitation {
  chunk_id: string;
  reason: string;
  known: boolean;
  title: string;
  source: string;
  source_path: string;
  language: string;
  framework: string;
  relevance: number | null;
  excerpt: string;
}

export interface TraceEvent {
  node: string;
  attempt: number;
  summary: string;
  data: Record<string, unknown>;
  duration_ms: number;
}

export interface UsageRecord {
  node: string;
  provider: 'bedrock' | 'jev' | 'offline';
  model: string;
  input_tokens: number;
  output_tokens: number;
  latency_ms: number;
  decisions: number;
  mocked: boolean;
}

export interface CostSummary {
  generation_usd: number;
  jev_usd: number;
  total_usd: number;
  jev_calls: number;
  jev_decisions: number;
  jev_input_tokens: number;
  generation_input_tokens: number;
  generation_output_tokens: number;
  llm_judge_decision_usd: number;
  total_with_llm_judge_usd: number;
  decision_cost_ratio: number | null;
  priced_mock_calls: boolean;
}

export interface RuntimeInfo {
  app_mode: string;
  jev: string;
  generator: string;
  vector_store: string;
  embeddings: string;
  warnings: string[];
}

export interface RemediationResult {
  request_id: string;
  status: RemediationStatus;
  requires_human_review: boolean;
  vuln_class: string | null;
  vuln_confidence: number | null;
  intent_probability: number | null;
  rejection_reason: string | null;
  handoff_reason: string | null;
  patch: PatchDraft | null;
  citations: ResolvedCitation[];
  scores: EvaluationScores | null;
  score_threshold: number;
  attempts: number;
  retries: number;
  latency_ms: number;
  trace: TraceEvent[];
  usage: UsageRecord[];
  cost: CostSummary;
  runtime: RuntimeInfo;
}

export interface HealthResponse {
  status: string;
  runtime: RuntimeInfo;
}

export interface ExampleCase {
  id: string;
  title: string;
  code: string;
  language: Language | null;
  framework: string | null;
  description: string | null;
  expected_status: RemediationStatus;
}
