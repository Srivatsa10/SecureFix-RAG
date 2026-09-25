import { useId, useState, type KeyboardEvent, type SyntheticEvent } from 'react';

import { LANGUAGES, type ExampleCase, type Language, type RemediationRequest } from '../api/types';
import { Card } from './Card';
import styles from './RemediationForm.module.css';

const MAX_CODE_CHARS = 20_000;

interface FormValues {
  code: string;
  language: Language | '';
  framework: string;
  description: string;
}

const EMPTY: FormValues = { code: '', language: '', framework: '', description: '' };

function fromExample(example: ExampleCase): FormValues {
  return {
    code: example.code,
    language: example.language ?? '',
    framework: example.framework ?? '',
    description: example.description ?? '',
  };
}

function toRequest(values: FormValues): RemediationRequest {
  return {
    code: values.code,
    language: values.language || null,
    framework: values.framework.trim() || null,
    description: values.description.trim() || null,
  };
}

interface RemediationFormProps {
  examples: ExampleCase[];
  loading: boolean;
  onSubmit: (request: RemediationRequest) => void;
  onCancel: () => void;
}

export function RemediationForm({ examples, loading, onSubmit, onCancel }: RemediationFormProps) {
  const [values, setValues] = useState<FormValues>(() =>
    examples[0] ? fromExample(examples[0]) : EMPTY,
  );
  const [exampleId, setExampleId] = useState(examples[0]?.id ?? '');
  const ids = { example: useId(), language: useId(), framework: useId(), description: useId(), code: useId() };

  const tooLong = values.code.length > MAX_CODE_CHARS;
  const canSubmit = values.code.trim().length > 0 && !tooLong && !loading;

  const update = <K extends keyof FormValues>(key: K, value: FormValues[K]) => {
    setValues((prev) => ({ ...prev, [key]: value }));
  };

  const loadExample = (id: string) => {
    setExampleId(id);
    const example = examples.find((e) => e.id === id);
    setValues(example ? fromExample(example) : EMPTY);
  };

  const submit = (event?: SyntheticEvent) => {
    event?.preventDefault();
    if (canSubmit) onSubmit(toRequest(values));
  };

  const onCodeKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) submit();
  };

  return (
    <Card title="Vulnerable code" subtitle="Paste a finding from your scanner, or start from an example.">
      <form className={styles.form} onSubmit={submit} noValidate>
        <div className={styles.field}>
          <label htmlFor={ids.example}>Example</label>
          <select id={ids.example} value={exampleId} onChange={(e) => { loadExample(e.target.value); }}>
            <option value="">Blank</option>
            {examples.map((example) => (
              <option key={example.id} value={example.id}>
                {example.title}
              </option>
            ))}
          </select>
        </div>

        <div className={styles.row}>
          <div className={styles.field}>
            <label htmlFor={ids.language}>Language</label>
            <select
              id={ids.language}
              value={values.language}
              onChange={(e) => { update('language', e.target.value as Language | ''); }}
            >
              <option value="">Auto / unknown</option>
              {LANGUAGES.map((lang) => (
                <option key={lang} value={lang}>
                  {lang}
                </option>
              ))}
            </select>
          </div>
          <div className={styles.field}>
            <label htmlFor={ids.framework}>Framework / driver</label>
            <input
              id={ids.framework}
              value={values.framework}
              placeholder="e.g. psycopg, pg, jdbc"
              maxLength={64}
              onChange={(e) => { update('framework', e.target.value); }}
            />
          </div>
        </div>

        <div className={styles.field}>
          <label htmlFor={ids.description}>Finding (optional)</label>
          <input
            id={ids.description}
            value={values.description}
            placeholder="Scanner rule or context"
            maxLength={2000}
            onChange={(e) => { update('description', e.target.value); }}
          />
        </div>

        <div className={styles.field}>
          <label htmlFor={ids.code}>Code</label>
          <textarea
            id={ids.code}
            className={`mono ${styles.code}`}
            value={values.code}
            spellCheck={false}
            wrap="off"
            aria-invalid={tooLong}
            aria-describedby={`${ids.code}-help`}
            onChange={(e) => { update('code', e.target.value); }}
            onKeyDown={onCodeKeyDown}
          />
          <span id={`${ids.code}-help`} className={tooLong ? styles.error : styles.help}>
            {values.code.length.toLocaleString()} / {MAX_CODE_CHARS.toLocaleString()} characters
            {tooLong ? ' - too long' : ' · ⌘/Ctrl + Enter to run'}
          </span>
        </div>

        <div className={styles.actions}>
          {loading ? (
            <button type="button" className={styles.secondary} onClick={onCancel}>
              Cancel
            </button>
          ) : null}
          <button type="submit" className={styles.primary} disabled={!canSubmit}>
            {loading ? 'Remediating…' : 'Generate patch'}
          </button>
        </div>
      </form>
    </Card>
  );
}
