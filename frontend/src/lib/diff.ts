export type DiffLineKind = 'add' | 'remove' | 'context' | 'hunk' | 'meta';

export interface DiffLine {
  kind: DiffLineKind;
  text: string;
  oldNumber: number | null;
  newNumber: number | null;
}

const HUNK_HEADER = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/;

/** Parse a unified diff into renderable lines with old/new line numbers. */
export function parseUnifiedDiff(diff: string): DiffLine[] {
  const lines: DiffLine[] = [];
  let oldLine = 0;
  let newLine = 0;

  for (const raw of diff.replace(/\n$/, '').split('\n')) {
    if (raw.startsWith('--- ') || raw.startsWith('+++ ')) {
      lines.push({ kind: 'meta', text: raw, oldNumber: null, newNumber: null });
      continue;
    }
    const hunk = HUNK_HEADER.exec(raw);
    if (hunk) {
      oldLine = Number(hunk[1]);
      newLine = Number(hunk[2]);
      lines.push({ kind: 'hunk', text: raw, oldNumber: null, newNumber: null });
      continue;
    }
    if (raw.startsWith('+')) {
      lines.push({ kind: 'add', text: raw.slice(1), oldNumber: null, newNumber: newLine++ });
    } else if (raw.startsWith('-')) {
      lines.push({ kind: 'remove', text: raw.slice(1), oldNumber: oldLine++, newNumber: null });
    } else if (raw.startsWith('\\')) {
      lines.push({ kind: 'meta', text: raw, oldNumber: null, newNumber: null });
    } else {
      lines.push({
        kind: 'context',
        text: raw.startsWith(' ') ? raw.slice(1) : raw,
        oldNumber: oldLine++,
        newNumber: newLine++,
      });
    }
  }
  return lines;
}

export function diffStats(lines: DiffLine[]): { added: number; removed: number } {
  return {
    added: lines.filter((l) => l.kind === 'add').length,
    removed: lines.filter((l) => l.kind === 'remove').length,
  };
}
