import { diffStats, parseUnifiedDiff } from './diff';

const DIFF = `--- a/snippet
+++ b/snippet
@@ -1,3 +1,3 @@
 def get_user(cursor, name):
-    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
+    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
     return cursor.fetchone()
`;

describe('parseUnifiedDiff', () => {
  it('tracks old and new line numbers per hunk', () => {
    const lines = parseUnifiedDiff(DIFF);
    const body = lines.filter((l) => l.kind !== 'meta' && l.kind !== 'hunk');
    expect(body.map((l) => [l.kind, l.oldNumber, l.newNumber])).toEqual([
      ['context', 1, 1],
      ['remove', 2, null],
      ['add', null, 2],
      ['context', 3, 3],
    ]);
    expect(body[2]?.text).toContain('%s');
  });

  it('counts additions and removals', () => {
    expect(diffStats(parseUnifiedDiff(DIFF))).toEqual({ added: 1, removed: 1 });
  });

  it('returns no changes for an empty diff', () => {
    expect(diffStats(parseUnifiedDiff(''))).toEqual({ added: 0, removed: 0 });
  });
});
