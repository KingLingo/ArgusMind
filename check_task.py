import sys
sys.path.insert(0, r'E:\code\ArgusMind')
from src.infrastructure.db import session_scope, init_engine
from src.config import load_config
from sqlalchemy import text

c = load_config()
init_engine(c.postgres)

tid = '75bc0c20-bf3f-4f86-a1e1-f664b0b14557'

with session_scope() as s:
    t = s.execute(text(
        'SELECT status, created_at, finished_at, error FROM tasks WHERE id=:tid'
    ), {'tid': tid}).fetchone()
    print(f'Status: {t[0]}')
    print(f'Created: {t[1]}')
    print(f'Finished: {t[2]}')
    print(f'Error: {t[3] or "(none)"}')

    rows = s.execute(text(
        'SELECT status, COUNT(*) FROM events WHERE task_id=:tid GROUP BY status'
    ), {'tid': tid}).fetchall()
    print(f'Events: {dict((r[0], r[1]) for r in rows)}')

    tl = s.execute(text(
        'SELECT COUNT(*),COALESCE(SUM(llm_input),0),COALESCE(SUM(llm_output),0) '
        'FROM token_ledger WHERE task_id=:tid'
    ), {'tid': tid}).fetchone()
    print(f'Token: rows={tl[0]} in={tl[1]} out={tl[2]} total={tl[1]+tl[2]}')

    evs = s.execute(text(
        'SELECT module, action_type, reason, status, '
        'COALESCE(EXTRACT(EPOCH FROM (finished_at-started_at))::int, -1) AS dur '
        'FROM events WHERE task_id=:tid ORDER BY started_at DESC LIMIT 15'
    ), {'tid': tid}).fetchall()
    print('\nRecent events:')
    for e in evs:
        print(f'  {e[0]}/{e[1]} [{e[3]}, dur={e[4]}s] {str(e[2])[:150]}')
