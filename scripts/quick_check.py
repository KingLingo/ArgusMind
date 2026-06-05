import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.config import load_config
c=load_config()
from sqlalchemy import create_engine, text
e=create_engine(c.postgres.sqlalchemy_url)
with e.connect() as conn:
    conn.execution_options(isolation_level="AUTOCOMMIT")
    # Latest logs
    rows=conn.execute(text("SELECT level, message, created_at FROM logs WHERE task_id='684554a8-83aa-45e5-b0e4-2049b049db24' ORDER BY created_at DESC LIMIT 8")).fetchall()
    for r in reversed(rows):
        print(f"[{r.level}] {r.message[:150]}")
    # Token ledger count
    r=conn.execute(text("SELECT count(1) AS cnt FROM token_ledger WHERE task_id='684554a8-83aa-45e5-b0e4-2049b049db24'")).fetchone()
    print(f"\nTokenLedger count: {r.cnt}")
    # Check if task still running
    r=conn.execute(text("SELECT status, error FROM tasks WHERE id='684554a8-83aa-45e5-b0e4-2049b049db24'")).fetchone()
    print(f"Task status: {r.status}")
    if r.error:
        print(f"  error: {r.error[:200]}")
e.dispose()
print("Done.")
