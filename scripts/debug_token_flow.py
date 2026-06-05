"""诊断：检查 token_ledger 中当前任务的 token 记录"""
import sys
from pathlib import Path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from src.config import load_config
cfg = load_config()
from sqlalchemy import create_engine, text

tid = "684554a8-83aa-45e5-b0e4-2049b049db24"
engine = create_engine(cfg.postgres.sqlalchemy_url)

with engine.connect() as conn:
    # Check token_ledger
    tokens = conn.execute(text(
        "SELECT source_event_id, llm_input, llm_output, code_agent_input, code_agent_output, note, created_at "
        "FROM token_ledger WHERE task_id = :tid ORDER BY created_at DESC LIMIT 20"
    ), {"tid": tid}).fetchall()
    print(f"TokenLedger rows ({len(tokens)}):")
    for t in tokens:
        print(f"  event={t.source_event_id or '-'} llm_in={t.llm_input} llm_out={t.llm_output} ca_in={t.code_agent_input} ca_out={t.code_agent_output} note={t.note} time={t.created_at}")

    # Check event_records table name
    tables = conn.execute(text(
        "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name LIKE '%event%'"
    )).fetchall()
    print(f"\nEvent tables: {[t[0] for t in tables]}")

    # Check recent events for this task
    for table_name in [t[0] for t in tables]:
        try:
            events = conn.execute(text(
                f"SELECT id, action_type, status, reason FROM {table_name} WHERE task_id = :tid ORDER BY id DESC LIMIT 10"
            ), {"tid": tid}).fetchall()
            if events:
                print(f"\nEvents from {table_name} ({len(events)}):")
                for e in events:
                    print(f"  id={e[0]} [{e[2]}] [{e[1]}] {str(e[3])[:100]}") 
        except Exception as ex:
            print(f"\n{table_name}: {ex}")

    # Check SinkFinder/ChainAnalyzer logs
    logs = conn.execute(text(
        "SELECT level, message FROM logs WHERE task_id = :tid AND message LIKE '%SinkFinder%' OR message LIKE '%Phase 2%' ORDER BY created_at DESC LIMIT 10"
    ), {"tid": tid}).fetchall()
    print(f"\nSinkFinder/ChainAnalyzer logs: {len(logs)}")
    for l in logs:
        print(f"  [{l.level}] {l.message[:150]}")

engine.dispose()
print("\nDone.")
