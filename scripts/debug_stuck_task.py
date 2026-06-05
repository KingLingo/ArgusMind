"""诊断任务 684554a8 状态"""
import sys
from pathlib import Path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from src.config import load_config
cfg = load_config()
from neo4j import GraphDatabase
from sqlalchemy import create_engine, text

tid = "684554a8-83aa-45e5-b0e4-2049b049db24"

# PostgreSQL
pg_engine = create_engine(cfg.postgres.sqlalchemy_url)
with pg_engine.connect() as conn:
    task = conn.execute(text("SELECT id, status, error FROM tasks WHERE id = :tid"), {"tid": tid}).fetchone()
    print(f"PostgreSQL Task: status={task.status if task else 'NOT FOUND'}")
    if task and task.error:
        print(f"  error={task.error[:300]}")

    interactions = conn.execute(text(
        "SELECT interaction_id, is_confirmed, decided_by, interaction_type, timeout_seconds "
        "FROM human_interactions WHERE task_id = :tid ORDER BY created_at DESC"
    ), {"tid": tid}).fetchall()
    print(f"\nHumanInteractions ({len(interactions)}):")
    for r in interactions:
        print(f"  confirmed={r.is_confirmed} by={r.decided_by} type={r.interaction_type} timeout={r.timeout_seconds}s")

    logs = conn.execute(text(
        "SELECT level, message FROM logs WHERE task_id = :tid ORDER BY created_at DESC LIMIT 15"
    ), {"tid": tid}).fetchall()
    print(f"\nRecent logs ({len(logs)}):")
    for l in reversed(logs):
        print(f"  [{l.level}] {l.message[:150]}")

# Neo4j
driver = GraphDatabase.driver(cfg.neo4j.uri, auth=(cfg.neo4j.user, cfg.neo4j.password))
with driver.session() as s:
    # Plan stage
    plan = s.run(
        "MATCH (s:AuditStage {task_id: $tid, name: 'make a plan'}) RETURN s.status, s.end_time", tid=tid
    ).single()
    print(f"\nNeo4j Plan: {plan['s.status'] if plan else 'NOT FOUND'}" + (f" end={plan.get('s.end_time','-')}" if plan else ""))

    # Languages
    langs = s.run(
        "MATCH (:AuditStage {task_id: $tid, name: 'make a plan'})-[:HAS_LANGUAGE]->(l:Language) "
        "RETURN l.name, l.status", tid=tid
    ).data()
    if langs:
        print(f"Languages: {[(l['l.name'], l['l.status']) for l in langs]}")

    # RiskCategories
    cats = s.run(
        "MATCH (:AuditStage {task_id: $tid})-[:HAS_LANGUAGE]->(:Language)-[:HAS_RISK_CATEGORY]->(c:RiskCategory) "
        "RETURN c.category_name, c.status, c.sink_finder_completed", tid=tid
    ).data()
    if cats:
        print(f"RiskCategories ({len(cats)}): {[(c['c.category_name'], c['c.status']) for c in cats[:5]]}...")

    # SinkFlowNodes count
    sinks = s.run("MATCH (sfn:SinkFlowNode {task_id: $tid}) RETURN count(sfn) AS cnt", tid=tid).single()
    print(f"SinkFlowNodes: {sinks['cnt']}")

    # ChainNodes count
    chains = s.run("MATCH (cn:ChainNode {task_id: $tid}) RETURN count(cn) AS cnt", tid=tid).single()
    print(f"ChainNodes: {chains['cnt']}")

    # Running nodes
    running = s.run(
        "MATCH (n) WHERE coalesce(n.task_id, '') = $tid AND coalesce(n.status, '') = 'running' "
        "RETURN labels(n)[0] AS label, count(n) AS cnt", tid=tid
    ).data()
    if running:
        print(f"\nRunning nodes: {[(r['label'], r['cnt']) for r in running]}")

driver.close()
pg_engine.dispose()
