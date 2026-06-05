"""重置卡住任务的 Neo4j 节点状态"""
import sys
from pathlib import Path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from src.config import load_config
cfg = load_config()
from neo4j import GraphDatabase

tid = "39c9efe3-d941-4181-b97f-686bba7ba57f"

driver = GraphDatabase.driver(cfg.neo4j.uri, auth=(cfg.neo4j.user, cfg.neo4j.password))
with driver.session() as s:
    r = s.run("MATCH (n) WHERE coalesce(n.task_id, '') = $tid AND coalesce(n.status, '') = 'running' SET n.status = 'pending' RETURN count(n) AS cnt", tid=tid).single()
    print(f"Reset running nodes: {r['cnt']}")
    r = s.run("MATCH (c:RiskCategory {task_id: $tid}) SET c.sink_finder_completed = false RETURN count(c) AS cnt", tid=tid).single()
    print(f"Reset RiskCategories: {r['cnt']}")
    langs = s.run("MATCH (:AuditStage {task_id: $tid, name: 'make a plan'})-[:HAS_LANGUAGE]->(l:Language) RETURN l.name, l.status", tid=tid).data()
    for l in langs:
        print(f"  [{l['l.status']}] {l['l.name']}")
driver.close()
print("Done. Task is ready to retry.")
