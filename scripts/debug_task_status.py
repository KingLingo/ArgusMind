"""诊断任务卡住原因 v2"""
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
    # 1. Plan stage
    plan = s.run(
        "MATCH (s:AuditStage {task_id: $tid, name: 'make a plan'}) RETURN s.status, s.node_id, s.end_time",
        tid=tid
    ).single()
    if plan:
        print(f"Plan: status={plan['s.status']} node_id={plan['s.node_id'][:30]}... end_time={plan.get('s.end_time', '-')}")

        # 2. Languages
        langs = s.run(
            "MATCH (:AuditStage {task_id: $tid, name: 'make a plan'})-[:HAS_LANGUAGE]->(l:Language) "
            "RETURN l.name, l.status, l.node_id",
            tid=tid
        ).data()
        print(f"Languages ({len(langs)}):")
        for l in langs:
            print(f"  [{l['l.status']}] {l['l.name']}")

        # 3. RiskCategories + SinkFinder status
        cats = s.run(
            "MATCH (:AuditStage {task_id: $tid, name: 'make a plan'})-[:HAS_LANGUAGE]->(l:Language)-[:HAS_RISK_CATEGORY]->(c:RiskCategory) "
            "RETURN l.name AS lang, c.category_name, c.status, c.sink_finder_completed",
            tid=tid
        ).data()
        print(f"RiskCategories ({len(cats)}):")
        for c in cats:
            sf = c.get('c.sink_finder_completed', False)
            print(f"  [{c['c.status']}] {c['lang']} :: {c['c.category_name']} (sink_finder_done={sf})")

        # 4. SinkFlowNodes (evidence of LLM audit)
        sinks = s.run(
            "MATCH (sfn:SinkFlowNode {task_id: $tid}) RETURN count(sfn) AS cnt",
            tid=tid
        ).single()
        print(f"\nSinkFlowNodes: {sinks['cnt']}")

        # 5. ChainNodes
        chains = s.run(
            "MATCH (cn:ChainNode {task_id: $tid}) RETURN count(cn) AS cnt",
            tid=tid
        ).single()
        print(f"ChainNodes: {chains['cnt']}")

        # 6. AnalysisResults
        ars = s.run(
            "MATCH (ar:AnalysisResult {task_id: $tid}) RETURN count(ar) AS cnt",
            tid=tid
        ).single()
        print(f"AnalysisResults: {ars['cnt']}")

        # 7. Running nodes
        running = s.run(
            "MATCH (n) WHERE coalesce(n.task_id, '') = $tid AND coalesce(n.status, '') = 'running' "
            "RETURN labels(n)[0] AS label, n.status, count(n) AS cnt, n.node_id",
            tid=tid
        ).data()
        print(f"\nRunning nodes:")
        for r in running:
            print(f"  {r['label']}: {r['cnt']}")

    else:
        print("NO PLAN FOUND")

driver.close()
print("\nDone.")
