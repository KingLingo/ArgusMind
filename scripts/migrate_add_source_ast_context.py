# -*- coding: utf-8 -*-
"""迁移脚本：为 vulnerability 和 vulnerability_details 表添加新列。"""
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from src.config import load_config

cfg = load_config()
url = cfg.postgres.sqlalchemy_url

from sqlalchemy import create_engine, text

engine = create_engine(url)

with engine.connect() as conn:
    # 1. vulnerability 表新增 source 列
    try:
        conn.execute(text(
            "ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS "
            "source VARCHAR(32) DEFAULT 'quick_scan' NOT NULL"
        ))
        conn.commit()
        print('[OK] vulnerability.source')
    except Exception as e:
        print(f'[SKIP] vulnerability.source: {e}')

    # 2. vulnerability_details 表新增 ast_context 列
    try:
        conn.execute(text(
            "ALTER TABLE vulnerability_details "
            "ADD COLUMN IF NOT EXISTS ast_context JSONB"
        ))
        conn.commit()
        print('[OK] vulnerability_details.ast_context')
    except Exception as e:
        print(f'[SKIP] vulnerability_details.ast_context: {e}')

print('[DONE] Migration complete')
