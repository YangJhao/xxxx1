"""
数据库迁移脚本
给旧数据库加上新版本的列
"""
from panel.models import engine
from sqlalchemy import text

ALTER_LINES = [
    ("http_port", "INTEGER"),
    ("ss_port", "INTEGER"),
]

ALTER_PROXY = [
    ("ss_password", "TEXT"),
    ("protocol", "TEXT DEFAULT 'socks5'"),
    ("ss_method", "TEXT"),
]

with engine.connect() as conn:
    print("迁移 proxy_users 表...")
    for col_name, col_type in ALTER_PROXY:
        try:
            conn.execute(text(f"ALTER TABLE proxy_users ADD COLUMN {col_name} {col_type}"))
            print(f"  + proxy_users.{col_name}")
        except Exception as e:
            msg = str(e).lower()
            if "duplicate" in msg or "already" in msg:
                print(f"  = proxy_users.{col_name} (已存在)")
            else:
                print(f"  ! proxy_users.{col_name}: {e}")

    print("迁移 lines 表...")
    for col_name, col_type in ALTER_LINES:
        try:
            conn.execute(text(f"ALTER TABLE lines ADD COLUMN {col_name} {col_type}"))
            print(f"  + lines.{col_name}")
        except Exception as e:
            msg = str(e).lower()
            if "duplicate" in msg or "already" in msg:
                print(f"  = lines.{col_name} (已存在)")
            else:
                print(f"  ! lines.{col_name}: {e}")

print("迁移完成！")
