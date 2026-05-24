import argparse
import os
import sqlite3
from typing import Iterable


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(str(row[1]) == column for row in rows)


def _index_exists(conn: sqlite3.Connection, index_name: str) -> bool:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND name=?", (index_name,)).fetchall()
    return bool(rows)


def _exec_many(conn: sqlite3.Connection, statements: Iterable[str], dry_run: bool) -> None:
    for sql in statements:
        if dry_run:
            print(f"[DRY-RUN] {sql}")
            continue
        conn.execute(sql)


def migrate_sqlite(db_path: str, dry_run: bool) -> None:
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"SQLite db file not found: {db_path}")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=OFF")

        # users.updated_at
        if not _column_exists(conn, "users", "updated_at"):
            _exec_many(conn, [
                "ALTER TABLE users ADD COLUMN updated_at DATETIME"
            ], dry_run)

        # users.email unique index (allow multiple NULL values)
        dup_rows = conn.execute(
            """
            SELECT email, COUNT(*) AS cnt
            FROM users
            WHERE email IS NOT NULL AND TRIM(email) <> ''
            GROUP BY email
            HAVING COUNT(*) > 1
            LIMIT 5
            """
        ).fetchall()
        if dup_rows:
            sample = ", ".join([f"{r['email']}({r['cnt']})" for r in dup_rows])
            raise RuntimeError(f"Cannot add unique index on users.email due to duplicates: {sample}")

        if not _index_exists(conn, "uq_users_email"):
            _exec_many(conn, [
                "CREATE UNIQUE INDEX uq_users_email ON users(email)"
            ], dry_run)

        # app_devices lifecycle columns
        if not _column_exists(conn, "app_devices", "is_revoked"):
            _exec_many(conn, [
                "ALTER TABLE app_devices ADD COLUMN is_revoked BOOLEAN NOT NULL DEFAULT 0"
            ], dry_run)
        if not _column_exists(conn, "app_devices", "revoked_at"):
            _exec_many(conn, [
                "ALTER TABLE app_devices ADD COLUMN revoked_at DATETIME"
            ], dry_run)
        if not _column_exists(conn, "app_devices", "revoke_reason"):
            _exec_many(conn, [
                "ALTER TABLE app_devices ADD COLUMN revoke_reason VARCHAR(255)"
            ], dry_run)
        if not _column_exists(conn, "app_devices", "expires_at"):
            _exec_many(conn, [
                "ALTER TABLE app_devices ADD COLUMN expires_at DATETIME"
            ], dry_run)

        if not _index_exists(conn, "ix_app_devices_is_revoked"):
            _exec_many(conn, [
                "CREATE INDEX ix_app_devices_is_revoked ON app_devices(is_revoked)"
            ], dry_run)
        if not _index_exists(conn, "ix_app_devices_expires_at"):
            _exec_many(conn, [
                "CREATE INDEX ix_app_devices_expires_at ON app_devices(expires_at)"
            ], dry_run)

        # webhook_configs.creator_id foreign key: recreate table on SQLite
        fk_rows = conn.execute("PRAGMA foreign_key_list(webhook_configs)").fetchall()
        has_creator_fk = any(r[3] == "creator_id" and r[2] == "users" for r in fk_rows)

        if not has_creator_fk:
            recreate_sql = [
                """
                CREATE TABLE webhook_configs_new (
                    id INTEGER NOT NULL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    url VARCHAR(500) NOT NULL,
                    secret VARCHAR(255),
                    events TEXT NOT NULL,
                    is_active BOOLEAN,
                    creator_id INTEGER NOT NULL,
                    created_at DATETIME,
                    FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """,
                """
                INSERT INTO webhook_configs_new (id, name, url, secret, events, is_active, creator_id, created_at)
                SELECT id, name, url, secret, events, is_active, creator_id, created_at
                FROM webhook_configs
                """,
                "DROP TABLE webhook_configs",
                "ALTER TABLE webhook_configs_new RENAME TO webhook_configs",
            ]
            _exec_many(conn, recreate_sql, dry_run)

            # recreate indexes expected by ORM
            if not _index_exists(conn, "ix_webhook_configs_id"):
                _exec_many(conn, ["CREATE INDEX ix_webhook_configs_id ON webhook_configs(id)"], dry_run)
            if not _index_exists(conn, "ix_webhook_configs_creator_id"):
                _exec_many(conn, ["CREATE INDEX ix_webhook_configs_creator_id ON webhook_configs(creator_id)"], dry_run)

        if dry_run:
            print("[DRY-RUN] Migration planned successfully. No data changed.")
            conn.rollback()
        else:
            conn.commit()
            print("Migration completed successfully.")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="OnAuth schema hardening migration (2026-05-24)")
    parser.add_argument("--db", default=os.path.join(os.path.dirname(__file__), "..", "apps.db"), help="Path to SQLite db")
    parser.add_argument("--dry-run", action="store_true", help="Preview SQL without applying")
    args = parser.parse_args()

    db_path = os.path.abspath(args.db)
    migrate_sqlite(db_path=db_path, dry_run=args.dry_run)


if __name__ == "__main__":
    main()

