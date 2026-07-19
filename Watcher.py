#!/usr/bin/env python3
"""Generic site configuration inventory watcher.

The watcher scans configured application directories for supported PHP database
configuration files and stores non-secret connection metadata in a MySQL
inventory table. Password values are never persisted.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import mysql.connector
from dotenv import load_dotenv
from mysql.connector import pooling


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / "watcher.env")


def get_log_level() -> int:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    return getattr(logging, level_name, logging.INFO)


logging.basicConfig(
    level=get_log_level(),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("site-config-watcher")


@dataclass(frozen=True)
class Settings:
    db_host: str
    db_port: int
    db_name: str
    db_user: str
    db_password: str
    environment: str
    watch_roots: tuple[Path, ...]
    watch_patterns: tuple[str, ...]
    poll_interval: int
    pool_size: int

    @classmethod
    def from_environment(cls) -> "Settings":
        required = {
            "DB_HOST": os.getenv("DB_HOST"),
            "DB_NAME": os.getenv("DB_NAME"),
            "DB_USER": os.getenv("DB_USER"),
            "DB_PASSWORD": os.getenv("DB_PASSWORD"),
            "DB_ENVIRONMENT": os.getenv("DB_ENVIRONMENT"),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(
                "Missing required environment variables: " + ", ".join(missing)
            )

        roots = tuple(
            Path(item.strip()).expanduser().resolve()
            for item in os.getenv("WATCH_ROOTS", "").split(",")
            if item.strip()
        )
        if not roots:
            raise ValueError("WATCH_ROOTS must contain at least one directory")

        patterns = tuple(
            item.strip()
            for item in os.getenv(
                "WATCH_PATTERNS",
                "init/config.php,config/database.php,app/config/database.php",
            ).split(",")
            if item.strip()
        )

        return cls(
            db_host=required["DB_HOST"] or "",
            db_port=int(os.getenv("DB_PORT", "3306")),
            db_name=required["DB_NAME"] or "",
            db_user=required["DB_USER"] or "",
            db_password=required["DB_PASSWORD"] or "",
            environment=required["DB_ENVIRONMENT"] or "",
            watch_roots=roots,
            watch_patterns=patterns,
            poll_interval=max(5, int(os.getenv("POLL_INTERVAL", "30"))),
            pool_size=max(1, int(os.getenv("DB_POOL_SIZE", "5"))),
        )


@dataclass(frozen=True)
class SiteRecord:
    site: str
    environment: str
    config_path: str
    db_host: str
    db_name: str
    db_user: str
    credential_configured: bool


shutdown_requested = False


def handle_signal(signum: int, _frame: object) -> None:
    global shutdown_requested
    shutdown_requested = True
    logger.info("Shutdown requested by signal %s", signum)


signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)


class InventoryDatabase:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.pool = pooling.MySQLConnectionPool(
            pool_name="site_config_watcher",
            pool_size=settings.pool_size,
            host=settings.db_host,
            port=settings.db_port,
            user=settings.db_user,
            password=settings.db_password,
            database=settings.db_name,
            autocommit=False,
        )

    def connection(self):
        return self.pool.get_connection()

    def initialize_schema(self) -> None:
        connection = self.connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS site_inventory (
                        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                        site VARCHAR(255) NOT NULL,
                        environment VARCHAR(64) NOT NULL,
                        config_path VARCHAR(1024) NOT NULL,
                        db_host VARCHAR(255) DEFAULT NULL,
                        db_name VARCHAR(255) DEFAULT NULL,
                        db_user VARCHAR(255) DEFAULT NULL,
                        credential_configured TINYINT(1) NOT NULL DEFAULT 0,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                            ON UPDATE CURRENT_TIMESTAMP,
                        PRIMARY KEY (id),
                        UNIQUE KEY uq_site_environment (site, environment)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def upsert(self, record: SiteRecord) -> None:
        connection = self.connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO site_inventory (
                        site,
                        environment,
                        config_path,
                        db_host,
                        db_name,
                        db_user,
                        credential_configured
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        config_path = VALUES(config_path),
                        db_host = VALUES(db_host),
                        db_name = VALUES(db_name),
                        db_user = VALUES(db_user),
                        credential_configured = VALUES(credential_configured),
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (
                        record.site,
                        record.environment,
                        record.config_path,
                        record.db_host,
                        record.db_name,
                        record.db_user,
                        int(record.credential_configured),
                    ),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def query(self, site: str | None, environment: str | None) -> list[tuple]:
        conditions: list[str] = []
        values: list[str] = []

        if site:
            conditions.append("site = %s")
            values.append(site)
        if environment:
            conditions.append("environment = %s")
            values.append(environment)

        sql = """
            SELECT
                site,
                environment,
                db_host,
                db_name,
                db_user,
                credential_configured,
                updated_at
            FROM site_inventory
        """
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY environment, site"

        connection = self.connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(sql, tuple(values))
                return cursor.fetchall()
        finally:
            connection.close()


LEGACY_CONFIG_RE = re.compile(
    r"\$config->(?P<key>[A-Za-z0-9_]+)\s*=\s*['\"](?P<value>[^'\"]*)['\"]"
)
ARRAY_CONFIG_RE = re.compile(
    r"['\"](?P<key>[A-Za-z0-9_]+)['\"]\s*=>\s*['\"](?P<value>[^'\"]*)['\"]"
)


def parse_php_config(config_path: Path) -> dict[str, str]:
    text = config_path.read_text(encoding="utf-8", errors="replace")

    legacy_values = {
        match.group("key"): match.group("value")
        for match in LEGACY_CONFIG_RE.finditer(text)
    }
    array_values = {
        match.group("key"): match.group("value")
        for match in ARRAY_CONFIG_RE.finditer(text)
    }

    if legacy_values:
        return {
            "db_host": legacy_values.get("db_host", ""),
            "db_name": legacy_values.get("db_name", ""),
            "db_user": legacy_values.get("db_user", ""),
            "db_password": legacy_values.get("db_pass", ""),
        }

    return {
        "db_host": array_values.get("host", ""),
        "db_name": array_values.get("database", ""),
        "db_user": array_values.get("username", ""),
        "db_password": array_values.get("password", ""),
    }


def discover_sites(settings: Settings) -> Iterable[SiteRecord]:
    for root in settings.watch_roots:
        if not root.is_dir():
            logger.warning("Watch root does not exist or is not a directory: %s", root)
            continue

        for site_directory in sorted(root.iterdir()):
            if not site_directory.is_dir():
                continue

            config_path = next(
                (
                    site_directory / relative_path
                    for relative_path in settings.watch_patterns
                    if (site_directory / relative_path).is_file()
                ),
                None,
            )
            if config_path is None:
                continue

            try:
                config = parse_php_config(config_path)
            except OSError as error:
                logger.error("Unable to read %s: %s", config_path, error)
                continue

            yield SiteRecord(
                site=site_directory.name,
                environment=settings.environment,
                config_path=str(config_path),
                db_host=config.get("db_host", ""),
                db_name=config.get("db_name", ""),
                db_user=config.get("db_user", ""),
                credential_configured=bool(config.get("db_password")),
            )


def run_scan(settings: Settings, database: InventoryDatabase) -> int:
    synced = 0
    for record in discover_sites(settings):
        try:
            database.upsert(record)
            synced += 1
            logger.info(
                "Synced site=%s environment=%s",
                record.site,
                record.environment,
            )
        except mysql.connector.Error as error:
            logger.error("Failed to sync site=%s: %s", record.site, error)
    logger.info("Scan completed. Synced %s site(s)", synced)
    return synced


def run_watch(settings: Settings, database: InventoryDatabase) -> None:
    logger.info(
        "Watcher started for environment=%s roots=%s",
        settings.environment,
        ",".join(str(path) for path in settings.watch_roots),
    )
    while not shutdown_requested:
        run_scan(settings, database)
        for _ in range(settings.poll_interval):
            if shutdown_requested:
                break
            time.sleep(1)
    logger.info("Watcher stopped")


def print_query_results(rows: list[tuple]) -> None:
    if not rows:
        print("No matching records found.")
        return

    headers = (
        "SITE",
        "ENVIRONMENT",
        "DB_HOST",
        "DB_NAME",
        "DB_USER",
        "PASSWORD_SET",
        "UPDATED_AT",
    )
    print("\t".join(headers))
    for row in rows:
        print("\t".join("" if value is None else str(value) for value in row))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan application directories and maintain a MySQL site inventory."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("watch", help="Continuously scan at the configured interval")
    subparsers.add_parser("scan", help="Run one scan and exit")

    query_parser = subparsers.add_parser("query", help="Query inventory records")
    query_parser.add_argument("--site", help="Filter by site name")
    query_parser.add_argument("--environment", help="Filter by environment")

    return parser


def main() -> int:
    args = build_parser().parse_args()

    try:
        settings = Settings.from_environment()
        database = InventoryDatabase(settings)
        database.initialize_schema()
    except (ValueError, mysql.connector.Error) as error:
        logger.critical("Startup failed: %s", error)
        return 1

    if args.command == "watch":
        run_watch(settings, database)
    elif args.command == "scan":
        run_scan(settings, database)
    else:
        rows = database.query(args.site, args.environment)
        print_query_results(rows)

    return 0


if __name__ == "__main__":
    sys.exit(main())
