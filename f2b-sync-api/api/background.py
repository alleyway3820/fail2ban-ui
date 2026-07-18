import asyncio
import logging
import os
from datetime import datetime, timezone

import aiosqlite

from .database import DATABASE_PATH
from .geoip import lookup_country

logger = logging.getLogger(__name__)
F2B_DB_PATH = os.getenv("DB_PATH", "/data/f2b.db")

_bg_task: asyncio.Task | None = None


async def cleanup_expired_whitelist():
    """Remove expired TTL-based whitelist entries."""
    try:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            now = datetime.now(timezone.utc).isoformat()
            async with db.execute(
                "DELETE FROM ip_whitelist WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            ) as cur:
                deleted = cur.rowcount
            if deleted:
                await db.commit()
                logger.info("Cleaned up %s expired whitelist entries", deleted)
    except Exception as e:
        logger.error("Error cleaning up expired whitelist: %s", e)


async def refresh_global_blocklist():
    """Rebuild global_blocklist entries from geo rules and permanent_blocks."""
    logger.info("Refreshing global blocklist from geo rules...")
    try:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row

            # Collect enabled geo-blocked country codes
            async with db.execute(
                "SELECT country_code FROM geo_blocked_countries WHERE enabled = 1"
            ) as cur:
                blocked_countries = {r["country_code"] for r in await cur.fetchall()}

            if not blocked_countries:
                return

            # Find reported IPs in those countries and ensure they're in blocklist
            async with db.execute(
                "SELECT ip_address, country_code FROM ban_reports WHERE country_code IS NOT NULL"
            ) as cur:
                rows = await cur.fetchall()

            for row in rows:
                if row["country_code"] in blocked_countries:
                    await db.execute(
                        """INSERT OR IGNORE INTO global_blocklist
                           (ip_address, reason, country_code, source)
                           VALUES (?, ?, ?, 'geoip')""",
                        (row["ip_address"], f"Geo-blocked country: {row['country_code']}", row["country_code"]),
                    )

            # Sync permanent_blocks from fail2ban-ui if available
            if os.path.exists(F2B_DB_PATH):
                try:
                    async with aiosqlite.connect(F2B_DB_PATH) as f2b:
                        f2b.row_factory = aiosqlite.Row
                        async with f2b.execute(
                            "SELECT ip_address, reason FROM permanent_blocks"
                        ) as cur:
                            pb_rows = await cur.fetchall()
                        for pb in pb_rows:
                            await db.execute(
                                """INSERT OR IGNORE INTO global_blocklist
                                   (ip_address, reason, source)
                                   VALUES (?, ?, 'recurring')""",
                                (pb["ip_address"], pb["reason"]),
                            )
                except Exception as e:
                    logger.debug("Could not read permanent_blocks from f2b.db: %s", e)

            await db.commit()
        logger.info("Global blocklist refresh complete")
    except Exception as e:
        logger.error("Error refreshing global blocklist: %s", e)


async def _background_loop():
    await cleanup_expired_whitelist()
    await refresh_global_blocklist()
    while True:
        await asyncio.sleep(3600)
        await cleanup_expired_whitelist()
        await refresh_global_blocklist()


def start_background_tasks():
    global _bg_task
    _bg_task = asyncio.create_task(_background_loop())
    logger.info("Background task started")


def stop_background_tasks():
    global _bg_task
    if _bg_task and not _bg_task.done():
        _bg_task.cancel()
        logger.info("Background task stopped")
