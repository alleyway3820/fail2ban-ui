import asyncio
import os
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "/data/GeoLite2-Country.mmdb")
_cache: dict[str, tuple[Optional[str], float]] = {}
CACHE_TTL = 3600


def lookup_country(ip: str) -> Optional[str]:
    now = time.time()
    if ip in _cache:
        result, ts = _cache[ip]
        if now - ts < CACHE_TTL:
            return result

    try:
        import maxminddb
        if not os.path.exists(GEOIP_DB_PATH):
            return None
        with maxminddb.open_database(GEOIP_DB_PATH) as reader:
            record = reader.get(ip)
            if record and "country" in record:
                code = record["country"].get("iso_code")
                _cache[ip] = (code, now)
                return code
            _cache[ip] = (None, now)
            return None
    except Exception as e:
        logger.warning("GeoIP lookup failed for %s: %s", ip, e)
        _cache[ip] = (None, now)
        return None


async def async_lookup_country(ip: str) -> Optional[str]:
    return await asyncio.to_thread(lookup_country, ip)
