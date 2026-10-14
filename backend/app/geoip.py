"""GeoIP enrichment: MaxMind GeoLite2 when a license key is set, otherwise the
keyless DB-IP free lite databases (same MaxMind mmdb format, geoip2-compatible).

Downloads are streamed; tar.gz archives (MaxMind) and .mmdb.gz files (DB-IP)
are both handled. Missing databases simply produce empty GeoInfo values until
the download job succeeds — enrichment never raises into the ingest path.
"""

from __future__ import annotations

import gzip
import ipaddress
import logging
import shutil
import tarfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

import geoip2.database
import httpx
from geoip2.errors import AddressNotFoundError, GeoIP2Error

logger = logging.getLogger(__name__)

_CITY_EDITION = "GeoLite2-City"
_ASN_EDITION = "GeoLite2-ASN"
_DOWNLOAD_URL = "https://download.maxmind.com/app/geoip_download"
_DBIP_URL = "https://download.db-ip.com/free"
_CHUNK_BYTES = 1 << 16
_DOWNLOAD_TIMEOUT = httpx.Timeout(120.0)


@dataclass(slots=True)
class GeoInfo:
    country: str | None = None
    city: str | None = None
    asn: str | None = None
    lat: float | None = None
    lon: float | None = None


class GeoEnricher:
    """Lazily opened geoip2 readers plus a streaming GeoLite2 downloader."""

    def __init__(self, geoip_dir: str, license_key: str = "", enabled: bool = True) -> None:
        self.geoip_dir = Path(geoip_dir)
        self.license_key = license_key
        self._enabled = enabled
        self.provider = "maxmind" if license_key else "dbip"
        self._city_reader: geoip2.database.Reader | None = None
        self._asn_reader: geoip2.database.Reader | None = None
        self._download_lock = None  # created lazily inside the running loop
        self.download_failed = False

    @property
    def enabled(self) -> bool:
        # GeoIP enrichment runs when OBS_GEOIP_ENABLED is true (default): a
        # MaxMind key selects the premium source, anything else falls back to
        # the keyless DB-IP lite databases. Tests set it false so they never
        # download the 130MB+ databases.
        return self._enabled

    def _city_file(self) -> Path:
        name = f"{_CITY_EDITION}.mmdb" if self.provider == "maxmind" else "DBIP-city-lite.mmdb"
        return self.geoip_dir / name

    def _asn_file(self) -> Path:
        name = f"{_ASN_EDITION}.mmdb" if self.provider == "maxmind" else "DBIP-asn-lite.mmdb"
        return self.geoip_dir / name

    def is_ready(self) -> bool:
        return self._city_file().is_file() and self._asn_file().is_file()

    def _ensure_readers(self) -> None:
        if not self.is_ready():
            return
        if self._city_reader is None:
            self._city_reader = geoip2.database.Reader(str(self._city_file()))
        if self._asn_reader is None:
            self._asn_reader = geoip2.database.Reader(str(self._asn_file()))

    def enrich(self, ip: str | None) -> GeoInfo:
        """Look up geo data for a public IP; anything else yields empty GeoInfo."""
        if not ip or not self.enabled:
            return GeoInfo()
        try:
            if not ipaddress.ip_address(ip).is_global:
                return GeoInfo()
        except ValueError:
            return GeoInfo()
        if not self.is_ready():
            return GeoInfo()
        try:
            self._ensure_readers()
        except (GeoIP2Error, OSError, ValueError) as exc:
            logger.warning("geoip readers unavailable: %s", exc)
            return GeoInfo()
        info = GeoInfo()
        if self._city_reader is not None:
            record = None
            try:
                record = self._city_reader.city(ip)
            except AddressNotFoundError:
                record = None
            except (GeoIP2Error, ValueError, OSError):
                logger.debug("city lookup failed for %s", ip, exc_info=True)
            if record is not None:
                info.country = record.country.iso_code
                info.city = record.city.name
                if record.location.latitude is not None:
                    info.lat = float(record.location.latitude)
                if record.location.longitude is not None:
                    info.lon = float(record.location.longitude)
        if self._asn_reader is not None:
            asn_record = None
            try:
                asn_record = self._asn_reader.asn(ip)
            except AddressNotFoundError:
                asn_record = None
            except (GeoIP2Error, ValueError, OSError):
                logger.debug("asn lookup failed for %s", ip, exc_info=True)
            if asn_record is not None:
                organization = asn_record.autonomous_system_organization or ""
                info.asn = f"AS{asn_record.autonomous_system_number} {organization}".strip()
        return info

    async def ensure_databases(self, force: bool = False) -> bool:
        """Download missing (or force-refresh) geo databases for the provider."""
        if not self.enabled:
            return False
        if not force and self.is_ready():
            return True
        import asyncio

        if self._download_lock is None:
            self._download_lock = asyncio.Lock()
        async with self._download_lock:
            if not force and self.is_ready():
                return True
            self.geoip_dir.mkdir(parents=True, exist_ok=True)
            ok = True
            for target in (self._city_file(), self._asn_file()):
                if not force and target.is_file():
                    continue
                try:
                    if self.provider == "maxmind":
                        edition = _CITY_EDITION if "City" in target.name else _ASN_EDITION
                        await self._download_maxmind(edition, target)
                    else:
                        kind = "dbip-city" if "city" in target.name else "dbip-asn"
                        await self._download_dbip(kind, target)
                except Exception as exc:  # noqa: BLE001 - a failed download must not kill the job
                    ok = False
                    logger.error("geoip download failed for %s: %s", target.name, exc)
            # Reopen readers so a refreshed file replaces the cached handle.
            self.close()
            ready = ok and self.is_ready()
            self.download_failed = not ready
            return ready

    async def _download_maxmind(self, edition: str, target: Path) -> None:
        params = urlencode({"edition_id": edition, "license_key": self.license_key, "suffix": "tar.gz"})
        archive = Path(f"{target}.tar.gz")
        try:
            async with httpx.AsyncClient(timeout=_DOWNLOAD_TIMEOUT, follow_redirects=True) as client:
                async with client.stream("GET", f"{_DOWNLOAD_URL}?{params}") as response:
                    response.raise_for_status()
                    with archive.open("wb") as fh:
                        async for chunk in response.aiter_bytes(_CHUNK_BYTES):
                            fh.write(chunk)
            self._extract_mmdb(archive, target)
        finally:
            archive.unlink(missing_ok=True)

    async def _download_dbip(self, kind: str, target: Path) -> None:
        """Fetch the free DB-IP lite monthly .mmdb.gz (current month, else last)."""
        now = datetime.now(timezone.utc)
        months = [now.strftime("%Y-%m"), (now - timedelta(days=14)).strftime("%Y-%m")]
        archive = Path(f"{target}.gz")
        try:
            async with httpx.AsyncClient(timeout=_DOWNLOAD_TIMEOUT, follow_redirects=True) as client:
                for month in months:
                    url = f"{_DBIP_URL}/{kind}-lite-{month}.mmdb.gz"
                    try:
                        async with client.stream("GET", url) as response:
                            if response.status_code == 404:
                                logger.info("dbip release %s not published yet, trying previous", month)
                                continue
                            response.raise_for_status()
                            with archive.open("wb") as fh:
                                async for chunk in response.aiter_bytes(_CHUNK_BYTES):
                                    fh.write(chunk)
                        break
                    except httpx.HTTPStatusError:
                        raise
                else:
                    raise ValueError(f"no dbip release found for {kind}")
            with gzip.open(archive, "rb") as src, target.open("wb") as out:
                shutil.copyfileobj(src, out, _CHUNK_BYTES)
        finally:
            archive.unlink(missing_ok=True)

    @staticmethod
    def _extract_mmdb(archive: Path, target: Path) -> None:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar.getmembers():
                if not member.isfile() or not member.name.endswith(".mmdb"):
                    continue
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                with target.open("wb") as out:
                    shutil.copyfileobj(extracted, out, _CHUNK_BYTES)
                return
        raise ValueError(f"no .mmdb member found in {archive.name}")

    def close(self) -> None:
        for reader in (self._city_reader, self._asn_reader):
            if reader is not None:
                try:
                    reader.close()
                except Exception:  # noqa: BLE001 - closing a broken reader must not raise
                    logger.debug("failed to close geoip reader", exc_info=True)
        self._city_reader = None
        self._asn_reader = None
