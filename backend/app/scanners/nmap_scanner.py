"""Safe Nmap integration.

Nmap is invoked via ``subprocess.Popen`` with an explicit argument array —
never a shell string — so target input cannot inject commands. Scans use the
standard TCP connect scan (no stealth/evasion flags), include a hard timeout,
cap XML output size, and clean up the process group on timeout.

If the nmap binary is unavailable the scan engine falls back to the built-in
TCP connect scanner, and the chosen engine is recorded transparently.
"""

import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from app.config import Settings
from app.scanners.base import HostData
from app.scanners.nmap_parser import parse_nmap_xml
from app.utils.errors import ScannerUnavailableError, ValidationFailedError
from app.utils.validation import validate_port_range, validate_target_address

logger = logging.getLogger(__name__)

MAX_XML_BYTES = 20 * 1024 * 1024  # 20 MB cap on nmap XML output


class NmapScanner:
    """Runs nmap against an authorized target and parses the XML output."""

    ENGINE_NAME = "nmap"

    def __init__(self, settings: Settings):
        self._settings = settings
        self.binary = self._locate_binary(settings.NMAP_BIN_PATH)

    @staticmethod
    def _locate_binary(configured: str) -> Optional[str]:
        if configured and configured != "nmap":
            path = shutil.which(configured)
            if path:
                return path
            if Path(configured).is_file():
                return configured
            return None
        return shutil.which("nmap")

    def available(self) -> bool:
        return self.binary is not None

    def scan(
        self,
        target: str,
        port_range: str = "top-1000",
        timeout_seconds: Optional[int] = None,
    ) -> list[HostData]:
        """Run nmap and return parsed hosts.

        Only benign, non-evasive arguments are used:
        ``-sT`` (TCP connect), ``-sV`` (version detection), ``-Pn`` (treat
        host as up — required for localhost), ``-oX`` (XML to a temp file).
        """
        if not self.available():
            raise ScannerUnavailableError(
                "nmap binary not found. Install nmap (https://nmap.org) or use "
                "the built-in TCP connect scanner fallback."
            )

        address, address_type = validate_target_address(target)
        port_range = validate_port_range(port_range)
        timeout = timeout_seconds or self._settings.SCAN_TIMEOUT_SECONDS

        args = self._build_args(address, port_range)

        logger.info(
            "Starting nmap scan target=%s range=%s binary=%s",
            address, port_range, self.binary,
        )
        xml_path = self._run(args, timeout)
        try:
            xml_text = self._read_limited(xml_path)
        finally:
            try:
                xml_path.unlink(missing_ok=True)
            except OSError:
                pass
        return parse_nmap_xml(xml_text)

    def _build_args(self, target: str, port_range: str) -> list[str]:
        args = [
            self.binary,
            "-sT",       # TCP connect scan (non-evasive)
            "-sV",       # version detection
            "-Pn",       # treat host as up
            "--open",    # report only open ports
        ]
        if port_range == "top-100":
            args += ["--top-ports", "100"]
        elif port_range == "top-1000":
            args += ["--top-ports", "1000"]
        else:
            args += ["-p", port_range]
        args += ["-oX", "-"]  # XML to stdout, parsed from a temp capture
        # Note: we capture stdout below into a temp file rather than writing
        # the XML to disk via nmap itself, avoiding path handling concerns.
        args += [target]
        return args

    def _run(self, args: list[str], timeout: int) -> Path:
        tmp = tempfile.NamedTemporaryFile(
            mode="w+", suffix=".xml", delete=False, encoding="utf-8"
        )
        tmp_path = Path(tmp.name)
        tmp.close()

        proc: Optional[subprocess.Popen] = None
        out_handle = None
        try:
            out_handle = tmp_path.open("w", encoding="utf-8")
            proc = subprocess.Popen(
                args,
                stdout=out_handle,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
                shell=False,
            )
            _, stderr = proc.communicate(timeout=timeout)
            if proc.returncode != 0:
                detail = (stderr or "nmap exited with a non-zero status").strip()
                if "Failed to resolve" in detail or "Failed to determine" in detail:
                    raise ValidationFailedError(f"nmap could not resolve target: {detail[:200]}")
                raise RuntimeError(f"nmap failed (exit {proc.returncode}): {detail[:300]}")
            return tmp_path
        except subprocess.TimeoutExpired:
            self._terminate(proc)
            raise ScannerUnavailableError(
                f"nmap timed out after {timeout}s and was terminated."
            ) from None
        finally:
            # Close the parent's stdout handle so the temp file is not locked
            # (critical on Windows, where an open handle blocks unlink()).
            if out_handle is not None:
                try:
                    out_handle.close()
                except OSError:
                    pass
            if proc is not None and proc.poll() is None:
                self._terminate(proc)

    @staticmethod
    def _terminate(proc: Optional[subprocess.Popen]) -> None:
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.kill()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            logger.warning("Could not fully terminate nmap process; continuing.")

    @staticmethod
    def _read_limited(path: Path) -> str:
        size = path.stat().st_size
        if size > MAX_XML_BYTES:
            raise ScannerUnavailableError(
                f"nmap output exceeded the {MAX_XML_BYTES} byte safety limit."
            )
        return path.read_text(encoding="utf-8", errors="replace")
