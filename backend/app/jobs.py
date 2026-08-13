"""Controlled background scan job execution.

A single worker thread drains a queue of scan jobs. A semaphore limits how
many scans run concurrently. Scan status is tracked in the database so long
scans never block FastAPI request handlers.
"""

import logging
import queue
import threading

from app.config import Settings, get_settings
from app.scanners.runner import execute_scan

logger = logging.getLogger(__name__)

_STOP = object()


class ScanJobManager:
    """Queue + worker pool for scan jobs."""

    def __init__(self, settings: Settings | None = None, max_concurrent: int | None = None):
        self._settings = settings or get_settings()
        self._queue: "queue.Queue[int | object]" = queue.Queue()
        self._semaphore = threading.Semaphore(
            max_concurrent or self._settings.SCAN_MAX_CONCURRENT
        )
        self._thread: threading.Thread | None = None
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._thread = threading.Thread(target=self._run, name="scan-worker", daemon=True)
        self._thread.start()
        logger.info("Scan job manager started (max_concurrent=%s)", self._settings.SCAN_MAX_CONCURRENT)

    def submit(self, scan_id: int) -> None:
        self._queue.put(scan_id)

    def shutdown(self, timeout: float = 5.0) -> None:
        if not self._started:
            return
        self._queue.put(_STOP)
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._started = False

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                self._queue.task_done()
                break
            scan_id = int(item)
            try:
                with self._semaphore:
                    logger.info("Executing scan job for scan id=%s", scan_id)
                    execute_scan(scan_id, settings=self._settings)
            except Exception:  # noqa: BLE001
                logger.exception("Scan job crashed for scan id=%s", scan_id)
            finally:
                self._queue.task_done()


# Singleton used by the API layer.
job_manager = ScanJobManager()
