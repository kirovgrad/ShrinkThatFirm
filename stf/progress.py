from __future__ import annotations

import logging
import sys
import threading

LOGGER_NAME = "shrink_that_firm"


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def setup_logging(verbose: bool = False) -> None:
    logger = get_logger()
    if logger.handlers:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)-7s %(message)s", "%H:%M:%S")
    )
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False


class ProgressBar:
    WIDTH = 50
    _lock = threading.Lock()

    def __init__(self, total: int, enabled: bool = True) -> None:
        self.total = max(total, 1)
        self.current = 0
        self.enabled = enabled and sys.stdout.isatty()

    def update(self, step: int = 1) -> None:
        self.current = min(self.current + step, self.total)
        if not self.enabled:
            return
        percent = 100.0 * self.current / self.total
        filled = int(self.WIDTH * self.current // self.total)
        bar = "\u2588" * filled + "-" * (self.WIDTH - filled)
        with self._lock:
            sys.stdout.write(f"\r|{bar}| {percent:5.1f}%")
            sys.stdout.flush()
        if self.current >= self.total:
            self.close()

    def close(self) -> None:
        if self.enabled:
            with self._lock:
                sys.stdout.write("\n")
                sys.stdout.flush()
        self.enabled = False

    def __enter__(self) -> "ProgressBar":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
